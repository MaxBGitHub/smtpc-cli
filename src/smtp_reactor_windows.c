#include "../include/smtp_reactor.h"

#if defined(_WIN32)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <mswsock.h>

/*
** IOCP backend (Windows).
**
** Structural difference from epoll/kqueue:
** epoll/kqueue are READINESS based, submit_*() just registers interest,
** and the actual read/write/connect happens inside poll() once the os
** says "ready". IOCP is COMPLETION based, the real WSARecv/WSASend/ConnectEx
** call happens at SUBMIT time, with the OS performing the operation 
** asynchronously and posting a completion packet when done.
** This means:
**  - A socket is associated with the completion port ONCE, at submit_connect
**    time (via CreateIoCompletionPort), not re-registered per operation
**    the way epoll_ctl/kevent are.
**  - GetQueuedCompletionStatusEx() PERMANENTLY dequeues whatever it retrieves,
**    unlike epoll_wait/kevents level-triggered "leave it unconsumed, it'll
**    be reported again" safety net, there is no "put it back" here. So
**    smtp_reactor_poll() must request at most min(max_connections, max_out)
**    entries in the first place, never fetch more than it can hand back
**    to the caller this call.
*/


static void 
smtp_reactor_assert_fail(
  const char* expr, 
  const char* file, 
        int   line)
{
    fprintf(stderr,
            "smtp_reactor_iocp: internal assertion failed: %s (%s:%d)\n",
            expr, file, line);
    abort();
}

#define SMTP_REACTOR_ASSERT(cond) \
    do { \
        if (!(cond)) { \
            smtp_reactor_assert_fail(#cond, __FILE__, __LINE__); \
        } \
    } while (0)


static const char *const g_smtp_reactor_err_strings[SMTP_REACTOR_ERR_COUNT] = {
    [SMTP_REACTOR_OK]                        = "no error",
    [SMTP_REACTOR_ERR_INVALID_ARG]           = "invalid argument",
    [SMTP_REACTOR_ERR_ALLOC_FAILED]          = "allocation failed",
    [SMTP_REACTOR_ERR_BACKEND_CREATE_FAILED] = "IOCP setup failed",
    [SMTP_REACTOR_ERR_AT_CAPACITY]           = "reactor is at max_connections capacity",
    [SMTP_REACTOR_ERR_REGISTER_FAILED]       = "IOCP registration or I/O submission failed",
    [SMTP_REACTOR_ERR_NOT_REGISTERED]        = "fd was not previously registered via submit_connect",
};

static _Thread_local smtp_reactor_err g_smtp_reactor_last_err = SMTP_REACTOR_OK;

static smtp_reactor_err 
smtp_reactor_fail(
  smtp_reactor_err err)
{
    g_smtp_reactor_last_err = err;
    return err;
}

const char*
smtp_reactor_get_last_error(void)
{
    SMTP_REACTOR_ASSERT(g_smtp_reactor_last_err < SMTP_REACTOR_ERR_COUNT);
    return g_smtp_reactor_err_strings[g_smtp_reactor_last_err];
}


struct smtp_reactor {
  HANDLE            iocp; /* Queried once at create, reused for every connect */
  LPFN_CONNECTEX    connect_ex;
  size_t            max_connections;
  size_t            live_count;
  OVERLAPPED_ENTRY* raw_entries; /* Scratch buffer, sized once at create */
};


static int
smtp_reactor_load_connect_ex(
  LPFN_CONNECTEX* out)
{
  SOCKET probe = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (probe == INVALID_SOCKET) {
    return -1;
  }  

  GUID  guid  = WSAID_CONNECTEX;
  DWORD bytes = 0;
  int rc = WSAIoctl(probe, 
                    SIO_GET_EXTENSION_FUNCTION_POINTER, 
                    &guid, 
                    sizeof(guid), 
                    out, 
                    sizeof(*out), 
                    &bytes, 
                    NULL, 
                    NULL);

  closesocket(probe);
  return (rc == 0) ? 0 : -1;
}


smtp_reactor*
smtp_reactor_create(
  size_t max_connections) 
{
  if (max_connections == 0) {
    smtp_reactor_fail(SMTP_REACTOR_ERR_INVALID_ARG);
    return NULL;
  }

  WSADATA wsa_data;
  if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
    smtp_reactor_fail(SMTP_REACTOR_ERR_BACKEND_CREATE_FAILED);
    return NULL;
  }

  smtp_reactor* r = malloc(sizeof(*r));
  if (r == NULL) {
    WSACleanup();
    smtp_reactor_fail(SMTP_REACTOR_ERR_ALLOC_FAILED);
    return NULL;
  }

  r->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
  if (r->iocp == NULL) {
    free(r);
    WSACleanup();
    smtp_reactor_fail(SMTP_REACTOR_ERR_BACKEND_CREATE_FAILED);
    return NULL;
  }

  if (smtp_reactor_load_connect_ex(&r->connect_ex) != 0) {
    CloseHandle(r->iocp);
    free(r);
    WSACleanup();
    smtp_reactor_fail(SMTP_REACTOR_ERR_BACKEND_CREATE_FAILED);
    return NULL;
  }

  r->raw_entries = malloc(sizeof(OVERLAPPED_ENTRY) * max_connections);
  if (r->raw_entries == NULL) {
    CloseHandle(r->iocp);
    free(r);
    WSACleanup();
    smtp_reactor_fail(SMTP_REACTOR_ERR_ALLOC_FAILED);
    return NULL;
  }

  r->max_connections = max_connections;
  r->live_count = 0;

  smtp_reactor_fail(SMTP_REACTOR_OK);
  return r;
}


void
smtp_reactor_destroy(
  smtp_reactor* r)
{
  if (r == NULL) {
    return;
  }
  CloseHandle(r->iocp);
  free(r->raw_entries);
  free(r);
  WSACleanup();
}


int
smtp_reactor_submit_connect(
        smtp_reactor*     r, 
        smtp_io_op*       op, 
        smtp_socket       sock,
  const struct sockaddr*  addr,
        size_t            addr_len,
        void*             user_data)
{
  SMTP_REACTOR_ASSERT(r != NULL);
  SMTP_REACTOR_ASSERT(op != NULL);
  SMTP_REACTOR_ASSERT(addr != NULL);

  if (r->live_count >= r->max_connections) {
    return (int)smtp_reactor_fail(SMTP_REACTOR_ERR_AT_CAPACITY);
  }

  /* ConnectEx requires the socket to already be bound to a local address.
  ** Unlike ordinary connect(), which binds implicitly.
  ** Skipping this makes ConnectEx fail with WSAEINVAL. 
  ** Well documented but easy to miss windows requirement. */
  struct sockaddr_in local_addr;
  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sin_family       = AF_INET;
  local_addr.sin_addr.s_addr  = INADDR_ANY;
  local_addr.sin_port         = 0;
  if (bind(sock, (struct sockaddr *)&local_addr, sizeof(local_addr)) != 0) {
    return (int)smtp_reactor_fail(SMTP_REACTOR_ERR_INVALID_ARG);
  }

  /* One time per socket lifetime association with completion port.
  ** every subsequent overlapped operation on this socket posts here
  ** automatically, unlike epoll/kqueues per operation re-arming. */
  if (CreateIoCompletionPort((HANDLE)sock, r->iocp, 0, 0) == NULL) {
    return (int)smtp_reactor_fail(SMTP_REACTOR_ERR_REGISTER_FAILED);
  }

  op->sock = sock;
  op->kind = SMTP_IO_CONNECT;
  op->user_data = user_data;
  memset(&op->ovl, 0, sizeof(op->ovl));
  memset(&op->buf, 0, sizeof(op->buf));

  BOOL ok = r->connect_ex(sock, addr, (int)addr_len, NULL, 0, NULL, &op->ovl);
  if (!ok && WSAGetLastError() != ERROR_IO_PENDING) {
    return (int)smtp_reactor_fail(SMTP_REACTOR_ERR_REGISTER_FAILED);
  }

  r->live_count++;
  return (int)smtp_reactor_fail(SMTP_REACTOR_OK);
}


int
smtp_reactor_submit_read(
  smtp_reactor* r,
  smtp_io_op*   op,
  smtp_socket   sock,
  void*         buf,
  size_t        buf_len,
  void*         user_data)
{
  SMTP_REACTOR_ASSERT(r != NULL);
  SMTP_REACTOR_ASSERT(op != NULL);
  SMTP_REACTOR_ASSERT(buf != NULL);

  op->sock = sock;
  op->kind = SMTP_IO_READ;
  op->user_data = user_data;
  memset(&op->ovl, 0, sizeof(op->ovl));
  op->buf.buf = (CHAR *)buf;
  op->buf.len = (ULONG)buf_len;

  DWORD flags = 0;
  int rc = WSARecv(sock, &op->buf, 1, NULL, &flags, &op->ovl, NULL);
  if (rc != 0 && WSAGetLastError() != WSA_IO_PENDING) {
    return (int)smtp_reactor_fail(SMTP_REACTOR_ERR_REGISTER_FAILED);
  }
  return (int)smtp_reactor_fail(SMTP_REACTOR_OK);
}


int 
smtp_reactor_submit_write(
        smtp_reactor* r,
        smtp_io_op*   op,
        smtp_socket   sock,
  const void*         buf,
        size_t        buf_len,
        void*         user_data)
{
  SMTP_REACTOR_ASSERT(r != NULL);
  SMTP_REACTOR_ASSERT(op != NULL);
  SMTP_REACTOR_ASSERT(buf != NULL);

  op->sock = sock;
  op->kind = SMTP_IO_WRITE;
  op->user_data = user_data;
  memset(&op->ovl, 0, sizeof(op->ovl));
  op->buf.buf = (CHAR *)(void *)buf; /* Safe: WRITE never writes through this. */
  op->buf.len = (ULONG)buf_len;

  int rc = WSASend(sock, &op->buf, 1, NULL, 0, &op->ovl, NULL);
  if (rc != 0 && WSAGetLastError() != WSA_IO_PENDING) {
    return (int)smtp_reactor_fail(SMTP_REACTOR_ERR_REGISTER_FAILED);
  }
  return (int)smtp_reactor_fail(SMTP_REACTOR_OK);
}


/*
** Recovers the enclosing smtp_io_op* from the OVERLAPPED* the OS hands back,
** via offsetof. Hand rolled for clarity instead of 
** depending on macro availability.
*/
static smtp_io_op* 
smtp_reactor_op_from_overlapped(
  OVERLAPPED* ovl)
{
  return (smtp_io_op *)((char *)ovl - offsetof(smtp_io_op, ovl));
}


static void
smtp_reactor_handle_completion(
  const OVERLAPPED_ENTRY* entry,
        smtp_io_result*   out)
{
  smtp_io_op* op = smtp_reactor_op_from_overlapped(entry->lpOverlapped);

  DWORD bytes = 0;
  DWORD flags = 0;
  BOOL ok = WSAGetOverlappedResult(op->sock, &op->ovl, &bytes, FALSE, &flags);

  if (ok && op->kind == SMTP_IO_CONNECT) {
    /* Required after a successful ConnectEx before the socket is fully
    ** usable with ordinary socket functions. */
    setsockopt(op->sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
  }
  out->user_data = op->user_data;
  out->kind = op->kind;
  out->result = ok ? 0 : (int)WSAGetLastError();
  out->bytes_transferred = ok ? (size_t)bytes : 0;
}


size_t
smtp_reactor_poll(
  smtp_reactor*   r,
  smtp_io_result* out,
  size_t          max_out,
  int             timeout_ms)
{
  SMTP_REACTOR_ASSERT(r != NULL);
  SMTP_REACTOR_ASSERT(out != NULL || max_out == 0);

  if (max_out == 0) {
    return 0;
  }

  /* Bounded to what we can actually hand back this call. 
  ** see the file-header comment: GetQueuedCompletionStatusEx permanently
  ** dequeues whatever it retrieves, so over requesting would lose
  ** completions rather than safely deferring them. */
  size_t request  = r->max_connections < max_out 
                  ? r->max_connections 
                  : max_out;

  ULONG removed = 0;
  DWORD timeout = (timeout_ms < 0) 
                ? INFINITE 
                : (DWORD)timeout_ms;

  BOOL ok = GetQueuedCompletionStatusEx(r->iocp, 
                                        r->raw_entries, 
                                        (ULONG)request, 
                                        &removed, 
                                        timeout, 
                                        FALSE);

  if (!ok || removed == 0) {
    return 0; /* timeout - not an error the caller needs. */ 
  }

  size_t filled = 0;
  for (ULONG i = 0; i < removed; i++) {
    smtp_io_result result;
    smtp_reactor_handle_completion(&r->raw_entries[i], &result);
    out[filled++] = result;
  }
  return filled;
}


void
smtp_reactor_forget(
  smtp_reactor* r,
  smtp_socket   sock)
{
  SMTP_REACTOR_ASSERT(r != NULL);
  SMTP_REACTOR_ASSERT(r->live_count > 0); /* Double forget edge case */

  /* Nothing to release at the OS level.
  ** IOCPs association is tied to the handle itself and is released
  ** automatically when the caller closes it. */
  (void)sock;   

  r->live_count--;
}

#endif /* _WIN32 */
