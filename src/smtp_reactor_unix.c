#include "../include/smtp_reactor.h"

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

/*
** kqueue backend (macOS/FreeBSD/OpenBSD)
**
** epoll vs kqueue: kqueue treats EVFILT_READ and EVFILT_WRITE as two
** seperate registrations per fd, not one combined event mask the way
** epoll's single events field is. Never has both directions armed on 
** the saame fd at once in our usage pattern. Strictly one op in flight
** per fd. submit_rw() below does a best-effort delete of whichever
** filter might currently be active (the wrong one fails with ENOENT
** and is ignored) as three seperate single-entry kevent() calls, rather
** than one multi-entry changelist batch with per-entry error reporting.
** The three-call version relies on nothing but the most basic, certain
** kevent() semantics, which matters more than the syscall-count cost.
**
** Like epoll, kqueue's default behavior (no EV_CLEAR flag) is level 
** equivalent: a ready filter keeps signaling on every kevent() wait call
** until the condition changes or the filter is removed. Same safety
** property as epoll: processing only a subset of what one kevent() call
** returns and leaving the rest untouched is always safe. It'll just be 
** reported again next call.
*/

static void 
smtp_reactor_assert_fail(
  const char* expr, 
  const char* file, 
        int   line)
{
  fprintf(stderr,
          "smtp_reactor_kqueue: internal assertion failed: %s (%s:%d)\n",
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
    [SMTP_REACTOR_ERR_BACKEND_CREATE_FAILED] = "kqueue() failed",
    [SMTP_REACTOR_ERR_AT_CAPACITY]           = "reactor is at max_connections capacity",
    [SMTP_REACTOR_ERR_REGISTER_FAILED]       = "kevent() registration failed",
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
  int     kq;
  size_t  max_connections;
  size_t  live_count;
  struct  kevent* raw_events; /* Scratch buffer for kevent() waits, sized once at create */
};


static int
smtp_reactor_make_nonblocking(
  smtp_socket sock)
{
  int flags = fcntl(sock, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }

  if (flags & O_NONBLOCK) {
    return 0;
  }
  return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}


smtp_reactor* 
smtp_reactor_create(
  size_t max_connections)
{
  if (max_connections == 0) {
    smtp_reactor_fail(SMTP_REACTOR_ERR_INVALID_ARG);
    return NULL;
  }

  smtp_reactor* r = malloc(sizeof(*r));
  if (r == NULL) {
    smtp_reactor_fail(SMTP_REACTOR_ERR_ALLOC_FAILED);
    return NULL;
  }

  r->kq = kqueue();
  if (r->kq < 0) {
    free(r);
    smtp_reactor_fail(SMTP_REACTOR_ERR_BACKEND_CREATE_FAILED);
    return NULL;
  }

  r->raw_events = malloc(sizeof(struct kevent) * max_connections);
  if (r->raw_events == NULL) {
    close(r->kq);
    free(r);
    smtp_reactor_fail(SMTP_REACTOR_ERR_ALLOC_FAILED);
    return NULL;
  }

  r->max_connections  = max_connections;
  r->live_count       = 0;

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
  close(r->kq);
  free(r->raw_events);
  free(r);
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

  if (smtp_reactor_make_nonblocking(sock) != 0) {
    return (int)smtp_reactor_fail(SMTP_REACTOR_ERR_INVALID_ARG);
  }

  /* Same reasoning as epoll backend: every outcome is routed through the
  ** same async completion path, one way for callers to learn outcomes,
  ** not two */
  connect(sock, addr, (socklen_t)addr_len);

  op->sock = sock;
  op->buf = NULL;
  op->buf_len = 0;
  op->kind = SMTP_IO_CONNECT;
  op->user_data = user_data;

  struct kevent kev;
  EV_SET(&kev, (uintptr_t)sock, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, op);

  if (kevent(r->kq, &kev, 1, NULL, 0, NULL) != 0) {
    return (int)smtp_reactor_fail(SMTP_REACTOR_ERR_REGISTER_FAILED);
  }

  r->live_count++;
  return (int)smtp_reactor_fail(SMTP_REACTOR_OK);
}


static int
smtp_reactor_submit_rw(
  smtp_reactor* r,
  smtp_io_op*   op,
  smtp_socket   sock,
  void*         buf,
  size_t        buf_len,
  void*         user_data,
  smtp_io_kind  kind, 
  int16_t       filter)
{
  SMTP_REACTOR_ASSERT(r != NULL);
  SMTP_REACTOR_ASSERT(op != NULL);

  op->sock = sock;
  op->buf = buf;
  op->buf_len = buf_len;
  op->kind = kind;
  op->user_data = user_data;

  struct kevent kev;

  /* Best effort removal of whichever filter might currently be active,
  ** the one that wasn't active legitimately fails with ENOENT.
  ** Both results are discarded deliberately */
  EV_SET(&kev, (uintptr_t)sock, EVFILT_READ, EV_DELETE, 0, 0, NULL);
  kevent(r->kq, &kev, 1, NULL, 0, NULL);

  EV_SET(&kev, (uintptr_t)sock, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
  kevent(r->kq, &kev, 1, NULL, 0, NULL);

  /* Arms exactly the filter this operation needs. This calls outcome is the
  ** one that's actually checked */
  EV_SET(&kev, (uintptr_t)sock, filter, EV_ADD | EV_ENABLE, 0, 0, op);
  if (kevent(r->kq, &kev, 1, NULL, 0, NULL) != 0) {
    if (errno == ENOENT) {
      return (int)smtp_reactor_fail(SMTP_REACTOR_ERR_NOT_REGISTERED);
    }
    return (int)smtp_reactor_fail(SMTP_REACTOR_ERR_REGISTER_FAILED);
  }
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
  SMTP_REACTOR_ASSERT(buf != NULL);
  return smtp_reactor_submit_rw(r, 
                                op, 
                                sock, 
                                buf, 
                                buf_len, 
                                user_data, 
                                SMTP_IO_READ, 
                                EVFILT_READ);
}


int smtp_reactor_submit_write(
        smtp_reactor* r,
        smtp_io_op*   op,
        smtp_socket   sock,
  const void*         buf,
        size_t        buf_len,
        void*         user_data)
{
  SMTP_REACTOR_ASSERT(buf != NULL);
  return smtp_reactor_submit_rw(r,
                                op,
                                sock,
                                (void *)buf,
                                buf_len,
                                user_data,
                                SMTP_IO_WRITE,
                                EVFILT_WRITE);
}


/*
** CONNECT and WRITE both arm EVFILT_WRITE. READ arms EVFILT_READ.
** Disarm removes whichever one this completion actually used.
*/
static void 
smtp_reactor_disarm(
  smtp_reactor* r,
  smtp_socket   sock,
  smtp_io_kind  kind)
{
  int16_t filter = (kind == SMTP_IO_READ) 
                  ? EVFILT_READ 
                  : EVFILT_WRITE;  

  struct kevent kev;
  EV_SET(&kev, (uintptr_t)sock, filter, EV_DELETE, 0, 0, NULL);
  kevent(r->kq, &kev, 1, NULL, 0, NULL);
  /* Best effor: if the fd was already closed by the caller between 
  ** poll() calls, theres nothing further to do about it. */
}


static void
smtp_reactor_handle_connect_ready(
  smtp_io_op*     op,
  smtp_io_result* out)
{
  int err = 0;
  socklen_t err_len = sizeof(err);
  getsockopt(op->sock, SOL_SOCKET, SO_ERROR, &err, &err_len);

  out->user_data = op->user_data;
  out->kind = SMTP_IO_CONNECT;
  out->result = err;
  out->bytes_transferred = 0;  
}


static int
smtp_reactor_handle_read_ready(
  smtp_io_op*     op,
  smtp_io_result* out)
{
  ssize_t n = recv(op->sock, op->buf, op->buf_len, 0);

  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return 0;
    }
    out->user_data = op->user_data;
    out->kind = SMTP_IO_READ;
    out->result = errno;
    out->bytes_transferred = 0;
    return 1;
  }

  out->user_data = op->user_data;
  out->kind = SMTP_IO_READ;
  out->result = 0;
  out->bytes_transferred = (size_t)n;
  return 1;
}


static int
smtp_reactor_handle_write_ready(
  smtp_io_op*     op,
  smtp_io_result* out)
{
  /* No MSG_NOSIGNLA on BSD/Darwin send() the way Linux has it. 
  ** SO_NOSIGPIPE is the BSD equivalent. This backend doesn't set it
  ** itself since socket creation is the caller's responsibility, not 
  ** the rector's. */
  ssize_t n = send(op->sock, op->buf, op->buf_len, 0);

  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return 0;
    }
    out->user_data = op->user_data;
    out->kind = SMTP_IO_WRITE;
    out->result = errno;
    out->bytes_transferred = 0;
    return 1;
  }

  out->user_data = op->user_data;
  out->kind = SMTP_IO_WRITE;
  out->result = 0;
  out->bytes_transferred = (size_t)n;
  return 1;
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

  struct timespec   ts;
  struct timespec*  ts_ptr = NULL;
  if (timeout_ms >= 0) {
    ts.tv_sec   = timeout_ms / 1000;
    ts.tv_nsec  = (long)(timeout_ms % 1000) * 1000000L;
    ts_ptr      = &ts;
  }

  int raw_count = kevent( r->kq, 
                          NULL, 
                          0, 
                          r->raw_events, 
                          (int)r->max_connections, 
                          ts_ptr);

  if (raw_count <= 0) {
    return 0;
  }

  size_t limit = (size_t)raw_count < max_out
                ? (size_t)raw_count
                : max_out;
  size_t filled = 0;

  for (size_t i = 0; i < limit; i++) {
    smtp_io_op* op = (smtp_io_op *)r->raw_events[i].udata;
    SMTP_REACTOR_ASSERT(op != NULL);

    int produced;
    smtp_io_result result;

    switch (op->kind) {
      case SMTP_IO_CONNECT:
        smtp_reactor_handle_connect_ready(op, &result);
        produced = 1;
        break;
      case SMTP_IO_READ:
        produced = smtp_reactor_handle_read_ready(op, &result);
        break;
      case SMTP_IO_WRITE:
        produced = smtp_reactor_handle_write_ready(op, &result);
        break;
      default:
        SMTP_REACTOR_ASSERT(0); /* unreachable */
        produced = 0;
        break;
    }

    if (produced) {
      smtp_reactor_disarm(r, op->sock, op->kind);
      out[filled++] = result;
    }
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

  /* Removal of both filters. Same delete both pattern as submit_rw,
  ** since we don't track which one (if either) is still armed.
  ** Whichever wasn't armed ligitimately fails with ENOENT. */
  struct kevent kev;
  EV_SET(&kev, (uintptr_t)sock, EVFILT_READ, EV_DELETE, 0, 0, NULL);
  kevent(r->kq, &kev, 1, NULL, 0, NULL);

  EV_SET(&kev, (uintptr_t)sock, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
  kevent(r->kq, &kev, 1, NULL, 0, NULL);

  r->live_count--;
  
}

#endif /* __APPLE__ / __FreeBSD__ / __OpenBSD__ */
