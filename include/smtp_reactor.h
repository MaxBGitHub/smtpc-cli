#ifndef SMTP_REACTOR_H
#define SMTP_REACTOR_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
  /* GetQueuedCompletionStatusEx() (used in smtp_reactor_windows.c) is gated
  ** behind _WIN32_WINNT >= 0x0600 inside Windows SDK. Without this, the 
  ** compiler falls back to an implicit declaration. 
  ** 0x0600 = Windows Vista/Server 2008, the oldest version anything in this
  ** project needs. If a build targets 0x0600 or higher, this leaves it
  ** completely untouched rather than silently forcing it down to 0x0600. */  
  #if !defined(_WIN32_WINNT) || (_WIN32_WINNT < 0x0600)
    #undef _WIN32_WINNT
    #define _WIN32_WINNT 0x0600
  #endif
  #if !defined(WINVER) || (WINVER < 0x0600)
    #undef WINVER
    #define WINVER 0x0600
  #endif
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef SOCKET smtp_socket;
#else
  #include <sys/socket.h>
  typedef int smtp_socket;
#endif


/*
** Platform agnostic non-blocking I/O multiplexer. One instance per worker 
** thread, backed by one of epoll (Linux), kqueue (macOS/BSD), 
** or IOCP (Windows) - chosen at compile time via platform detection in the
** corresponding smtp_reactor_*.c file, never at runtime.
**
** The interface is completion based, matching IOCP, the stricter of the 
** two models. A readiness backend (epoll/kqueue) can easily emulate
** completion semantics.
** Only the backend .c files know which real model they're built on.
**
** No dynamic allocation after smtp_reactor_create():
**  max_connections is fixed for the reactor's lifetime, sized once from
** config. smtp_io_op is a real caller embeddable struct, the reactor never
** allocates or owns operation states.
*/

typedef struct smtp_reactor smtp_reactor;

typedef enum {
  SMTP_IO_CONNECT,
  SMTP_IO_READ,
  SMTP_IO_WRITE
} smtp_io_kind;


/*
** One in-flight I/O operation state, two shapes, chosen at compile time:
**  - epoll (Linux) and kqueue (macOS/BSD) are both readiness based: 
**    submit_*() just records what we intend to do. 
**    Actual read()/write()/connect() happens inside smtp_reactor_poll() once
**    the kernel reports the fd ready. No OS owned substruct is needed so 
**    both backened share this struct shape.
**  - IOCP (Windows) is completion based: the real read/write/connect call 
**    happens at submit time and the OS itself writes into OVERLAPPED as the
**    operation progresses. Completions are correlated by that structs address,
**    so it must be embedded directly.
**
** Caller allocated, typically one embedded per connection slot (or a small
** fixed set per connection for concurrent read+write in flight). The reactor
** never allocates these. This project targets general 
** purpose Linux/macOS/BSD/Windows, not embedded.
*/

#if defined(_WIN32)
  typedef struct {
    OVERLAPPED    ovl; /* OS owned - IOCP correlates completion by this address */
    SOCKET        sock;
    WSABUF        buf;
    smtp_io_kind  kind;
    void*         user_data;
  }smtp_io_op;
#else
  typedef struct {
    smtp_socket   sock;
    void*         buf; /* Write target for READ, source for WRITE */
    size_t        buf_len;
    smtp_io_kind  kind;
    void*         user_data;
  } smtp_io_op;
#endif

typedef struct {
  void*         user_data;          /* Caller context (e.g. connection struct)    */
  smtp_io_kind  kind;
  int           result;             /* 0 = success, non-zero = platform err code  */
  size_t        bytes_transferred;  /* Meaningful for READ/WRITE, 0 for CONNECT   */
} smtp_io_result;


typedef enum {
  SMTP_REACTOR_OK = 0,
  SMTP_REACTOR_ERR_INVALID_ARG,
  SMTP_REACTOR_ERR_ALLOC_FAILED,
  SMTP_REACTOR_ERR_BACKEND_CREATE_FAILED,
  SMTP_REACTOR_ERR_AT_CAPACITY,
  SMTP_REACTOR_ERR_REGISTER_FAILED,
  SMTP_REACTOR_ERR_NOT_REGISTERED,
  SMTP_REACTOR_ERR_COUNT
} smtp_reactor_err;


/*
** Creates a reactor sized for exactly max_connection concurrent operations.
** This is the reactors own one time allocation (per-thread, 
** not per-connection).
** Returns NULL on failure, see smtp_reactor_get_last_error() for details.
*/
smtp_reactor* smtp_reactor_create(size_t max_connections);
void          smtp_reactor_destroy(smtp_reactor* r);
const char*   smtp_reactor_get_last_error(void);


/*
** Submits non blocking connect on sock (created but not connected). op must 
** be caller-owned and remain valid and untouched until its completion is
** reported via smtp_reactor_poll(). The reactor writes into it between
** submit and completion. user_data is copied into the eventual 
** smtp_io_result unchanged.
**
** Returns 0 if the operation was accepted for submission (NOT that it 
** completed, completion arrives later via poll()). Non-Zero on a
** submission time failure (e.g. reactor at capacity).
*/
int 
smtp_reactor_submit_connect(
        smtp_reactor*     reactor,
        smtp_io_op*       op,
        smtp_socket       sock,
  const struct sockaddr*  addr,
        size_t            addr_len,
        void*             user_data
);

int 
smtp_reactor_submit_read(
  smtp_reactor* reactor,
  smtp_io_op*   op,
  smtp_socket   sock,
  void*         buf,
  size_t        buf_len,
  void*         user_data
);

int 
smtp_reactor_submit_write(
        smtp_reactor* reactor,
        smtp_io_op*   op,
        smtp_socket   sock,
  const void*         buf, 
        size_t        buf_len,
        void*         user_data
);


/*
** Blocks up to timeout_ms (0 = don't block, negative = block indefinitely) 
** for at least one submitted operation to complete. Fills result_out[] with up 
** to max_out completed operations and returns the number actually filled.
** 0 on timeout, which expected, not an error.
*/
size_t 
smtp_reactor_poll(
  smtp_reactor*   reactor,
  smtp_io_result* result_out,
  size_t          max_out,
  int             timeout_ms
);


/*
** Releases the reactor's tracking of sock. Call this once a connection
** is done and its capacity slot should be reclaimed for a future
** submit_connect. Does NOT close the sock itself, that remains the callers
** responsibility. Decrements the live connection count and on
** epoll/kqueue removes the kernel side registration.
**
** IOCP has no equivalent "disassociate from completion port" operation. 
** Once a handle is associated via CreateIoCompletionPort that association
** is tied to the handle is released automatically when the caller 
** closes it. On Windows this function only decrements the live count.
** There is nothing else to release at the OS level.
**
** Safe to call even if sock was already closed. Does not fail 
** loudly for that case since by the time a caller wants to forget a 
** connection the exact registration state no longer matters to them.
*/
void 
smtp_reactor_forget(
  smtp_reactor* r, 
  smtp_socket   sock
);

#endif /* SMTP_REACTOR_H */
