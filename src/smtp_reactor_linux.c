#include "../include/smtp_reactor.h"

#if defined(__linux__)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/epoll.h>

/*
** epoll backend for Linux. Level-triggered (default mode, no EPOLLET).
** Lets smtp_reactor_poll() safely process only a subset of waht epoll_wait()
** returned (bounded by callers max_out) and defer the rest to the next call
** with zero risk of losing a completion. 
**
** epoll only tells us if a fd is ready it never performs I/O itself.
** The actial recv()/send()/connect() outcome check happens inside
** smtp_reactor_poll(), the instant readiness is reported.
** This is what "readiness-based" means in the headers design comment.
*/

static void
smtp_reactor_assert_fail(
  const char* expr,
  const char* file, 
        int   line)
{
  fprintf(stderr,
          "smtp_reactor_poll: internal assertion failed: %s (%s:%d)\n",
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
    [SMTP_REACTOR_ERR_BACKEND_CREATE_FAILED] = "epoll_create1 failed",
    [SMTP_REACTOR_ERR_AT_CAPACITY]           = "reactor is at max_connections capacity",
    [SMTP_REACTOR_ERR_REGISTER_FAILED]       = "epoll_ctl failed",
    [SMTP_REACTOR_ERR_NOT_REGISTERED]        = "fd was not previously registered via submit_connect"
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
  int                 epoll_fd;
  size_t              max_connections;
  size_t              live_count; /* fds currently registered */
  struct epoll_event* raw_events; /* scratch buffer for epoll_wait, sized once at create */
};


/*
** Ensures sock is non-blocking regardless of what the caller already did.
** The reactor's whole contract depends on this, so it doesn't trust 
** the caller to have remembered it.
*/
static int
smtp_reactor_make_nonblocking(smtp_socket sock)
{
  int flags = fcntl(sock, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }

  if (flags & O_NONBLOCK) {
    return 0; /* Already non blocking */
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

  r->epoll_fd = epoll_create1(0);
  if (r->epoll_fd < 0) {
    free(r);
    smtp_reactor_fail(SMTP_REACTOR_ERR_BACKEND_CREATE_FAILED);
    return NULL;
  }

  r->raw_events = malloc(sizeof(struct epoll_event) * max_connections);
  if (r->raw_events == NULL) {
    close(r->epoll_fd);
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
  close(r->epoll_fd);
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

  /* Initiate the connect. A non-blocking connect() normally returns
  ** -1/EINGPROGRESS immediately but it can also return 0 (rare, e.g. 
  ** connecting to loopback can resolve synchronously) or fail
  ** synchronously with a real errno. All three outcomes are still routed
  ** through the same completion path below (registered with epoll either way)
  ** rather than some reported via this functions return value and others via
  ** poll(). One way for callers to learn outcomes, not two.
  ** This functions own return value reports only submission time problems
  ** like: bad args, capacity, epoll_ctl itself failing. */
  connect(sock, addr, (socklen_t)addr_len);

  op->sock      = sock;
  op->buf       = NULL;
  op->buf_len   = 0;
  op->kind      = SMTP_IO_CONNECT;
  op->user_data = user_data;

  struct epoll_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.events = EPOLLOUT; /* writable -> connect attempt resolved, check SO_ERROR */
  ev.data.ptr = op;

  if (epoll_ctl(r->epoll_fd, EPOLL_CTL_ADD, sock, &ev) != 0) {
    return (int)smtp_reactor_fail(SMTP_REACTOR_ERR_REGISTER_FAILED);
  }

  r->live_count++;
  return (int)smtp_reactor_fail(SMTP_REACTOR_OK);
}


/*
** Shared by submit_read and submit_write: both modify an existing
** registration (the fd must already be added via submit_connect) - 
** never add here. A mod on an unregistered fd failing with ENOENT is
** a genuine caller contract violation (submit_read/write called before
** submit_connect on this fd), reported explicitly rather than silently
** falling back to add and papering over the bug.
*/
static int
smtp_reactor_submit_rw(
  smtp_reactor* r, 
  smtp_io_op*   op, 
  smtp_socket   sock,
  void*         buf, 
  size_t        buf_len, 
  void*         user_data,
  smtp_io_kind  kind,
  uint32_t      epoll_events)
{
  SMTP_REACTOR_ASSERT(r != NULL);
  SMTP_REACTOR_ASSERT(op != NULL);

  op->sock      = sock;
  op->buf       = buf;
  op->buf_len   = buf_len;
  op->kind      = kind;
  op->user_data = user_data;

  struct epoll_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.events = epoll_events;
  ev.data.ptr = op;

  if (epoll_ctl(r->epoll_fd, EPOLL_CTL_MOD, sock, &ev) != 0) {
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
                                EPOLLIN); 
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
  SMTP_REACTOR_ASSERT(buf != NULL);
  /* safe: a write op never writes through op->buf, only reads from it */
  return smtp_reactor_submit_rw(r, 
                                op, 
                                sock, 
                                (void *)buf, 
                                buf_len, 
                                user_data, 
                                SMTP_IO_WRITE, 
                                EPOLLOUT);
}


static void
smtp_reactor_disarm(
  smtp_reactor* r, 
  smtp_socket   sock) 
{
  struct epoll_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.events = 0;
  /* Best-effor: if this fails (fd already closed by caller between
  ** poll() calls), there's nothing further to do about it */
  epoll_ctl(r->epoll_fd, EPOLL_CTL_MOD, sock, &ev);  
}


static void
smtp_reactor_handle_connect_ready(
  smtp_io_op*     op,
  smtp_io_result* out)
{
  int err = 0;
  socklen_t err_len = sizeof(err);
  getsockopt(op->sock, SOL_SOCKET, SO_ERROR, &err, &err_len);

  out->user_data          = op->user_data;
  out->kind               = SMTP_IO_CONNECT;
  out->result             = err;
  out->bytes_transferred  = 0;
}


/*
** Returns 1 if a completion was produced, 0 if the event should be silently
** skipped this round (EAGAIN right after readiness is a rare race cond, not 
** a real error. The fd will be re-reported next call under level triggered
** epoll, so nothing is lost).
*/
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
    out->user_data          = op->user_data;
    out->kind               = SMTP_IO_READ;
    out->result             = errno;
    out->bytes_transferred  = 0;
    return 1;
  }

  /* n == 0 is EOF (peer closed) - reported as a successful zero-byte read,
  ** not an error. Interpreting that as "connection closed" is the caller's
  ** job, not this layer's. */
  out->user_data          = op->user_data;
  out->kind               = SMTP_IO_READ;
  out->result             = 0;
  out->bytes_transferred  = (size_t)n;
  return 1;
}


static int
smtp_reactor_handle_write_ready(
  smtp_io_op*     op, 
  smtp_io_result* out)
{
  /* MSG_NOSIGNAL: writing to a peer-closed socket without it raises SIGPIPE,
  ** which by default terminates the process. */
  ssize_t n = send(op->sock, op->buf, op->buf_len, MSG_NOSIGNAL);

  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return 0;
    }
    out->user_data          = op->user_data;
    out->kind               = SMTP_IO_WRITE;
    out->result             = errno;
    out->bytes_transferred  = 0;
    return 1;
  }

  out->user_data          = op->user_data;
  out->kind               = SMTP_IO_WRITE;
  out->result             = 0;
  out->bytes_transferred  = (size_t)n;
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

  int raw_count = epoll_wait( r->epoll_fd, 
                              r->raw_events, 
                              (int)r->max_connections, 
                              timeout_ms);

  if (raw_count <= 0) {
    return 0; /* Timeout or a benign interrupt, not an error the caller needs */
  }

  /* Bounded by min(raw_count, max_out), both finite and known here.
  ** Any raw event beyond this bound is deliberately left untouched, 
  ** not disarmed nor consumed. Level-triggering reports it again next call. 
  ** Nothing lost by processing only a partial batch. */
  size_t limit = (size_t)raw_count < max_out 
                ? (size_t)raw_count 
                : max_out;
  size_t filled = 0;

  for (size_t i = 0; i < limit; i++) {
    smtp_io_op* op = (smtp_io_op *)r->raw_events[i].data.ptr;
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
        /* Unreachable: every op is set via submit_connect/read/write */
        SMTP_REACTOR_ASSERT(0);
        produced = 0;
        break;
    }

    if (produced) {
      smtp_reactor_disarm(r, op->sock);
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

  /* If sock was already closed by the caller, this legitimately fails
  ** and there is nothing further to do about it. */
  epoll_ctl(r->epoll_fd, EPOLL_CTL_DEL, sock, NULL);

  r->live_count--;
}

#endif /* __linux__ */
