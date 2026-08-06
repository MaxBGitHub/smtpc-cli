#include "../include/smtp_connection.h"
#include "../include/smtp_reply_parser.h"
#include "../include/smtp_reply_reader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
smtp_conn_assert_fail(
  const char* expr,
  const char* file,
        int   line)
{
  fprintf(stderr,
          "smtp_connection: internal assertion failed: %s (%s:%d)\n",
          expr, file, line);
  abort();
}


#define SMTP_CONN_ASSERT(cond) \
  do { \
    if (!(cond)) { \
      smtp_conn_assert_fail(#cond, __FILE__, __LINE__); \
    } \
  } while (0)

/* RFC 5321 Sec 4.5.3.2 minimum. EHLO has no seperately enumerated entry.
** Defaulted to the same 5-minute value as the greeting/MAIL phase, since 
** it sits in the same pre-transaction part of the conversation. */
#define SMTP_CONN_GREETING_TIMEOUT_MS (5ull * 60ull * 1000ull)
#define SMTP_CONN_EHLO_TIMEOUT_MS     (5ull * 60ull * 1000ull)


static size_t
smtp_conn_build_ehlo_command(
        char*   dst, 
        size_t  dst_size,
  const char*   identity)
{
  SMTP_CONN_ASSERT(dst != NULL);
  SMTP_CONN_ASSERT(identity != NULL);

  int n = snprintf(dst, dst_size, "EHLO %s\r\n", identity);
  if (n < 0 || (size_t)n >= dst_size) {
    return 0; /* Identity too long to fit, or encoding err */
  }
  return (size_t)n;
}

static void
smtp_conn_copy_reply_text(
  const char*   buf,
        size_t  offset,
        size_t  len,
        char*   dst,
        size_t  dst_size)
{
  SMTP_CONN_ASSERT(dst != NULL);
  SMTP_CONN_ASSERT(dst_size > 0);

  size_t n = len < dst_size - 1 ? len : dst_size - 1;
  memcpy(dst, buf + offset, n);
  dst[n] = '\0';
}


static smtp_conn_state
smtp_conn_handle_connect_completion(
        smtp_connection*  conn, 
        smtp_reactor*     r,
  const smtp_io_result*   result,
        uint64_t          now_ms)
{
  if (result->result != 0) {
    smtp_log_emit(SMTP_LOG_ERROR, &conn->log_id, conn->actor, "connect failed");
    conn->state = SMTP_CONN_STATE_ERROR;
    return conn->state;
  }

  smtp_log_emit(SMTP_LOG_CONNECTED, &conn->log_id, conn->actor, "connected");

  conn->state       = SMTP_CONN_STATE_WAIT_BANNER;
  conn->deadline_ms = now_ms + SMTP_CONN_GREETING_TIMEOUT_MS;
  conn->read_len    = 0;

  int rc = smtp_reactor_submit_read(r, 
                                    &conn->op, 
                                    conn->sock, 
                                    conn->read_buf, 
                                    sizeof(conn->read_buf), 
                                    conn);
  if (rc != 0) {
    conn->state = SMTP_CONN_STATE_ERROR;
  }
  return conn->state;
}


static smtp_conn_state
smtp_conn_handle_banner_read(
        smtp_connection*  conn, 
        smtp_reactor*     r, 
  const smtp_io_result*   result,
  const char*             ehlo_identity,
        uint64_t          now_ms)
{
  if (result->result != 0) {
    smtp_log_emit(SMTP_LOG_ERROR, 
                  &conn->log_id, 
                  conn->actor, 
                  "banner read failed");
    conn->state = SMTP_CONN_STATE_ERROR;
    return conn->state;
  }

  if (result->bytes_transferred == 0) {
    smtp_log_emit(SMTP_LOG_ERROR, 
                  &conn->log_id, 
                  conn->actor, 
                  "peer closed before sending a greeting");
    conn->state = SMTP_CONN_STATE_ERROR;
    return conn->state;
  }

  conn->read_len += result->bytes_transferred;

  smtp_reply reply;
  int rc = smtp_reply_read( conn->read_buf, 
                            conn->read_len, 
                            SMTP_CONN_MAX_REPLY_LINES, 
                            &reply);

  if (rc == SMTP_REPLY_READ_INCOMPLETE) {
    if (conn->read_len >= sizeof(conn->read_buf)) {
      smtp_log_emit(SMTP_LOG_ERROR, 
                    &conn->log_id, 
                    conn->actor, 
                    "greeting exceeded the read buffer without completing");
      conn->state = SMTP_CONN_STATE_ERROR;
      return conn->state;
    }

    if (smtp_reactor_submit_read(r, 
                                &conn->op, 
                                conn->sock, 
                                conn->read_buf + conn->read_len, 
                                sizeof(conn->read_buf) - conn->read_len, 
                                conn) != 0) 
    {
      conn->state = SMTP_CONN_STATE_ERROR;  
    }
    return conn->state;
  }

  if (rc != SMTP_REPLY_READ_OK) {
    smtp_log_emit(SMTP_LOG_ERROR, 
                  &conn->log_id, 
                  conn->actor, 
                  "malformed greeting");
    conn->state = SMTP_CONN_STATE_ERROR;
    return conn->state;
  }

  conn->greeting_code = reply.code;

  char text[256];  
  smtp_conn_copy_reply_text(conn->read_buf, 
                                  0, 
                                  reply.consumed > 2 ? reply.consumed - 2 : 0,
                                  text, 
                                  sizeof(text));
  smtp_log_emit(SMTP_LOG_REPLY, &conn->log_id, conn->actor, text);

  if (reply.code < 200 || reply.code >= 300) {
    /* RFC 5321 Sec 3.1: a non-2xx greeting means the 
    ** client should not proceed. */
    smtp_log_emit(SMTP_LOG_ERROR, 
                  &conn->log_id, 
                  conn->actor, 
                  "greeting was not a 2xx reply");
    conn->state = SMTP_CONN_STATE_ERROR;
    return conn->state;
  }

  conn->write_len = smtp_conn_build_ehlo_command( conn->write_buf, 
                                                  sizeof(conn->write_buf), 
                                                  ehlo_identity);

  if (conn->write_len == 0) {
    smtp_log_emit(SMTP_LOG_ERROR, 
                  &conn->log_id, 
                  conn->actor, 
                  "EHLO identity too long to fit the command buffer");
    conn->state = SMTP_CONN_STATE_ERROR;
    return conn->state;
  }

  smtp_log_emit(SMTP_LOG_EHLO, &conn->log_id, conn->actor, ehlo_identity);

  conn->state       = SMTP_CONN_STATE_SENDING_EHLO;
  conn->deadline_ms = now_ms + SMTP_CONN_EHLO_TIMEOUT_MS;

  if (smtp_reactor_submit_write(r, 
                                &conn->op, 
                                conn->sock, 
                                conn->write_buf, 
                                conn->write_len, 
                                conn) != 0) 
  {
    conn->state = SMTP_CONN_STATE_ERROR;
  }
  return conn->state;
}


static smtp_conn_state
smtp_conn_handle_ehlo_write_completion(
        smtp_connection*  conn, 
        smtp_reactor*     r,
  const smtp_io_result*   result)
{
  if (result->result != 0) {
    smtp_log_emit(SMTP_LOG_ERROR, 
                  &conn->log_id, 
                  conn->actor, 
                  "sending EHLO failed");
    conn->state = SMTP_CONN_STATE_ERROR;
    return conn->state;
  }

  if (result->bytes_transferred != conn->write_len) {
    /* Partial write - deferred for this pass.
    ** The EHLO line is short enough that this should be rare, but it's a 
    ** possible network/OS condition, not a programming bug. Treated as a
    ** connection level error, never a process level assert. Since one
    ** connection's partial write must never take an entire worker threads
    ** other healthy connection down with it. */
    smtp_log_emit(SMTP_LOG_ERROR, 
                  &conn->log_id, 
                  conn->actor, 
                  "EHLO write was partial (not yet handled)");
    conn->state = SMTP_CONN_STATE_ERROR;
    return conn->state;
  }

  conn->state     = SMTP_CONN_STATE_WAIT_EHLO;
  conn->read_len  = 0;

  if (smtp_reactor_submit_read( r, 
                                &conn->op, 
                                conn->sock, 
                                conn->read_buf, 
                                sizeof(conn->read_buf), 
                                conn) != 0) 
  {
    conn->state = SMTP_CONN_STATE_ERROR;  
  }
  return conn->state;
}


static smtp_conn_state
smtp_conn_handle_ehlo_read(
        smtp_connection*  conn,
        smtp_reactor*     r,
  const smtp_io_result*   result)
{
  if (result->result != 0) {
    smtp_log_emit(SMTP_LOG_ERROR, 
                  &conn->log_id, 
                  conn->actor, 
                  "EHLO response read failed");
    conn->state = SMTP_CONN_STATE_ERROR;
    return conn->state;
  }

  if (result->bytes_transferred == 0) {
    smtp_log_emit(SMTP_LOG_ERROR, 
                  &conn->log_id, 
                  conn->actor, 
                  "peer closed before completing the EHLO response");
    conn->state = SMTP_CONN_STATE_ERROR;
    return conn->state;
  }

  conn->read_len += result->bytes_transferred;

  int rc = smtp_cap_parse_ehlo_response(conn->caps, 
                                        conn->read_buf, 
                                        conn->read_len, 
                                        SMTP_CONN_MAX_REPLY_LINES);

  if (rc == SMTP_REPLY_READ_INCOMPLETE) {
    if (conn->read_len >= sizeof(conn->read_buf)) {
      smtp_log_emit(SMTP_LOG_ERROR, 
                    &conn->log_id, 
                    conn->actor, 
                    "EHLO response exceeded the read buffer without completing");
      conn->state = SMTP_CONN_STATE_ERROR;
      return conn->state;
    }

    if (smtp_reactor_submit_read( r, 
                                  &conn->op, 
                                  conn->sock, 
                                  conn->read_buf + conn->read_len, 
                                  sizeof(conn->read_buf) - conn->read_len, 
                                  conn) != 0) 
    {
      conn->state = SMTP_CONN_STATE_ERROR;  
    }
    return conn->state;
  }

  if (rc != SMTP_REPLY_READ_OK) {
    smtp_log_emit(SMTP_LOG_ERROR, 
                  &conn->log_id, 
                  conn->actor, 
                  "malformed EHLO response");
    conn->state = SMTP_CONN_STATE_ERROR;
    return conn->state;
  }

  char summary[256];
  smtp_cap_format_summary(conn->caps, summary, sizeof(summary));
  smtp_log_emit(SMTP_LOG_CAPABILITIES, &conn->log_id, conn->actor, summary);

  conn->state = SMTP_CONN_STATE_READY;
  return conn->state;
}


void 
smtp_connection_init(
        smtp_connection*    conn, 
        smtp_capabilities*  caps, 
        smtp_log_id         log_id, 
  const char*               actor)
{
  SMTP_CONN_ASSERT(conn != NULL);
  SMTP_CONN_ASSERT(caps != NULL);
  SMTP_CONN_ASSERT(actor != NULL);

  memset(conn, 0, sizeof(*conn));
  conn->caps    = caps;
  conn->log_id  = log_id;

  size_t n = strlen(actor);
  if (n >= sizeof(conn->actor)) {
    n = sizeof(conn->actor) - 1;
  }
  memcpy(conn->actor, actor, n);
  conn->actor[n] = '\0';
}


int 
smtp_connection_start(
        smtp_connection*  conn, 
        smtp_reactor*     r, 
        smtp_socket       sock,
  const struct sockaddr*  addr,
        size_t            addr_len,
        uint64_t          now_ms,
        uint64_t          connect_timeout_ms)
{
  SMTP_CONN_ASSERT(conn != NULL);
  SMTP_CONN_ASSERT(r != NULL);
  SMTP_CONN_ASSERT(addr != NULL);

  conn->sock                = sock;
  conn->state               = SMTP_CONN_STATE_CONNECTING;
  conn->connect_timeout_ms  = connect_timeout_ms;
  conn->deadline_ms         = now_ms + connect_timeout_ms;
  conn->read_len            = 0;
  conn->write_len           = 0;

  smtp_log_emit(SMTP_LOG_CONNECTING, &conn->log_id, conn->actor, "connecting");

  int rc = smtp_reactor_submit_connect( r, 
                                        &conn->op, 
                                        sock, 
                                        addr, 
                                        addr_len, 
                                        conn);
  if (rc != 0) {
    conn->state = SMTP_CONN_STATE_ERROR;
  }
  return rc;
}


smtp_conn_state
smtp_connection_on_io(
        smtp_connection*  conn, 
        smtp_reactor*     r, 
  const smtp_io_result*   result,
  const char*             ehlo_identity,
        uint64_t          now_ms)
{
  SMTP_CONN_ASSERT(conn != NULL);
  SMTP_CONN_ASSERT(r != NULL);
  SMTP_CONN_ASSERT(result != NULL);
  SMTP_CONN_ASSERT(result->user_data == conn); /* Dispatch loop contract, see header */

  switch (conn->state) {
    case SMTP_CONN_STATE_CONNECTING:
      SMTP_CONN_ASSERT(result->kind == SMTP_IO_CONNECT);
      return smtp_conn_handle_connect_completion(conn, r, result, now_ms);
      
    case SMTP_CONN_STATE_WAIT_BANNER:
      SMTP_CONN_ASSERT(result->kind == SMTP_IO_READ);
      SMTP_CONN_ASSERT(ehlo_identity != NULL);
      return smtp_conn_handle_banner_read(conn, r, result, ehlo_identity, now_ms);
    
    case SMTP_CONN_STATE_SENDING_EHLO:
      SMTP_CONN_ASSERT(result->kind == SMTP_IO_WRITE);
      return smtp_conn_handle_ehlo_write_completion(conn, r, result);
      
    case SMTP_CONN_STATE_WAIT_EHLO:
      SMTP_CONN_ASSERT(result->kind == SMTP_IO_READ);
      return smtp_conn_handle_ehlo_read(conn, r, result);
    default:
      /* READY/ERROR/TIMED_OUT receiving further I/O means the dispatch
      ** loop kept routing completions to an already finished connection.
      ** A caller contract bug, not external input. */
      SMTP_CONN_ASSERT(0);
      return conn->state;
  }
}


smtp_conn_state
smtp_connection_check_timeout(
  smtp_connection*  conn, 
  uint64_t          now_ms) 
{
  SMTP_CONN_ASSERT(conn != NULL);

  if (conn->state == SMTP_CONN_STATE_READY
    || conn->state == SMTP_CONN_STATE_ERROR
    || conn->state == SMTP_CONN_STATE_TIMED_OUT)
  {
    return conn->state;  
  }

  if (now_ms >= conn->deadline_ms) {
    smtp_log_emit(SMTP_LOG_TIMEOUT, 
                  &conn->log_id, 
                  conn->actor, 
                  "step deadline exceeded");
    conn->state = SMTP_CONN_STATE_TIMED_OUT;
  }
  return conn->state;
}
