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
** it sits in the same pre-transaction part of the conversation. 
** Same reasoning applies to the TLS handshake. No RFC cited minium 
** exists for it either. */
#define SMTP_CONN_GREETING_TIMEOUT_MS       (5ull * 60ull * 1000ull)
#define SMTP_CONN_EHLO_TIMEOUT_MS           (5ull * 60ull * 1000ull)
#define SMTP_CONN_TLS_HANDSHAKE_TIMEOUT_MS  (5ull * 60ull * 1000ull)


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


static size_t 
smtp_conn_build_starttls_command(
  char*   dst, 
  size_t  dst_size)
{
  SMTP_CONN_ASSERT(dst != NULL);

  int n = snprintf(dst, dst_size, "STARTTLS\r\n");
  SMTP_CONN_ASSERT(n > 0 && (size_t)n < dst_size); /* Fixed short literal,
                                                      never fails in practice.
                                                      An internal invariant
                                                      not external input. */

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


/*
** Submits the next raw read. When TLS is active, this targets cipher_buf, the
** raw ciphertext (always from the start. It never needs to accumulate at a
** growing offset the way plaintext does, since each raw chunk is immediately
** handed to decrypt and then overwritten next time) rather than read_buf
** directly. When TLS is not active, this targets read_buf at the current
** append position.
*/
static int
smtp_conn_submit_read_bytes(
  smtp_connection*  conn,
  smtp_reactor*     r)
{
  if (conn->tls != NULL) {
    return smtp_reactor_submit_read(r, 
                                    &conn->op, 
                                    conn->sock, 
                                    conn->cipher_buf, 
                                    sizeof(conn->cipher_buf), 
                                    conn);
  }
  return smtp_reactor_submit_read(r,
                                  &conn->op,
                                  conn->sock,
                                  conn->read_buf + conn->read_len,
                                  sizeof(conn->read_buf) - conn->read_len,
                                  conn);
}


/*
** Submits plaintext_len bytes of plaintext for sending, transparently routing
** through TLS encryption first when active. Records the actual number of 
** bytes handed to the reactor in conn->wire_write_len. Callers must check
** completions against that field, never plaintext_len/write_len directly,
** since the two only coincide when TLS is inactive.
** Returns 0 on success, non-zero on failure.
*/
static int
smtp_conn_submit_write_bytes(
        smtp_connection*  conn,
        smtp_reactor*     r,
  const void*             plaintext,
        size_t            plaintext_len)
{
  if (conn->tls != NULL) {
    size_t cipher_len = 0;
    smtp_tls_status tls_stat = smtp_tls_encrypt(conn->tls, 
                                                plaintext, 
                                                plaintext_len, 
                                                conn->cipher_buf, 
                                                sizeof(conn->cipher_buf), 
                                                &cipher_len);

    if (tls_stat != SMTP_TLS_WANT_WRITE) {
      return -1;
    }
    conn->wire_write_len = cipher_len;
    return smtp_reactor_submit_write( r, 
                                      &conn->op, 
                                      conn->sock, 
                                      conn->cipher_buf, 
                                      cipher_len, 
                                      conn);
  }
  conn->wire_write_len = plaintext_len;
  return smtp_reactor_submit_write( r,
                                    &conn->op,
                                    conn->sock,
                                    plaintext,
                                    plaintext_len,
                                    conn);
}


/*
** Shared by the implicit path (entered right after CONNECTING) and the 
** explicit/oppurtunistic path (entered after STARTTLS is accepted): creates
** the TLS engine and drives the handshake's first step. 
** begin_log_detail distinguishes the two in the TLS_BEGIN log line,
** since otherwise this is identical work either way.
*/
static smtp_conn_state
smtp_conn_begin_tls_handshake(
        smtp_connection*  conn,
        smtp_reactor*     r,
        uint64_t          now_ms,
  const char*             begin_log_detail)
{
  conn->tls = smtp_tls_create(conn->tls_ctx, 
                              conn->actor, 
                              conn->tls_trust_without_validation);
  if (conn->tls == NULL) {
    smtp_log_emit(SMTP_LOG_TLS_FAIL, 
                  &conn->log_id, 
                  conn->actor, 
                  "failed to create the TLS engine");
    conn->state = SMTP_CONN_STATE_ERROR;
    return conn->state;
  }

  smtp_log_emit(SMTP_LOG_TLS_BEGIN, 
                &conn->log_id, 
                conn->actor, 
                begin_log_detail);
                
  conn->state       = SMTP_CONN_STATE_TLS_HANDSHAKING;
  conn->deadline_ms = now_ms + SMTP_CONN_TLS_HANDSHAKE_TIMEOUT_MS;
  conn->read_len    = 0;

  size_t out_len = 0;
  smtp_tls_status tls_stat = smtp_tls_handshake(conn->tls, 
                                                NULL, 
                                                0, 
                                                conn->cipher_buf, 
                                                sizeof(conn->cipher_buf), 
                                                &out_len);

  if (tls_stat == SMTP_TLS_WANT_WRITE) {
    conn->wire_write_len = out_len;
    int rc = smtp_reactor_submit_write( r, 
                                        &conn->op, 
                                        conn->sock, 
                                        conn->cipher_buf, 
                                        out_len, 
                                        conn);
    if (rc != 0) {
      conn->state = SMTP_CONN_STATE_ERROR;
    }
    return conn->state;
  }

  if (tls_stat == SMTP_TLS_WANT_READ) {
    int rc = smtp_reactor_submit_read(r, 
                                      &conn->op, 
                                      conn->sock, 
                                      conn->cipher_buf, 
                                      sizeof(conn->cipher_buf), 
                                      conn);
    if (rc != 0) {
      conn->state = SMTP_CONN_STATE_ERROR;
    }
    return conn->state;
  }

  /* SMTP_TLS_OK on the very first call would be unusual (no real handshake
  ** completes in zero round trips) but handled rather than assumed impossible.
  ** SMTP_TLS_ERROR here is a genuine, immediate setup failure either way. */
  smtp_log_emit(SMTP_LOG_TLS_FAIL, 
                &conn->log_id, 
                conn->actor, 
                "TLS handshake failed to start");
  conn->state = SMTP_CONN_STATE_ERROR;
  return conn->state;
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

  if (conn->tls_mode == SMTP_TLS_MODE_IMPLICIT) {
    return smtp_conn_begin_tls_handshake( conn, 
                                          r, 
                                          now_ms, 
                                          "starting implicit TLS handshake");
  }

  conn->state       = SMTP_CONN_STATE_WAIT_BANNER;
  conn->deadline_ms = now_ms + SMTP_CONN_GREETING_TIMEOUT_MS;
  conn->read_len    = 0;

  if (smtp_conn_submit_read_bytes(conn, r) != 0) {
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

    if (smtp_conn_submit_read_bytes(conn, r) != 0) {
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
  conn->banner_seen   = 1;

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

  rc = smtp_conn_submit_write_bytes(conn, r, conn->write_buf, conn->write_len);
  if (rc != 0) {
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

  if (result->bytes_transferred != conn->wire_write_len) {
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

  if (smtp_conn_submit_read_bytes(conn, r) != 0) {
    conn->state = SMTP_CONN_STATE_ERROR;
  }
  return conn->state;
}


static smtp_conn_state
smtp_conn_handle_ehlo_read(
        smtp_connection*  conn,
        smtp_reactor*     r,
  const smtp_io_result*   result,
        uint64_t          now_ms)
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

    if (smtp_conn_submit_read_bytes(conn, r) != 0) {
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

  if (conn->tls != NULL) {
    /* This is the second EHLO over an already encrypted channel. 
    ** Never re-attempt STARTTLS regardless of what the server advertises now.
    ** A second handshake on an already encrypted connection makes no sense. */
    conn->state = SMTP_CONN_STATE_READY;
    return conn->state;
  }

  switch (conn->tls_mode) {
    case SMTP_TLS_MODE_NONE:
      conn->state = SMTP_CONN_STATE_READY;
      return conn->state;      

    case SMTP_TLS_MODE_OPPORTUNISTIC:
      if (!conn->caps->has_starttls) {
        conn->state = SMTP_CONN_STATE_READY;
        return conn->state;
      }      
      break; /* Offered, fall through and send STARTTLS below.
                once sent a failure from here on is fatal even in this mode. 
                See smtp_conn_handle_starttls_reply and 
                smtp_conn_handle_tls_handshake: opportunistic governs whether
                an attempt is required to be offered. */

    case SMTP_TLS_MODE_EXPLICIT:
      if (!conn->caps->has_starttls) {
        smtp_log_emit(SMTP_LOG_ERROR, 
                      &conn->log_id, 
                      conn->actor, 
                      "STARTTLS required but not offered by the server");
        conn->state = SMTP_CONN_STATE_ERROR;
        return conn->state;
      }
      break;
      
    default:
      /* SMTP_TLS_MODE_IMPLICIT is unreachable here: an implicit connections
      ** tls field is already non-NULL by the time it returned. Reaching
      ** there with any other value is a caller/internal state bug, 
      ** not external input. */
      SMTP_CONN_ASSERT(0);
      return conn->state;
  }

  size_t cmd_len = smtp_conn_build_starttls_command(conn->write_buf, 
                                                    sizeof(conn->write_buf));
  smtp_log_emit(SMTP_LOG_STARTTLS, 
                &conn->log_id, 
                conn->actor, "sending STARTTLS");

  conn->state       = SMTP_CONN_STATE_SENDING_STARTTLS;
  conn->deadline_ms = now_ms + SMTP_CONN_EHLO_TIMEOUT_MS;

  rc = smtp_conn_submit_write_bytes(conn, r, conn->write_buf, cmd_len);
  if (rc != 0) {
    conn->state = SMTP_CONN_STATE_ERROR;
  }
  return conn->state;
}


static smtp_conn_state
smtp_conn_handle_starttls_write_completion(
        smtp_connection*  conn,
        smtp_reactor*     r,
  const smtp_io_result*   result)
{
  if (result->result != 0 
    || result->bytes_transferred != conn->wire_write_len) 
  {
    smtp_log_emit(SMTP_LOG_ERROR, 
                  &conn->log_id, 
                  conn->actor, 
                  "sending STARTTLS failed");
    conn->state = SMTP_CONN_STATE_ERROR;
    return conn->state;
  }

  conn->state     = SMTP_CONN_STATE_WAIT_STARTTLS_REPLY;
  conn->read_len  = 0;

  if (smtp_conn_submit_read_bytes(conn, r) != 0) {
    conn->state = SMTP_CONN_STATE_ERROR;
  }
  return conn->state;
}


static smtp_conn_state
smtp_conn_handle_starttls_reply(
        smtp_connection*  conn,
        smtp_reactor*     r,
  const smtp_io_result*   result,
        uint64_t          now_ms)
{
  if (result->result != 0) {
    smtp_log_emit(SMTP_LOG_ERROR, 
                  &conn->log_id, 
                  conn->actor, 
                  "STARTTLS reply read failed");
    conn->state = SMTP_CONN_STATE_ERROR;
    return conn->state;
  }

  if (result->bytes_transferred == 0) {
    smtp_log_emit(SMTP_LOG_ERROR, 
                  &conn->log_id,
                  conn->actor,
                  "peer closed before replying to STARTTLS");
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
                    "STARTTLS reply exceeded the read buffer without completing");
      conn->state = SMTP_CONN_STATE_ERROR;
      return conn->state;
    }

    if (smtp_conn_submit_read_bytes(conn, r) != 0) {
      conn->state = SMTP_CONN_STATE_ERROR;
    }
    return conn->state;
  }

  if (rc != SMTP_REPLY_READ_OK) {
    smtp_log_emit(SMTP_LOG_ERROR, 
                  &conn->log_id, 
                  conn->actor, 
                  "malformed STARTTLS reply");
    conn->state = SMTP_CONN_STATE_ERROR;
    return conn->state;
  }

  if (reply.code < 200 || reply.code >= 300) {
    smtp_log_emit(SMTP_LOG_TLS_FAIL, 
                  &conn->log_id, 
                  conn->actor,
                  "server declined STARTTLS");
    conn->state = SMTP_CONN_STATE_ERROR;
    return conn->state;
  }
  return smtp_conn_begin_tls_handshake( conn, 
                                        r, 
                                        now_ms, 
                                        "starting TLS handshake after STARTTLS");
}


static smtp_conn_state
smtp_conn_handle_tls_handshake(
        smtp_connection*  conn,
        smtp_reactor*     r,
  const smtp_io_result*   result,
  const char*             ehlo_identity,
        uint64_t          now_ms)
{
  if (result->result != 0) {
    smtp_log_emit(SMTP_LOG_TLS_FAIL, 
                  &conn->log_id, 
                  conn->actor, 
                  "TLS handshake I/O failed");
    conn->state = SMTP_CONN_STATE_ERROR;
    return conn->state;
  }

  const void* in_data = NULL;
  size_t      in_len  = 0;

  if (result->kind == SMTP_IO_READ) {
    if (result->bytes_transferred == 0) {
      smtp_log_emit(SMTP_LOG_TLS_FAIL, 
                    &conn->log_id,
                    conn->actor,
                    "peer closed during the TLS handshake");
      conn->state = SMTP_CONN_STATE_ERROR;
      return conn->state;      
    }
    in_data = conn->cipher_buf;
    in_len  = result->bytes_transferred;
  }

  /* On a WRITE completion there is nothing new to feed the engine.
  ** This just confirms the last batch of handshake bytes went out,
  ** then drives the engine again with no new 
  ** input to see what it wants next. */

  size_t out_len = 0;
  smtp_tls_status tls_stat = smtp_tls_handshake(conn->tls, 
                                                in_data, 
                                                in_len, 
                                                conn->cipher_buf, 
                                                sizeof(conn->cipher_buf), 
                                                &out_len);

  int rc = 0;
                                                
  if (tls_stat == SMTP_TLS_WANT_WRITE) {
    conn->wire_write_len = out_len;
    rc = smtp_reactor_submit_write( r, 
                                    &conn->op, 
                                    conn->sock, 
                                    conn->cipher_buf, 
                                    out_len, 
                                    conn);
    if (rc != 0) {
      conn->state = SMTP_CONN_STATE_ERROR;
    }
    return conn->state;
  }

  if (tls_stat == SMTP_TLS_WANT_READ) {
    rc = smtp_reactor_submit_read(r, 
                                  &conn->op, 
                                  conn->sock,
                                  conn->cipher_buf,
                                  sizeof(conn->cipher_buf), 
                                  conn);
    if (rc != 0) {
      conn->state = SMTP_CONN_STATE_ERROR;
    }
    return conn->state;
  }

  if (tls_stat == SMTP_TLS_ERROR) {
    smtp_log_emit(SMTP_LOG_TLS_FAIL,
                  &conn->log_id,
                  conn->actor,
                  "TLS handshake failed");
    conn->state = SMTP_CONN_STATE_ERROR;
    return conn->state;
  }

  SMTP_CONN_ASSERT(tls_stat == SMTP_TLS_OK);

  const smtp_tls_cert_info* cert_info = smtp_tls_get_cert_info(conn->tls);
  if (cert_info->validated) {
    smtp_log_emit(SMTP_LOG_TLS_OK, 
                  &conn->log_id, 
                  conn->actor, 
                  cert_info->subject);
  }
  else {
    /* Reaching SMTP_TLS_OK with validated == 0 only happens in trust mode
    ** (strict mode's handshake would have failed instead). See smtp_tls.h's
    ** own contract. Always logged, never silent, per the granular logging
    ** requirement this was specifically built for. */
    smtp_log_emit(SMTP_LOG_TLS_CERT_WARNING, 
                  &conn->log_id,
                  conn->actor,
                  cert_info->failure_reason);
  }

  conn->read_len = 0;

  if (!conn->banner_seen) {
    /* Implicit path: no greeting has been read yet - it arrives now, over
    ** the channel we just encrypted. */
    conn->state = SMTP_CONN_STATE_WAIT_BANNER;
    conn->deadline_ms = now_ms + SMTP_CONN_GREETING_TIMEOUT_MS;
    if (smtp_conn_submit_read_bytes(conn, r) != 0) {
      conn->state = SMTP_CONN_STATE_ERROR;
    }
    return conn->state;
  }

  /* Explicit/opportunistic path: capabilities from before STARTTLS
  ** must be fully discard and rebuilt from the post-TLS EHLO.
  ** RFC 3207 Sec 4.2, see the module doc comment. */
  smtp_cap_init(conn->caps);

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

  rc = smtp_conn_submit_write_bytes(conn, r, conn->write_buf, conn->write_len);
  if (rc != 0) {
    conn->state = SMTP_CONN_STATE_ERROR;
  }
  return conn->state;
}


void 
smtp_connection_init(
        smtp_connection*    conn, 
        smtp_capabilities*  caps, 
        smtp_log_id         log_id, 
  const char*               actor,
        smtp_tls_mode       tls_mode,
        smtp_tls_ctx*       tls_ctx,
        int                 tls_trust_without_validation)
{
  SMTP_CONN_ASSERT(conn != NULL);
  SMTP_CONN_ASSERT(caps != NULL);
  SMTP_CONN_ASSERT(actor != NULL);
  SMTP_CONN_ASSERT(tls_mode == SMTP_TLS_MODE_NONE || tls_ctx != NULL);

  memset(conn, 0, sizeof(*conn));
  conn->caps    = caps;
  conn->log_id  = log_id;

  size_t n = strlen(actor);
  if (n >= sizeof(conn->actor)) {
    n = sizeof(conn->actor) - 1;
  }
  memcpy(conn->actor, actor, n);
  conn->actor[n] = '\0';

  conn->tls_mode                      = tls_mode;
  conn->tls_ctx                       = tls_ctx;
  conn->tls_trust_without_validation  = tls_trust_without_validation;
}


void 
smtp_connection_close(
  smtp_connection* conn)
{
  SMTP_CONN_ASSERT(conn != NULL);
  if (conn->tls != NULL) {
    smtp_tls_destroy(conn->tls);
    conn->tls = NULL;
  }
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
  SMTP_CONN_ASSERT(conn->tls == NULL);

  conn->sock                = sock;
  conn->state               = SMTP_CONN_STATE_CONNECTING;
  conn->connect_timeout_ms  = connect_timeout_ms;
  conn->deadline_ms         = now_ms + connect_timeout_ms;
  conn->read_len            = 0;
  conn->write_len           = 0;
  conn->banner_seen         = 0;

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

  if (conn->state == SMTP_CONN_STATE_TLS_HANDSHAKING) {
    SMTP_CONN_ASSERT(result->kind == SMTP_IO_READ 
      || result->kind == SMTP_IO_WRITE);
    return smtp_conn_handle_tls_handshake(conn, 
                                          r, 
                                          result, 
                                          ehlo_identity, 
                                          now_ms);
  }

  /* For every other state, a READ completion while TLS is already active
  ** means the raw bytes are ciphertext. Decrypt them into plaintext landing
  ** directly in read_buf (which may take several raw reactor round-trips per
  ** one logical plaintext delivery, via SMTP_TLS_WANT_READ below) before any
  ** state specific handler ever sees them. This is the ONLY place
  ** TLS-awareness lives for ordinary read handling. */
  smtp_io_result plain_result = *result;

  if (conn->tls != NULL 
    && result->kind == SMTP_IO_READ 
    && result->result == 0) 
  {
    if (conn->read_len >= sizeof(conn->read_buf)) {
      smtp_log_emit(SMTP_LOG_ERROR, 
                    &conn->log_id, 
                    conn->actor, 
                    "decrypt data would exceed the read buffer");
      conn->state = SMTP_CONN_STATE_ERROR;
      return conn->state;
    }  

    size_t decrypted_len = 0;
    smtp_tls_status tls_stat = smtp_tls_decrypt(conn->tls, 
                                                conn->cipher_buf, 
                                                result->bytes_transferred, 
                                                conn->read_buf 
                                                  + conn->read_len, 
                                                sizeof(conn->read_buf) 
                                                  - conn->read_len, 
                                                &decrypted_len);

    if (tls_stat == SMTP_TLS_WANT_READ) {
      /* Not enough ciphertext yet for a full record. 
      ** Transparently ask for more raw bytes and report nothing
      ** to the state machine this round. */
      if (smtp_conn_submit_read_bytes(conn, r) != 0) {
        conn->state = SMTP_CONN_STATE_ERROR;
      }
      return conn->state;
    }

    if (tls_stat == SMTP_TLS_ERROR) {
      smtp_log_emit(SMTP_LOG_ERROR, 
                    &conn->log_id, 
                    conn->actor, 
                    "TLS decrypt failed");
      conn->state = SMTP_CONN_STATE_ERROR;
      return conn->state;
    }

    SMTP_CONN_ASSERT(tls_stat == SMTP_TLS_OK);
    plain_result.bytes_transferred = decrypted_len; /* 0 = clean TLS-level close */
  }
  
  switch (conn->state) {
    case SMTP_CONN_STATE_CONNECTING:
      SMTP_CONN_ASSERT(result->kind == SMTP_IO_CONNECT);
      return smtp_conn_handle_connect_completion(conn, r, result, now_ms);
      
    case SMTP_CONN_STATE_WAIT_BANNER:
      SMTP_CONN_ASSERT(plain_result.kind == SMTP_IO_READ);
      SMTP_CONN_ASSERT(ehlo_identity != NULL);
      return smtp_conn_handle_banner_read(conn, r, &plain_result, ehlo_identity, now_ms);
    
    case SMTP_CONN_STATE_SENDING_EHLO:
      SMTP_CONN_ASSERT(result->kind == SMTP_IO_WRITE);
      return smtp_conn_handle_ehlo_write_completion(conn, r, result);
      
    case SMTP_CONN_STATE_WAIT_EHLO:
      SMTP_CONN_ASSERT(plain_result.kind == SMTP_IO_READ);
      return smtp_conn_handle_ehlo_read(conn, r, &plain_result, now_ms);

    case SMTP_CONN_STATE_SENDING_STARTTLS:
      SMTP_CONN_ASSERT(result->kind == SMTP_IO_WRITE);
      return smtp_conn_handle_starttls_write_completion(conn, r, result);

    case SMTP_CONN_STATE_WAIT_STARTTLS_REPLY:
      SMTP_CONN_ASSERT(plain_result.kind == SMTP_IO_READ);
      return smtp_conn_handle_starttls_reply(conn, r, &plain_result, now_ms);

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
