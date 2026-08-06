#ifndef SMTP_CONNECTION_H
#define SMTP_CONNECTION_H

#include <stddef.h>
#include <stdint.h>

#include "smtp_reactor.h"
#include "smtp_capabilities.h"
#include "smtp_log.h"

/* 
** Per connection state machine covering connect, banner, EHLO.
** Driven by explicit calls from an orchestration loop.
**
** Timeout follow RFC 5321 Sec 4.5.3.2 minimum client values:
**    - initial 220 greeting: 5 minutes
**    - EHLO: not seperately enumerated in the RFC table. Defaulted to the
**      same 5-minute minimum as the greeting/MAIL phase, since it sits in
**      the same pre-transaction part of the conversation. A reasonable
**      default, not a directly cited RFC number.
** Connect itself is a transport layer concern the RFC doesn't cover. 
** Its timeout is tool configured (caller supplied), not a RFC minimum.
**
** Deliberately deferred for this pass: falling back to HELO when a server
** rejects EHLO (RFC 5321 Sec 4.1.4) - rare among real servers, but a known 
** gap, not a missed one. Also deferred: partial write continuation for the 
** EHLO command itself. The line is short enough that a partial write should
** be rare and when it happens it's treated as a connection level error (never
** a process level assert, since it's a possible network/OS condition).
*/

/* Covers a real world EHLO response with margin. 
** A server that fills this without completing
** a valid reply is treated as an error, not a
** silent truncation */
#define SMTP_CONN_READ_BUF_SIZE     4096

/* 'EHLO ' + max 255-octet domain 
** (RFC 5321 Sec 4.5.3.1) + CRLF with margin */
#define SMTP_CONN_WRITE_BUF_SIZE    320

/* Bound for smtp_reply_read() line count guard. 
** Generous for any real EHLO response */
#define SMTP_CONN_MAX_REPLY_LINES   64

/* Max length of host/ip for logging.*/
#define SMTP_CONN_MAX_ACTOR_SIZE    64


typedef enum {
  SMTP_CONN_STATE_CONNECTING,
  SMTP_CONN_STATE_WAIT_BANNER,
  SMTP_CONN_STATE_SENDING_EHLO,
  SMTP_CONN_STATE_WAIT_EHLO,
  SMTP_CONN_STATE_READY, /* EHLO complete and capabilities populated */
  SMTP_CONN_STATE_ERROR,
  SMTP_CONN_STATE_TIMED_OUT
} smtp_conn_state;


typedef struct {
  smtp_socket     sock;
  smtp_io_op      op;
  smtp_conn_state state;

  char    read_buf[SMTP_CONN_READ_BUF_SIZE];
  size_t  read_len;

  char    write_buf[SMTP_CONN_WRITE_BUF_SIZE];
  size_t  write_len;

  uint64_t connect_timeout_ms;  /* Tool configured not an RFC value             */
  uint64_t deadline_ms;         /* Absolute monotonic deadline for current step */

  smtp_capabilities* caps;  /* Thread owned scratch buffer. Not allocated or
                            ** owned here, see smtp_capabilities.h design notes
                            ** on per-thread reuse rather than
                            ** per-connection embedding */

  smtp_log_id log_id;
  char        actor[SMTP_CONN_MAX_ACTOR_SIZE]; /* Remote host/ip for logging */

  int greeting_code; /* The 220, or error code, kept for diagnostics. */
} smtp_connection;


/*
** Initializes conn for reuse, caps must outlive conn and is the reactor
** threads shared scratch buffer, not per connection state. Callers pass
** the same smtp_capabilities* across many connections on one thread.
** 'actor' is copied (truncated safely if too long).
*/ 
void
smtp_connection_init(
        smtp_connection*    conn,
        smtp_capabilities*  caps,
        smtp_log_id         log_id,
  const char*               actor
);


/*
** Begins the connection: submits the connect via the reactor and sets the
** CONNECTING state and its deadline. sock must already exist (created but
** not connected). Matches smtp_reactor_submit_connect own contract.
** connect_timeout_ms is tool configured, not RFC derived.
** now_ms is the caller's current monotonic clock reading, so this module
** never reads the clock itself. Keeps it trivially testable with syntehic time.
**
** Returns 0 on successful submission, non-zero if reactor rejected it
** (capacity, bad args). See smtp_reactor_get_last_error().
*/
int
smtp_connection_start(
        smtp_connection*  conn,
        smtp_reactor*     r,
        smtp_socket       sock,
  const struct sockaddr*  addr,
        size_t            addr_len,
        uint64_t          now_ms,
        uint64_t          connect_timeout_ms
);


/*
** Feeds one reactor completion to the connections state machine.
** Callers must only pass a result whose user_data == conn (the 
** orchestration loops job to route correctly - passing a mismatched result
** is a caller contract violation, asserted, not gracefully handled, since it
** indicates a bug in the dispatch loop, not anything external). 
** ehlo_identity is the local identity to send in the EHLO command 
** (RFC 5321 Sec 4.1.4: FQDN or address literal) - caller supplied, since
** reliable cross platform hostname detection is its own seperate
** concern, not this modules.
**
** Returns the connection's state after processing.
*/
smtp_conn_state 
smtp_connection_on_io(
        smtp_connection*  conn,
        smtp_reactor*     r,
  const smtp_io_result*   result,
  const char*             ehlo_identity,
        uint64_t          now_ms
);


/*
** Checks whether the connections current step has exceeded its deadline. 
** Call this periodically from the orchestration loop, independent of I/O
** completions (a connection can time out even if nothing else ever arrives
** for it). Returns the resulting state - SMTP_CONN_STATE_TIMED_OUT if it 
** just timed out, otherwise the connection's unchanged current state.
*/
smtp_conn_state
smtp_connection_check_timeout(
  smtp_connection*  conn,
  uint64_t          now_ms
);


#endif /* SMTP_CONNECTION_H */
