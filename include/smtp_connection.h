#ifndef SMTP_CONNECTION_H
#define SMTP_CONNECTION_H

#include <stddef.h>
#include <stdint.h>

#include "smtp_reactor.h"
#include "smtp_capabilities.h"
#include "smtp_log.h"
#include "smtp_tls.h"

/* 
** Per connection state machine covering connect, banner, EHLO, and the 
** TLS upgrade (implicit, or explicit via STARTTLS command) in all 4
** configured modes: none, opportunistic, explicit, implicit.
** See smtp_tls.h's smtp_tls_mode for what each one means.
**
** TLS_HANDSHAKING is one shared state entered from two different places.
** Implicit mode enters it immediately after CONNECTING, before any SMTP text
** at all. Explicit/opportunistic mode enters it after WAIT_EHLO decides to
** upgrade, once STARTTLS command has been sent and accepted. What happens
** when it completes depends on which path led there, tracked via banner_seen
** rather than a second state: if no banner has been read yet (implicit),
** proceed to WAIT_BANNER; if one already has (explicit/opportunistic), the
** capabilities from before TLS are discarded and a second EHLO is sent -
** RFC 3207 Sec 4.2: capabilities negotiated before STARTTLS must never be
** merged with what comes after, since a MITM could have forged them.
**
** Driven by explicit calls from orchestration loop.
**
** Timeout follow RFC 5321 Sec 4.5.3.2 minimum client values:
**    - initial 220 greeting: 5 minutes
**    - EHLO: not seperately enumerated in the RFC table. Defaulted to the
**      same 5-minute minimum as the greeting/MAIL phase, since it sits in
**      the same pre-transaction part of the conversation. A reasonable
**      default, not a directly cited RFC number.
** Connect itself is a transport layer concern the RFC doesn't cover. 
** Its timeout is tool configured (caller supplied), not a RFC minimum.
** The TLS handshake likewise has no RFC-cited minimum of its own -
** defaulted to the same 5-minute class as EHLO/greeting, for the same 
** reason: it's part of the same pre-transaction phase.
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

/* Max length of the actor string for logging: "ip:port - hostname:port"
** (or "ip:port - n/a" when no hostname is known). Sized to fit a full-length
** legal DNS hostname (up to 253 octets, RFC 1035) plus both ports and the 
** seperator, not just a bare IP. The same domain plus margin reasoning
** already used for SMTP_CONN_WRITE_BUF_SIZE above, not an arbitrary number. */
#define SMTP_CONN_MAX_ACTOR_SIZE    320


typedef enum {
  SMTP_CONN_STATE_CONNECTING,
  SMTP_CONN_STATE_WAIT_BANNER,
  SMTP_CONN_STATE_SENDING_EHLO,
  SMTP_CONN_STATE_WAIT_EHLO,
  SMTP_CONN_STATE_SENDING_STARTTLS,
  SMTP_CONN_STATE_WAIT_STARTTLS_REPLY,
  SMTP_CONN_STATE_TLS_HANDSHAKING, /* Shared by implicit/explicit TLS */
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
  size_t  write_len; /* Plaintext command length */
  size_t  wire_write_len; /* Bytes actually handed to the reactor for
                             in-flight write. Equals write_len when TLS is
                             inactive, but is the ciphertext length once
                             it's active, so write completion checks must
                             compare against this, never write_len directly,
                             when TLS might be in play */

  uint64_t connect_timeout_ms;  /* Tool configured not an RFC value             */
  uint64_t deadline_ms;         /* Absolute monotonic deadline for current step */

  smtp_capabilities* caps;  /* Thread owned scratch buffer. Not allocated or
                               owned here, see smtp_capabilities.h design notes
                               on per-thread reuse rather than
                               per-connection embedding */

  smtp_log_id log_id;
  char        actor[SMTP_CONN_MAX_ACTOR_SIZE]; /* Remote host/ip for logging */

  int greeting_code; /* The 220, or error code, kept for diagnostics. */

  smtp_tls_mode tls_mode;
  smtp_tls_ctx* tls_ctx;  /* Thread owned, not allocated or owned here.
                             same reuse convention as caps. NULL is only
                             valid when tls_mode is SMTP_TLS_MODE_NONE */
  smtp_tls*     tls;      /* NULL until a hanshake begins. Non-NULL means every
                             subsequent read/write on this connection must route
                             through it, never the reactor directly. Owned by 
                             this connection once created. 
                             See smtp_connection_close(). */
  int tls_trust_without_validation;
  int banner_seen; /* Distinguishes which side of TLS_HANDSHAKING a 
                      completion in on. See the module doc comment */

  unsigned char cipher_buf[SMTP_CONN_READ_BUF_SIZE]; /* Raw ciphertext buf,
                            used for directions: the target of raw reactor
                            reads pending decrypt and the target
                            smtp_tls_encrypt()/smtp_tls_handshake()
                            write into before a reactor write is submitted.
                            Never holds plaintext. */
  
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
  const char*               actor,
        smtp_tls_mode       tls_mode,
        smtp_tls_ctx*       tls_ctx,
        int                 tls_trust_without_validation
);


/*
** Releases any TLS engine associated with conn. Callers must call this before
** reusing conn for a new connection attempt (via smtp_connection_init again)
** or discarding it, whenever conn may have reached a point where TLS became
** active (READY, or ERROR/TIMED_OUT after STARTTLS was sent or an implicit
** handshake began), otherwise a TLS engine created partway through is leaked.
** Safe to call even if no TLS engine was ever created for conn.
*/
void
smtp_connection_close(
  smtp_connection* conn
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
