#ifndef SMTP_LOG_H
#define SMTP_LOG_H

#include <stddef.h>
#include <stdint.h>

/*
** MTA-style verbose plain-text logger (Cisco ESA-style).
** Unstructured; One line per event:
**
**  [yyyy-MM-dd] [HH:mm:ss.ms] [T0001.C0003.M0047] [actor] EVENT detail...
**
** - Timestamp: UTC, purely numeric (no locale dependent day/month names)
**      Millisecond precision.
** - ID: thread.connection for connection level events, extended with 
**     .message for message level events (MAIL FROM/RCPT TO/DATA) - refuses
**     the same global atomic message sequence already used in generated
**      subject lines, so a log line and the corresponding subject line
**      correlate directly via that number.
** - Actor: the local bind address/hostname or the remote target host,
**      whichever side issued this event - caller supplied, this module
**      doesn't know or care about connection semantics.
** - Event: one of a small fixed uppercase vocabulary, always the first token
**      after the actor bracket, so plain grep/awk can filter reliably 
**      without a real parser.
**
** Sanitization scope (deliberately narrow): text that already passed
** smtp_reply_parse_line() is provably free of CR/LF/control chars by
** that parser's own grammar (HTAB + 0x20-0x7E only) - it needs no
** further sanitizing, and re-checking it here would just be redundant
** work. The one place raw, unvalidated external bytes reach the logger
** is diagnostic dumps on parse failure/timeout/protocol anomalies -
** exactly what smtp_log_hex_dump() is for.
*/

typedef enum {
  SMTP_LOG_CONNECTING,
  SMTP_LOG_CONNECTED,
  SMTP_LOG_EHLO,
  SMTP_LOG_REPLY,
  SMTP_LOG_CAPABILITIES,
  SMTP_LOG_STARTTLS,
  SMTP_LOG_TLS_BEGIN,
  SMTP_LOG_TLS_OK,
  SMTP_LOG_TLS_FAIL,
  SMTP_LOG_TLS_CERT_WARNING, /* Handshake succeeded in trust mode despite
                                a certificate that would have failed strict
                                validation - detail is the reason it would
                                have failed */
  SMTP_LOG_MAIL_FROM,
  SMTP_LOG_RCPT_TO,
  SMTP_LOG_DATA_BEGIN,
  SMTP_LOG_DATA_END,
  SMTP_LOG_RSET,
  SMTP_LOG_QUIT,
  SMTP_LOG_DISCONNECT,
  SMTP_LOG_ERROR,
  SMTP_LOG_TIMEOUT,
  SMTP_LOG_EVENT_COUNT
} smtp_log_event;


typedef struct {
  uint64_t  thread_id;
  uint64_t  connection_id;
  uint64_t  message_seq;      /* Only relevent if has_message_seq is set */
  int       has_message_seq;
} smtp_log_id;


/*
** Renders src[0..src_len] as an uppercase, space separated bracketed
** hex dump: [1B 0A 41 00]. If src_len exceeds max_bytes, only the first
** max_bytes are dumped and a " +N more bytes]" suffix (inside the closing
** bracket) reports how many bytes were omitted - same
** truncation-is-always-reported discipline used by the capability parsers
** unknown[] slots, never a silent cut.
**
** Bounded, allocation-free: writes into caller-owned dst[dst_size],
** always NUL-terminated. Returns the number of bytes written
** (excluding the NUL), or 0 if dst_size is too small to hold even the 
** empty brackets.
**
** This is the ONLY sanatization primitive this module has - see the
** file-level comment on why nothing else needs one.
*/
size_t smtp_log_hex_dump(
        char*           dst,
        size_t          dst_size,
  const unsigned char*  src,
        size_t          src_len,
        size_t          max_bytes
);


/*
** smtp_log_init() must be called exactly once, before any thread calls
** smtp_log_emit(), and smtp_log_shutdown() exactly once after every
** thread that might call emit() has finished. Neither is safe to call
** concurrently with the other or with itself. smtp_log_emit() IS safe
** to call concurrently from many threads once init has succeeded.
** A single mutex-guarded shared writer serializes actual file writes.
**
** Opens filepath in append mode (never clobbers a prior run's log).
** Returns 0 on success; on failure returns non-zero and
** smtp_log_get_last_error() gives a static, non-thread-local reason
** string (init is inherently a single call, startup time operation, so it
** doesn't need the per-thread GetLastError pattern used elsewhere).
*/
int smtp_log_init(const char* filepath);
void smtp_log_shutdown(void);
const char* smtp_log_get_last_error(void);

/*
** Formats and writes one log line:
**    [yyyy-MM-dd] [HH:mm:ss.ms] [T####.C####(.M####)] [actor] EVENT detail
**
** actor and detail must never contain a raw CR or LF - every legit call site
** already guarantees this (validated reply text is CR/LF free by the reply 
** parsers own grammar. Raw/unvalidated bytes must go through
** smtp_log_hex_dump() first, which never emits a literal control byte).
** This is asserted, not gracefully handled: if it fires, it means a call site
** skipped that step, which is a bug in this codebase to fix, not external
** input to accept or tolerate.
*/
void 
smtp_log_emit(
        smtp_log_event  type, 
  const smtp_log_id*    id, 
  const char*           actor, 
  const char*           detail
);


#endif /* SMTP_LOG_H */
