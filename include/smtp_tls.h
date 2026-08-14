#ifndef SMTP_TLS_H
#define SMTP_TLS_H

#include <stddef.h>


/*
** TLS engine interface. One instance per connection, backed by exactly one
** of OpenSSL (Linux/macOS/FreeBSD/OpenBSD) or SChannel (Windows) - chosen
** at compile time via platform detection in the corresponding 
** smtp_tls_*.c file, never at runtime, matching smtp_reactor.h's own
** backend-selection discipline.
**
** This engine NEVER touches a socket. It is a pure memory-buffer transform:
** feed it ciphertext bytes already read via the reactor, it hands back 
** plaintext. Feed it plaintext to send, it hands back ciphertext to write
** via the reactor. Neither OpenSSL's default socket-BIO mode nor SChannel's 
** API assume the same things about who owns the socket - the reactor
** already owns it, so both backends are built in memory-buffer mode (OpenSSL's 
** memory BOI pair. SChannel's native EncryptMessage/DecryptMessage-on-buffers
** shape), letting both present this identical interface despite being
** structurally different underneath. The same principle as the reactor's
** three backends presenting one interface.
**
** The handshake is its own sub-state-machine, driven by explicit calls exactly
** like smtp_connection. No poll loop of its own here either. A TLS handshake
** is several message round-trips, and under non blocking I/O each step can
** span mutliple reactor read/poll cycles as TCP delivers the stream in 
** arbitrary sized chunks, so "call once, done" is not a real option.
*/

#define SMTP_TLS_CERT_FIELD_LEN   256
#define SMTP_TLS_CERT_REASON_LEN  128


typedef enum {
  SMTP_TLS_MODE_NONE,           /* Never attempt TLS  */
  SMTP_TLS_MODE_OPPORTUNISTIC,  /* STARTTLS if offered, continue plaintext if
                                    not. FAILS is still a hard error, never a
                                    silent fallback. Opportunistic govers
                                    whether an attempt is requried to be
                                    offered, not whether a failed attempt is
                                    tolerated. */
  SMTP_TLS_MODE_EXPLICIT,       /* Require STARTTLS. End the connection if the 
                                    server doesn't offer it. */
  SMTP_TLS_MODE_IMPLICIT        /* TLS handshake begins immediately on connect,
                                    before any SMTP text is exchanged. 
                                    No STARTTLS command and STARTTLS is never
                                    attempted even if a server oddly advertises
                                    it post-handshake (a second handshake makes
                                    no sense on an already encrypted channel). */
} smtp_tls_mode;


typedef enum {
  SMTP_TLS_OK = 0,      /* This call's operation completed */
  SMTP_TLS_WANT_READ,   /* Need more ciphertext from the peer before
                            continuing. Read more via the reactor, then
                            call again with it */
  SMTP_TLS_WANT_WRITE,  /* out_buf/out_len holds ciphertext that MUST be sent
                            to the peer via the reactor before calling again */
  SMTP_TLS_ERROR        /* Unrecoverable, see smtp_tls_get_last_error() */
} smtp_tls_status;


/*
** Certificate info is always populated after a handshake reaches SMTP_TLS_OK,
** Including a trust-mode handshake that proceedes despite failing validation.
** trust_without_validation never skips inspecting the certificate, it only 
** controls whether a failed validation aborts the handshake or is logged and
** continues. This struct is what the connection layer's log call site reads
** to emit TLS_OK / TLS_CERT_WARNING. The certificate detail an admin actually
** needs to debug an MTA is the entire point of this field existing, 
** not an afterthought.
*/
typedef struct {
  int   validated; /* 1 if cert passed full  chain + hostname validation */
  char  failure_reason[SMTP_TLS_CERT_REASON_LEN]; /* Populated if !validated */
  char  subject[SMTP_TLS_CERT_FIELD_LEN]; 
  char  issuer[SMTP_TLS_CERT_FIELD_LEN];
  long  not_after; /* Cert expiry, Unix timestamp */
} smtp_tls_cert_info;


typedef struct smtp_tls_ctx smtp_tls_ctx; /* Opaque, one per reactor thread */

/*
** Creates the thread scoped TLS context: Loads the system trust store and 
** holds engine level configuration shared across every connection on this 
** thread. Expensive (real filesystem I/O and CA cert parsing). Create once
** per reactor thread and reuse across every connection on it.
** Never create one per connection. At bulk test scale (thousands of 
** connections) that would repeat this cost needlessly on every single one.
** Returns NULL on failure, see smtp_tls_get_last_error().
*/
smtp_tls_ctx* smtp_tls_ctx_create(void);
void smtp_tls_ctx_destroy(smtp_tls_ctx* ctx);


typedef struct smtp_tls smtp_tls; /* Opaque, one per connection */

/*
** Creates a TLS engine for one connection. Hostname is used for SNI and,
** when trust_without_validation is 0, hostname verification.
** Returns NULL on failure - see smtp_tls_get_last_error().
*/
smtp_tls* 
smtp_tls_create(
        smtp_tls_ctx* ctx,
  const char*         hostname,
        int           trust_without_validation
);

void smtp_tls_destroy(smtp_tls* tls);


/*
** Drives the handshake forward by one step. On the very first call,
** pass in_data=NULL, in_len = 0. Whenever the peer has sent bytes, pass them
** as in_data/in_len on the next call.
**
** SMTP_TLS_WANT_WRITE: *out_len bytes were written into out_buf and MUST be
**  sent to the peer via the reactor before calling again.
** SMTP_TLS_WANT_READ: more ciphertext is needed from the peer before the 
**  handshake can proceed further. No output was produced.
** SMTP_TLS_OK: the handshake is complete. smtp_tls_get_cert_info() is now 
**  valid, and smtp_tls_encrypt()/smtp_tls_decrypt() may be used.
*/
smtp_tls_status 
smtp_tls_handshake(
        smtp_tls* tls,
  const void*     in_data,
        size_t    in_len,
        void*     out_buf,
        size_t    out_buf_size,
        size_t*   out_len
);

const smtp_tls_cert_info* smtp_tls_get_cert_info(const smtp_tls* tls);


/*
** Encrypts palintext_len bytes of application data into out_buf.
** Can in principal return SMTP_TLS_WANT_WRITE if TLS-layer bookkeeping bytes
** need to be flushed first (e.g. a post-handshake protocol message).
** Same drain-before-retry contract as the handshake, kept explicitly in 
** the API even though it should be rare in practive, rather than 
** assumed away.
*/
smtp_tls_status 
smtp_tls_encrypt(
        smtp_tls* tls,
  const void*     plaintext, 
        size_t    plaintext_len,
        void*     out_buf,
        size_t    out_buf_size,
        size_t*   out_len
);


/*
** Decrypts newly received ciphertext (in_data/in_len) into plaintext
** (out_buf/out_len). Returns SMTP_TLS_WANT_READ if more ciphertext is
** needed before a full plaintext record can be produced.
*/
smtp_tls_status
smtp_tls_decrypt(
        smtp_tls* tls,
  const void*     in_data,
        size_t    in_len,
        void*     out_buf, 
        size_t    out_buf_size,
        size_t*   out_len
);


/*
** Initiates a clean TLS shutdown by sending a close_notify alert to the peer.
** Best effort and single shot, deliberately not a multi-round-trip exchange:
**  the caller writes out_buf/out_len (if SMTP_TLS_WANT_WRITE) via the reactor
**  and then closes the underlying socket. This function does not wait for
**  the peer's own close_notify in return, matching standard client practive.
**  A blocking on the peer's acknowledgement, and risks hanging if the peer
**  never sends one. Whithout this, the abrupt close is what an independet
**  peer's TLS stack reports as "unexpected eof", which is indistinguishable 
**  at the wire level from a truncation attack even though nothing was 
**  actually lost.
**
** Returns SMTP_TLS_OK if there is nothing to send (the handshake never 
** completed, or a prior call already sent it). The caller should simply close
** the socket in that case too. Safe to call more than once.
** A redundant call is a harmless no-op.
*/
smtp_tls_status
smtp_tls_shutdown(
  smtp_tls* tls, 
  void*     out_buf, 
  size_t    out_buf_size,
  size_t*   out_len);


const char* smtp_tls_get_last_error(void);

#endif /* SMTP_TLS_H */
