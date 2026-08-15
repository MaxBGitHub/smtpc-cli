#include "../include/smtp_tls.h"

#if !defined(_WIN32)

/*
** For timegm() under -std=c11 - timegm is a BSD/glibc extension, not POSIX
** standardized despite being POSIX adjacent, so _POSIX_C_SOURCE alone
** dones not expose it.
** Must precede all system headers below.
*/
#define _DEFAULT_SOURCE

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


/*
** OpenSSL backend (Linux/macOS/FreeBSD/OpenBSD).
** 
** Built entirely on a memory BIO pair (BIO_new_bio_pair), never OpenSSL's
** default socket-BIO mode. The SSL objects internal BIO is handed to 
** SSL_set_bio. The 'network' BIO is ours, every byte OpenSSL wants to send
** appears there for us to drain and hand to the reactor, and every byte
** we read via the reactor gets written there for OpenSSL to consume.
** OpenSSL never sees a real socket.
*/


static void
smtp_tls_assert_fail(
  const char* expr,
  const char* file,
        int   line)
{
  fprintf(stderr,
          "smtp_tls_openssl: internal assertion failed: %s (%s:%d)\n",
          expr, file, line);
  abort();
}


#define SMTP_TLS_ASSERT(cond) \
  do { \
    if (!(cond)) { \
      smtp_tls_assert_fail(#cond, __FILE__, __LINE__); \
    } \
  } while (0)


typedef enum {
  SMTP_TLS_ERR_OK = 0,
  SMTP_TLS_ERR_INVALID_ARG,
  SMTP_TLS_ERR_ALLOC_FAILED,
  SMTP_TLS_ERR_CTX_CREATE_FAILED,
  SMTP_TLS_ERR_TRUST_STORE_LOAD_FAILED,
  SMTP_TLS_ERR_BIO_PAIR_FAILED,
  SMTP_TLS_ERR_SSL_CREATE_FAILED,
  SMTP_TLS_ERR_HANDSHAKE_FAILED,
  SMTP_TLS_ERR_PROTOCOL_ERROR,
  SMTP_TLS_ERR_COUNT
} smtp_tls_err;


static const char *const g_smtp_tls_err_strings[SMTP_TLS_ERR_COUNT] = {
    [SMTP_TLS_ERR_OK]                        = "no error",
    [SMTP_TLS_ERR_INVALID_ARG]               = "invalid argument",
    [SMTP_TLS_ERR_ALLOC_FAILED]              = "allocation failed",
    [SMTP_TLS_ERR_CTX_CREATE_FAILED]         = "SSL_CTX_new failed",
    [SMTP_TLS_ERR_TRUST_STORE_LOAD_FAILED]   = "failed to load the system trust store",
    [SMTP_TLS_ERR_BIO_PAIR_FAILED]           = "BIO_new_bio_pair failed",
    [SMTP_TLS_ERR_SSL_CREATE_FAILED]         = "SSL_new failed",
    [SMTP_TLS_ERR_HANDSHAKE_FAILED]          = "TLS handshake failed",
    [SMTP_TLS_ERR_PROTOCOL_ERROR]            = "TLS protocol error",
};

static _Thread_local smtp_tls_err g_smtp_tls_last_err = SMTP_TLS_ERR_OK;

static smtp_tls_err
smtp_tls_fail(
  smtp_tls_err err)
{
  g_smtp_tls_last_err = err;
  return err;
}

const char*
smtp_tls_get_last_error(void)
{
  SMTP_TLS_ASSERT(g_smtp_tls_last_err < SMTP_TLS_ERR_COUNT);
  return g_smtp_tls_err_strings[g_smtp_tls_last_err];
}


struct smtp_tls_ctx {
  SSL_CTX* ssl_ctx;
};

struct smtp_tls {
  SSL*                ssl;
  BIO*                network_bio; /* our side of the pair - we push/pull ciphertext here */
  int                 handshake_done;
  int                 trust_without_validation;
  char                hostname[256];
  smtp_tls_cert_info  cert_info;
};


/*
** Bounded copy into a NUL-terminated destination, matching the pattern used
** throughout the rest of this codebase (see smtp_connection.c's
** own copy helper). 
*/ 
static void 
smtp_tls_copy_bounded(
  const char*   src,
        char*   dst,
        size_t  dst_size)
{
  size_t n = strlen(src);
  if (n >= dst_size) {
    n = dst_size - 1;
  }
  memcpy(dst, src, n);
  dst[n] = '\0';
}


smtp_tls_ctx*
smtp_tls_ctx_create(void) 
{
  smtp_tls_ctx* ctx = malloc(sizeof(*ctx));
  if (ctx == NULL) {
    smtp_tls_fail(SMTP_TLS_ERR_ALLOC_FAILED);
    return NULL;
  }

  ctx->ssl_ctx = SSL_CTX_new(TLS_client_method());
  if (ctx->ssl_ctx == NULL) {
    free(ctx);
    smtp_tls_fail(SMTP_TLS_ERR_CTX_CREATE_FAILED);
    return NULL;
  }

  /* Floor at TLS 1.2 by default. A stress-testing tool may
  ** deliberately want to probe older/weaker configurations later -
  ** that's a future config knob, not something to silently allow by
  ** default here. */
  SSL_CTX_set_min_proto_version(ctx->ssl_ctx, TLS1_2_VERSION);

  if (SSL_CTX_set_default_verify_paths(ctx->ssl_ctx) != 1) {
    SSL_CTX_free(ctx->ssl_ctx);
    free(ctx);
    smtp_tls_fail(SMTP_TLS_ERR_TRUST_STORE_LOAD_FAILED);
    return NULL;
  }

  smtp_tls_fail(SMTP_TLS_ERR_OK);
  return ctx;
}


void
smtp_tls_ctx_destroy(
  smtp_tls_ctx* ctx)
{
  if (ctx == NULL) {
    return;
  }
  SSL_CTX_free(ctx->ssl_ctx);
  free(ctx);
}


/*
** Runs once per certificate in the chain (leaf at depth 0, then each
** issuer up toward the root at increasing depth). Always captures info about
** the leaf specifically (depth 0), that's the certificate an admin actually
** wants subject/issuer/expiry for, not whichever cert this callback happens
** to be invoked for last. Records the first validation failure seen across
** the while chain and never lets a later unrelated callback invocation for
** a different certificate paper over it.
** Returns 1 (continue) unconditionally in trust mode. 
** Otherwise returns preverify_ok, so OpenSSL genuinely aborts the
** handshake on a real validation failure in normal/strict mode.
*/
static int
smtp_tls_verify_callback(
  int             preverify_ok,
  X509_STORE_CTX* store_ctx)
{
  SSL* ssl = X509_STORE_CTX_get_ex_data(store_ctx, 
                                        SSL_get_ex_data_X509_STORE_CTX_idx());
  smtp_tls* tls = (smtp_tls*)SSL_get_app_data(ssl);
  SMTP_TLS_ASSERT(tls != NULL);

  int depth = X509_STORE_CTX_get_error_depth(store_ctx);
  X509* cert = X509_STORE_CTX_get_current_cert(store_ctx);

  if (depth == 0 && cert != NULL) {
    X509_NAME_oneline(X509_get_subject_name(cert),
                      tls->cert_info.subject,
                      sizeof(tls->cert_info.subject));
    X509_NAME_oneline(X509_get_issuer_name(cert),
                      tls->cert_info.issuer, 
                      sizeof(tls->cert_info.issuer));
    struct tm exp_tm;
    memset(&exp_tm, 0, sizeof(exp_tm));
    if (ASN1_TIME_to_tm(X509_get0_notAfter(cert), &exp_tm) == 1) {
      tls->cert_info.not_after = timegm(&exp_tm);
    }
  }

  if (!preverify_ok && tls->cert_info.validated) {
    tls->cert_info.validated = 0;
    int err = X509_STORE_CTX_get_error(store_ctx);
    smtp_tls_copy_bounded(X509_verify_cert_error_string(err),
                          tls->cert_info.failure_reason,
                          sizeof(tls->cert_info.failure_reason));
  }
  return tls->trust_without_validation 
          ? 1 
          : preverify_ok;
}


smtp_tls*
smtp_tls_create(
        smtp_tls_ctx* ctx,
  const char*         hostname,
        int           trust_without_validation)
{
  SMTP_TLS_ASSERT(ctx != NULL);
  SMTP_TLS_ASSERT(hostname != NULL);

  size_t hostname_len = strlen(hostname);

  smtp_tls* tls = calloc(1, sizeof(*tls));
  if (tls == NULL) {
    smtp_tls_fail(SMTP_TLS_ERR_ALLOC_FAILED);
    return NULL;
  }

  if (hostname_len >= sizeof(tls->hostname)) {
    free(tls);
    smtp_tls_fail(SMTP_TLS_ERR_INVALID_ARG);
    return NULL;
  }
  memcpy(tls->hostname, hostname, hostname_len);
  tls->hostname[hostname_len] = '\0';

  tls->trust_without_validation = trust_without_validation;
  tls->cert_info.validated      = 1; /* Optimistic default, the verify callback
                                        clears this on the first real 
                                        failure seen */

  tls->ssl = SSL_new(ctx->ssl_ctx);
  if (tls->ssl == NULL) {
    free(tls);
    smtp_tls_fail(SMTP_TLS_ERR_SSL_CREATE_FAILED);
    return NULL;
  }

  BIO* internal_bio = NULL;
  if (BIO_new_bio_pair(&internal_bio, 16384, &tls->network_bio, 16384) != 1) {
    SSL_free(tls->ssl);
    free(tls);
    smtp_tls_fail(SMTP_TLS_ERR_BIO_PAIR_FAILED);
    return NULL;
  }

  /* SSL_set_bio takes ownership of the BIOs passed to it. Passing the same
  ** one for both rbio and wbio is the standard, documented pattern here. */
  SSL_set_bio(tls->ssl, internal_bio, internal_bio);
  SSL_set_connect_state(tls->ssl); /* We are always the client */
  SSL_set_app_data(tls->ssl, tls); /* Recovered inside the verify callback */

  SSL_set_tlsext_host_name(tls->ssl, tls->hostname); /* SNI */

  SSL_set_verify(tls->ssl, SSL_VERIFY_PEER, smtp_tls_verify_callback);
  if (!trust_without_validation) {
    X509_VERIFY_PARAM* param = SSL_get0_param(tls->ssl);
    X509_VERIFY_PARAM_set1_host(param, tls->hostname, 0);
  }

  smtp_tls_fail(SMTP_TLS_ERR_OK);
  return tls;
}


void
smtp_tls_destroy(
  smtp_tls* tls)
{
  if (tls == NULL) {
    return;
  }

  /* network_bio is the other half of the pair we passed to SSL_set_bio.
  ** That half is freed by SSL_free. 
  ** Only our side needs an explicit BIO_free here. */
  BIO_free(tls->network_bio);
  SSL_free(tls->ssl);
  free(tls);
}


const smtp_tls_cert_info*
smtp_tls_get_cert_info(
  const smtp_tls* tls)
{
  SMTP_TLS_ASSERT(tls != NULL);
  return &tls->cert_info;
}


static int
smtp_tls_feed_input(
        smtp_tls* tls,
  const void*     data,
        size_t    len)
{
  if (len == 0) {
    return 0;
  }

  int n = BIO_write(tls->network_bio, data, (int)len);
  return (n >= 0 && (size_t)n == len) 
    ? 0 
    : -1;
}


static size_t
smtp_tls_drain_output(
  smtp_tls* tls,
  void*     out_buf,
  size_t    out_buf_size)
{
  int n = BIO_read(tls->network_bio, out_buf, (int)out_buf_size);
  return (n > 0) 
    ? (size_t)n 
    : 0;
}


smtp_tls_status
smtp_tls_handshake(
        smtp_tls* tls,
  const void*     in_data,
        size_t    in_len,
        void*     out_buf,
        size_t    out_buf_size,
        size_t*   out_len)
{
  SMTP_TLS_ASSERT(tls != NULL);
  SMTP_TLS_ASSERT(out_buf != NULL);
  SMTP_TLS_ASSERT(out_len != NULL);

  *out_len = 0;

  if (smtp_tls_feed_input(tls, in_data, in_len) != 0) {
    smtp_tls_fail(SMTP_TLS_ERR_BIO_PAIR_FAILED);
    return SMTP_TLS_ERROR;
  }

  int rc = SSL_do_handshake(tls->ssl);

  /* Drain first, regardless of rc: OpenSSL may have queued bytes to send
  ** (e.g. our ClientHello) even when the call itself reports WANT_READ (now 
  ** waiting on the server). Output always takes priority over interpreting
  ** rc, the caller must send it before calling again either way. */
  size_t drained = smtp_tls_drain_output(tls, out_buf, out_buf_size);
  if (drained > 0) {
    *out_len = drained;
    return SMTP_TLS_WANT_WRITE;
  }

  if (rc == 1) {
    tls->handshake_done = 1;
    return SMTP_TLS_OK;
  }

  int err = SSL_get_error(tls->ssl, rc);
  if (err == SSL_ERROR_WANT_READ) {
    return SMTP_TLS_WANT_READ;
  }

  if (err == SSL_ERROR_WANT_WRITE) {
    /* Should be rare given we already drained above, handled explicitly 
    ** rather than assumed unreachable. Nothing is actually pending to write
    ** at this point, so requesting more input is 
    ** the correct, safe way forward. */
    return SMTP_TLS_WANT_READ;
  }

  smtp_tls_fail(SMTP_TLS_ERR_HANDSHAKE_FAILED);
  return SMTP_TLS_ERROR;
}


smtp_tls_status
smtp_tls_encrypt(
        smtp_tls* tls,
  const void*     plaintext,
        size_t    plaintext_len,
        void*     out_buf,
        size_t    out_buf_size,
        size_t*   out_len)
{
  SMTP_TLS_ASSERT(tls != NULL);
  SMTP_TLS_ASSERT(tls->handshake_done);
  SMTP_TLS_ASSERT(out_buf != NULL);
  SMTP_TLS_ASSERT(out_len != NULL);

  *out_len = 0;

  if (plaintext_len > 0) {
    int wrc = SSL_write(tls->ssl, plaintext, (int)plaintext_len);
    if (wrc <= 0) {
      int err = SSL_get_error(tls->ssl, wrc);
      if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
        smtp_tls_fail(SMTP_TLS_ERR_PROTOCOL_ERROR);
        return SMTP_TLS_ERROR;
      }
      /* Fall through - drain below reports whatever was actually 
      ** produced, if anything. */      
    }
  }

  size_t drained = smtp_tls_drain_output(tls, out_buf, out_buf_size);
  if (drained > 0) {
    *out_len = drained;
    return SMTP_TLS_WANT_WRITE;
  }
  return SMTP_TLS_WANT_READ;
}


smtp_tls_status
smtp_tls_decrypt(
        smtp_tls* tls,
  const void*     in_data,
        size_t    in_len,
        void*     out_buf,
        size_t    out_buf_size,
        size_t*   out_len)
{
  SMTP_TLS_ASSERT(tls != NULL);
  SMTP_TLS_ASSERT(tls->handshake_done);
  SMTP_TLS_ASSERT(out_buf != NULL);
  SMTP_TLS_ASSERT(out_len != NULL);

  *out_len = 0;

  if (smtp_tls_feed_input(tls, in_data, in_len) != 0) {
    smtp_tls_fail(SMTP_TLS_ERR_BIO_PAIR_FAILED);
    return SMTP_TLS_ERROR;
  }

  int rc = SSL_read(tls->ssl, out_buf, (int)out_buf_size);

  if (rc > 0) {
    *out_len = (size_t)rc;
    return SMTP_TLS_OK;
  }

  int err = SSL_get_error(tls->ssl, rc);
  if (err == SSL_ERROR_WANT_READ) {
    return SMTP_TLS_WANT_READ;
  }

  if (err == SSL_ERROR_ZERO_RETURN) {
    /* Clean TLS level shutdown (close_notify). Reported as a successful
    ** zero-byte read, mirroring how the reactor already treats a 0-byte
    ** plaintext layer EOF as protocol neutral success rather than an
    ** error at this layer. */
    return SMTP_TLS_OK;
  }

  smtp_tls_fail(SMTP_TLS_ERR_PROTOCOL_ERROR);
  return SMTP_TLS_ERROR;
}


smtp_tls_status
smtp_tls_shutdown(
  smtp_tls* tls,
  void*     out_buf,
  size_t    out_buf_size,
  size_t*   out_len)
{
  SMTP_TLS_ASSERT(tls != NULL);
  SMTP_TLS_ASSERT(out_buf != NULL);
  SMTP_TLS_ASSERT(out_len != NULL);

  *out_len = 0;

  if (!tls->handshake_done) {
    /* Nothing meaningful to shut down, the handshake never actually completed,
    ** so there is no close_notify to send. Not an error... the caller should
    ** simply close the underlying socket. */
    return SMTP_TLS_OK;
  }

  SSL_shutdown(tls->ssl);

  size_t drained = smtp_tls_drain_output(tls, out_buf, out_buf_size);
  if (drained > 0) {
    *out_len = drained;
    return SMTP_TLS_WANT_WRITE;
  }
  return SMTP_TLS_OK;
}

#endif /* !_WIN32 */
