#include "../include/smtp_tls.h"

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
#endif
#define SECURITY_WIN32

#include <windows.h>
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/*
** SChannel/SSPI backend (Windows). 
**
** Structural differences from the OpenSSL backend:
**  - No BIO-pair equivalent: InitizalizeSecurityContext/DecryptMessage take
**    input/output buffers directly as call parameters rather than through
**    a persistent internal buffer pair. This actually maps more directly
**    onto smtp_tls.h's own in_data/out_buf per call shape than OpenSSL's
**    BIO-drain model did.
**  - SChannel does NOT buffer partial input itself the way OpenSSL's BIO-pair
**    does. When a full TLS record isn't available yet 
**    (SEC_E_INCOMPLETE_MESSAGE), accumulating the partial bytes across calls
**    is this backend's own job. See the accum field below - both the handshake
**    and decrypt use it.
**  - Certificate validation is asymmetric by design: in normal/strict mode,
**    SChannel validates the chain itself and the handshake simply fails
**    on a bad certificate. No verify callback needed, unlike OpenSSL.
**    In trust mode, ISC_REQ_MANUAL_CRED_VALIDATION tells SChannel to skip
**    that automatic check, and this backend then performs the identical
**    validation manually (CertGetCertificateChain + 
**    CertVerifyCertificateChainPolicy) purely to capture and report why it
**    would have failed, exactly mirroring the OpenSSL backends policy even
**    though the mechanism is necessarily different. Deliberately NOT using
**    SCH_CRED_MANUAL_CRED_VALIDATION (a credential-level flag), that would
**    disable validation for every connection sharing the thread-scoped
**    credential, rather than per-connection the way trust_without_validation 
**    is meant to work.
*/


static void
smtp_tls_assert_fail(
  const char* expr,
  const char* file,
        int   line)
{
  fprintf(stderr, 
          "smtp_tls_schannel: internal assertion failed: %s (%s:%d)\n",
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
  SMTP_TLS_ERR_HANDSHAKE_FAILED,
  SMTP_TLS_ERR_PROTOCOL_ERROR,
  SMTP_TLS_ERR_COUNT
} smtp_tls_err;

static const char *const g_smtp_tls_err_strings[SMTP_TLS_ERR_COUNT] = {
    [SMTP_TLS_ERR_OK]                = "no error",
    [SMTP_TLS_ERR_INVALID_ARG]       = "invalid argument",
    [SMTP_TLS_ERR_ALLOC_FAILED]      = "allocation failed",
    [SMTP_TLS_ERR_CTX_CREATE_FAILED] = "AcquireCredentialsHandle failed",
    [SMTP_TLS_ERR_HANDSHAKE_FAILED]  = "TLS handshake failed",
    [SMTP_TLS_ERR_PROTOCOL_ERROR]    = "TLS protocol error",
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
  CredHandle cred_handle;
};


/* Generous bound for one TLS record on the wire (16384-byte plaintext
** max per RFC 8446, plus header/MAC/padding overhead), comfortable
** margin, not a tight fit. A peer that cannot complete a record
** within this bound is treated as a protocol error, not silently
** handled by growing the buffer. 
*/
#define SMTP_TLS_ACCUM_SIZE 18432


struct smtp_tls {
  CredHandle* cred_handle;
  CtxtHandle  ctxt_handle;
  int         ctxt_handle_valid;
  int         handshake_done;
  int         trust_without_validation;

  char  hostname[256];
  WCHAR hostname_w[256];

  smtp_tls_cert_info cert_info;

  /* Accumulates raw input across calls until a complete TLS record
  ** is available. Shared between the handshake and decrypt paths, since they
  ** are never active at the same time for one connection. */
  unsigned char accum[SMTP_TLS_ACCUM_SIZE];
  size_t        accum_len;

  SecPkgContext_StreamSizes stream_sizes;
  int                       stream_sizes_valid;
}


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

  SCHANNEL_CRED cred;
  memset(&cred, 0, sizeof(cred));
  cred.dwVersion = SCHANNEL_CRED_VERSION;
  /* Floor at TLSv1.2, matching OpenSSL backend's own default. Both client
  ** protocol bits requested. The servers own response during negotiation 
  ** determines the actual version used. */
  cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;
  /* NO_DEFAULT_CREDS: we present no client certificate, this tool
  **  authenticates via SMTP AUTH, not TLS client certs.
  ** USE_STRONG_CRYPTO: disallow known weak cipher suites within the
  **  negotiated protocol versions. Deliberately NOT setting
  **  SCH_CRED_MANUAL_CRED_VALIDATION here. See file header comment on why
  **  that must stay a per-call, per-connection flag 
  **  (ISC_REQ_MANUAL_CRED_VALIDATION) instead. */
  cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;

  TimeStamp expiry;
  SECURITY_STATUS status = AcquireCredentialsHandleW(
    NULL,
    (SEC_WCHAR*)UNISP_NAME_W,
    SECPKG_CRED_OUTBOUND,
    NULL, &cred, NULL, NULL,
    &ctx->cred_handle, &expiry);

  if (status != SEC_E_OK) {
    free(ctx);
    smtp_tls_fail(SMTP_TLS_ERR_CTX_CREATE_FAILED);
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
  FreeCredentialsHandle(&ctx->cred_handle);
  free(ctx);
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

  int wlen = MultiByteToWideChar( 
    CP_UTF8, 
    0, 
    tls->hostname, 
    -1, 
    tls->hostname_w, 
    (int)(sizeof(tls->hostname_w) / sizeof(WCHAR)));

  if (wlen == 0) {
    free(tls);
    smtp_tls_fail(SMTP_TLS_ERR_INVALID_ARG);
    return NULL;
  }

  tls->cred_handle = &ctx->cred_handle;
  tls->trust_without_validation = trust_without_validation;
  /* optimistic default, same convention as the OpenSSL backend */
  tls->cert_info.validated = 1; 

  SecInvalidateHandle(&tls->ctxt_handle);

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

  if (tls->ctxt_handle_valid) {
    DeleteSecurityContext(&tls->ctxt_handle);
  }
  free(tls);
}


const smtp_tls_cert_info*
smtp_tls_get_cert_info(
  const smtp_tls* tls)
{
  SMTP_TLS_ASSERT(tls != NULL);
  return &tls->cert_info;  
}


/*
** Populates cert_info after a successful handshake. In strict mode, SChannels
** own automatic validation already ran (we would not have reached SEC_E_OK 
** otherwise), so reaching here means it already passed. Nothing further to
** check. In trust mode, SChannel skipped that check on request, so this
** manually performs the same chain-and-hostname validation purely to capture
** and log why it would have failed. 
** The result never aborts the connection here.
*/
static void
smtp_tls_populate_cert_info(
  smtp_tls* tls)
{
  PCCERT_CONTEXT cert = NULL;
  SECURITY_STATUS qstatus = QueryContextAttributesW(
    &tls->ctxt_handle, 
    SECPKG_ATTR_REMOTE_CERT_CONTEXT, 
    &cert);

  if (qstatus != SEC_E_OK || cert == NULL) {
    return; /* Nothing to report - cert_info stays at its default */
  }

  CertGetNameStringA( cert, 
                      CERT_NAME_SIMPLE_DISPLAY_TYPE, 
                      0, 
                      NULL,
                      tls->cert_info.subject, 
                      (DWORD)sizeof(tls->cert_info.subject));
  CertGetNameStringA( cert, 
                      CERT_NAME_SIMPLE_DISPLAY_TYPE, 
                      CERT_NAME_ISSUER_FLAG, 
                      NULL,
                      tls->cert_info.issuer, 
                      (DWORD)sizeof(tls->cert_info.issuer));

  /* FILETIME (100ns intervals since 1601-01-01) -> Unix timestamp
  ** (seconds since 1970-01-01). 11644473600 is the standard,
  ** documented offset between those two epochs. */
  ULARGE_INTEGER ft;
  ft.LowPart = cert->pCertInfo->NotAfter.dwLowDateTime;
  ft.HighPart = cert->pCertInfo->NotAfter.dwHighDateTime;
  tls->cert_info.not_after = (long)((ft.QuadPart / 10000000ULL) 
    - 11644473600ULL);

  if (!tls->trust_without_validation) {
    tls->cert_info.validated = 1;
    CertFreeCertificateContext(cert);
    return;
  }

  CERT_CHAIN_PARA chain_para;
  memset(&chain_para, 0, sizeof(chain_para));
  chain_para.cbSize = sizeof(chain_para);

  PCCERT_CHAIN_CONTEXT chain = NULL;
  BOOL got_chain = CertGetCertificateChain(
    NULL, 
    cert, 
    NULL, 
    cert->hCertStore, 
    &chain_para, 
    CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, 
    NULL, 
    &chain);

  if (!got_chain) {
    tls->cert_info.validated = 0;
    smtp_tls_copy_bounded("failed to build certificate chain", 
                          tls->cert_info.failure_reason, 
                          sizeof(tls->cert_info.failure_reason));
    CertFreeCertificateContext(cert);
    return;
  }

  HTTPSPolicyCallbackData https_policy;
  memset(&https_policy, 0, sizeof(https_policy));
  https_policy.cbStruct       = sizeof(https_policy);
  https_policy.dwAuthType     = AUTHTYPE_SERVER;
  https_policy.pwszServerName = tls->hostname_w;

  CERT_CHAIN_POLICY_PARA policy_para;
  memset(&policy_para, 0, sizeof(policy_para));
  policy_para.cbSize = sizeof(policy_para);
  policy_para.pvExtraPolicyPara = &https_policy;

  CERT_CHAIN_POLICY_STATUS policy_status;
  memset(&policy_status, 0, sizeof(policy_status));
  policy_status.cbSize = sizeof(policy_status);

  BOOL verified = CertVerifyCertificateChainPolicy(
    CERT_CHAIN_POLICY_SSL,
    chain,
    &policy_para,
    &policy_status);

  if (verified && policy_status.dwError == 0) {
    tls->cert_info.validated = 1;
  }
  else {
    tls->cert_info.validated = 0;
    char buf[SMTP_TLS_CERT_REASON_LEN];
    DWORD n = FormatMessageA(
      FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL,
      policy_status.dwError,
      0, 
      buf, 
      (DWORD)sizeof(buf), 
      NULL);
    if (n == 0) {
      snprintf( buf, 
                sizeof(buf), 
                "certificate validation failed (0x%lx)", 
                (unsigned long)policy_status.dwError);
    }
    smtp_tls_copy_bounded(buf, 
                          tls->cert_info.failure_reason, 
                          sizeof(tls->cert_info.failure_reason));
  }
  CertFreeCertificateChain(chain);
  CertFreeCertificateContext(cert);
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

  if (in_len > 0) {
    if (tls->accum_len + in_len > sizeof(tls->accum)) {
      smtp_tls_fail(SMTP_TLS_ERR_HANDSHAKE_FAILED);
      return SMTP_TLS_ERROR;
    }
    memcpy(tls->accum + tls->accum_len, in_data, in_len);
    tls->accum_len += in_len;
  }

  SecBuffer in_buffers[2];
  in_buffers[0].BufferType = SECBUFFER_TOKEN;
  in_buffers[0].pvBuffer   = tls->accum_len > 0 ? tls->accum : NULL;
  in_buffers[0].cbBuffer   = (unsigned long)tls->accum_len;
  in_buffers[1].BufferType = SECBUFFER_EMPTY;
  in_buffers[1].pvBuffer   = NULL;
  in_buffers[1].cbBuffer   = 0;

  SecBufferDesc in_desc;
  in_desc.ulVersion = SECBUFFER_VERSION;
  in_desc.cBuffers  = 2;
  in_desc.pBuffers  = in_buffers;

  SecBuffer out_buffers[1];
  out_buffers[0].BufferType = SECBUFFER_TOKEN;
  out_buffers[0].pvBuffer   = NULL;
  out_buffers[0].cbBuffer   = 0;

  SecBufferDesc out_desc;
  out_desc.ulVersion = SECBUFFER_VERSION;
  out_desc.cBuffers  = 1;
  out_desc.pBuffers  = out_buffers;

  unsigned long req_flags = ISC_REQ_SEQUENCE_DETECT 
                          | ISC_REQ_REPLAY_DETECT 
                          | ISC_REQ_CONFIDENTIALITY 
                          | ISC_REQ_ALLOCATE_MEMORY 
                          | ISC_REQ_STREAM;

  if (tls->trust_without_validation) {
    req_flags |= ISC_REQ_MANUAL_CRED_VALIDATION;
  }

  int first_call = !tls->ctxt_handle_valid;
  unsigned long out_flags = 0;

  SECURITY_STATUS status = InitializeSecurityContextW(
    tls->cred_handle,
    first_call ? NULL : &tls->ctxt_handle,
    tls->hostname_w,
    req_flags, 
    0, 
    0,
    first_call ? NULL : &in_desc,
    0,
    first_call ? &tls->ctxt_handle : NULL,
    &out_desc,
    &out_flags,
    NULL);

  if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED) {
    tls->ctxt_handle_valid = 1;
  }  

  /* Track how much of what we fed in was actually consumed.
  ** SECBUFFER_EXTRA on the way out means SChannel saw trailing bytes belonging
  ** to a message beyond this one, keep those for the next call; otherwise,
  ** unless we're waiting on more input entirely, everything we supplied
  ** was consumed. */
  if (in_buffers[1].BufferType == SECBUFFER_EXTRA) {
    size_t extra = in_buffers[1].cbBuffer;
    size_t consumed = tls->accum_len - extra;
    memmove(tls->accum, tls->accum + consumed, extra);
    tls->accum_len = extra;
  }
  else if (status != SEC_E_INCOMPLETE_MESSAGE) {
    tls->accum_len = 0;
  }

  /* On SEC_E_INCOMPLETE_MESSAGE, accum_len is deliberately left untouched.
  ** Keep what we have and wait for more... */

  /* Output always takes priority regardless of status. Same rule as the 
  ** OpenSSL backend: the caller must send it before calling again either way. */
  if (out_buffers[0].cbBuffer > 0 && out_buffers[0].pvBuffer != NULL) {
    size_t n = out_buffers[0].cbBuffer;
    if (n > out_buf_size) {
      FreeContextBuffer(out_buffers[0].pvBuffer);
      smtp_tls_fail(SMTP_TLS_ERR_HANDSHAKE_FAILED);
      return SMTP_TLS_ERROR;
    }
    memcpy(out_buf, out_buffers[0].pvBuffer, n);
    FreeContextBuffer(out_buffers[0].pvBuffer);
    *out_len = n;
    return SMTP_TLS_WANT_WRITE;
  }

  if (status == SEC_E_OK) {
    tls->handshake_done = 1;
    smtp_tls_populate_cert_info(tls);
    return SMTP_TLS_OK;
  }

  if (status == SEC_I_CONTINUE_NEEDED || status == SEC_E_INCOMPLETE_MESSAGE) {
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
        size_t    out_len)
{
  SMTP_TLS_ASSERT(tls != NULL);
  SMTP_TLS_ASSERT(tls->handshake_done);
  SMTP_TLS_ASSERT(out_buf != NULL);
  SMTP_TLS_ASSERT(out_len != NULL);

  *out_len = 0;

  if (!tls->stream_sizes_valid) {
    SECURITY_STATUS qs = QueryContextAttributesW(
      &tls->ctxt_handle,
      SECPKG_ATTR_STREAM_SIZES, 
      &tls->stream_sizes);    
    if (qs != SEC_E_OK) {
      smtp_tls_fail(SMTP_TLS_ERROR_PROTOCOL_ERROR);
      return SMTP_TLS_ERROR;
    }
    tls->stream_sizes_valid = 1;
  }

  size_t needed = tls->stream_sizes.cbHeader 
                + plaintext_len 
                + tls->stream_sizes.cbTrailer;
  if (needed > out_buf_size) {
    /* Callers buffer is too small for this much plaintext in one call.
    ** Reported explicitly rather than silently truncated or split.
    ** Callers are expected to size write buffers against cbMaximumMessage
    ** sized chunks in practice. */
    smtp_tls_fail(SMTP_TLS_ERR_INVALID_ARG);
    return SMTP_TLS_ERROR;
  }

  unsigned char* buf = (unsigned char*)out_buf;
  memcpy(buf + tls->stream_sizes.cbHeader, plaintext, plaintext_len);

  SecBuffer buffers[4];
  buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
  buffers[0].pvBuffer   = buf;
  buffers[0].cbBuffer   = tls->stream_sizes.cbHeader;
  buffers[1].BufferType = SECBUFFER_DATA;
  buffers[1].pvBuffer   = buf + tls->stream_sizes.cbHeader;
  buffers[1].cbBuffer   = (unsigned long)plaintext_len;
  buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
  buffers[2].pvBuffer   = buf + tls->stream_sizes.cbHeader + plaintext_len;
  buffers[2].cbBuffer   = tls->stream_sizes.cbTrailer;
  buffers[3].BufferType = SECBUFFER_EMPTY;
  buffers[3].pvBuffer   = NULL;
  buffers[3].cbBuffer   = 0;

  SecBufferDesc desc;
  desc.ulVersion = SECBUFFER_VERSION;
  desc.cBuffers  = 4;
  desc.pBuffers  = buffers;

  SECURITY_STATUS status = EncryptMessage(&tls->ctxt_handle, 0, &desc, 0);
  if (status != SEC_E_OK) {
    smtp_tls_fail(SMTP_TLS_ERR_PROTOCOL_ERROR);
    return SMTP_TLS_ERROR;
  }

  *out_len = buffers[0].cbBuffer 
            + buffers[1].cbBuffer 
            + buffers[2].cbBuffer;            
  return SMTP_TLS_WANT_WRITE;
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

  if (in_len > 0) {
    if (tls->accum_len + in_len > sizeof(tls->accum)) {
      smtp_tls_fail(SMTP_TLS_ERR_PROTOCOL_ERROR);
      return SMTP_TLS_ERROR;
    }
    memcpy(tls->accum + tls->accum_len, in_data, in_len);
    tls->accum_len += in_len;
  }

  SecBuffer buffers[4];
  buffers[0].BufferType = SECBUFFER_DATA;
  buffers[0].pvBuffer   = tls->accum;
  buffers[0].cbBuffer   = (unsigned long)tls->accum_len;
  buffers[1].BufferType = SECBUFFER_EMPTY;
  buffers[1].pvBuffer   = NULL;
  buffers[1].cbBuffer   = 0;
  buffers[2].BufferType = SECBUFFER_EMPTY;
  buffers[2].pvBuffer   = NULL;
  buffers[2].cbBuffer   = 0;
  buffers[3].BufferType = SECBUFFER_EMPTY;
  buffers[3].pvBuffer   = NULL;
  buffers[3].cbBuffer   = 0;

  SecBufferDesc desc;
  desc.ulVersion = SECBUFFER_VERSION;
  desc.cBuffers  = 4;
  desc.pBuffers  = buffers;

  SECURITY_STATUS status = DecryptMessage(&tls->ctxt_handle, &desc, 0, NULL);

  if (status == SEC_E_INCOMPLETE_MESSAGE) {
    return SMTP_TLS_WANT_READ; /* accum_len left untouched, wait for more */
  }

  if (status == SEC_I_CONTEXT_EXPIRED) {
    /* Peer sent close_notify, a successful zero-byte read, not an error at
    ** at this layer, mirroring the OpenSSL backends 
    ** treatment of SSL_ERROR_ZERO_RETURN. */
    tls->accum_len = 0;
    return SMTP_TLS_OK;
  }

  if (status != SEC_E_OK && status != SEC_I_RENEGOTIATE) {
    smtp_tls_fail(SMTP_TLS_ERR_PROTOCOL_ERROR);
    return SMTP_TLS_ERROR;
  }

  size_t plaintext_len = 0;
  const unsigned char* plaintext_ptr = NULL;
  
  size_t extra_len = 0;
  const unsigned char* extra_ptr = NULL;

  for (int i = 0; i < 4; i++) {
    if (buffers[i].BufferType == SECBUFFER_DATA) {
      plaintext_ptr = (const unsigned char*)buffers[i].pvBuffer;
      plaintext_len = buffers[i].cbBuffer;
    }
    else if (buffers[i].BufferType == SECBUFFER_EXTRA) {
      extra_ptr = (const unsigned char*)buffers[i].pvBuffer;
      extra_len = buffers[i].cbBuffer;
    }
  }

  if (plaintext_len > out_buf_size) {
    smtp_tls_fail(SMTP_TLS_ERR_PROTOCOL_ERROR);
    return SMTP_TLS_ERROR;
  }

  if (plaintext_len > 0 && plaintext_ptr != NULL) {
    memcpy(out_buf, plaintext_ptr, plaintext_len);
  }

  /* Shift any leftover bytes (the start of a subsequent record) to the front
  ** of the accumulation buffer for the next call. */
  if (extra_len > 0 && extra_ptr != NULL) {
    memmove(tls->accum, extra_ptr, extra_len);
  }
  tls->accum_len = extra_len;

  *out_len = plaintext_len;
  return SMTP_TLS_OK;
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
    return SMTP_TLS_OK;
  }

  DWORD shutdown_type = SCHANNEL_SHUTDOWN;
  SecBuffer token_buffer;
  token_buffer.BufferType = SECBUFFER_TOKEN;
  token_buffer.pvBuffer   = &shutdown_type;
  token_buffer.cbBuffer   = sizeof(shutdown_type);

  SecBufferDesc token_desc;
  token_desc.ulVersion = SECBUFFER_VERSION;
  token_desc.cBuffers  = 1;
  token_desc.pBuffers  = &token_buffer;

  if (ApplyControlToken(&tls->ctxt_handle, &token_desc) != SEC_E_OK) {
    return SMTP_TLS_OK; /* best effort - nothing further we can do */
  }

  SecBuffer out_buffers[1];
  out_buffers[0].BufferType = SECBUFFER_TOKEN;
  out_buffers[0].pvBuffer   = NULL;
  out_buffers[0].cbBuffer   = 0;

  SecBufferDesc out_desc;
  out_desc.ulVersion = SECBUFFER_VERSION;
  out_desc.cBuffers  = 1;
  out_desc.pBuffers  = out_buffers;

  unsigned long req_flags = ISC_REQ_SEQUENCE_DETECT 
                          | ISC_REQ_REPLAY_DETECT 
                          | ISC_REQ_CONFIDENTIALITY 
                          | ISC_REQ_ALLOCATE_MEMORY 
                          | ISC_REQ_STREAM;                          
  unsigned long out_flags = 0;

  SECURITY_STATUS status = InitializeSecurityContextW(
    tls->cred_handle, 
    &tls->ctxt_handle,
    tls->hostname_w,
    req_flags,
    0, 
    0,
    NULL, 
    0,
    NULL,
    &out_desc,
    &out_flags,
    NULL);

  if ((status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED)
    && out_buffers[0].cbBuffer > 0 
    && out_buffers[0].pvBuffer != NULL) 
  {
    size_t n = out_buffers[0].cbBuffer;
    if (n <= out_buf_size) {
      memcpy(out_buf, out_buffers[0].pvBuffer, n);
      *out_len = n;
    }
    FreeContextBuffer(out_buffers[0].pvBuffer);
    if (*out_len > 0) {
      return SMTP_TLS_WANT_WRITE;
    }
  }
  return SMTP_TLS_OK;
}

#endif /* _WIN32 */
