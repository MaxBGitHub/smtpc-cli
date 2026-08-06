#ifndef SMTP_HEADER_VALUE_H
#define SMTP_HEADER_VALUE_H
 
#include <stddef.h>

/*
 * RFC 5322 header-value scanner: validates the "unstructured" field
 * value (the bytes after "Name:"), covering:
 *
 *   - folding whitespace (FWS): a CRLF inside the value is only valid
 *     immediately followed by WSP (fold continuation), or as the very
 *     last two bytes of the value (terminating CRLF). Any other CR/LF
 *     placement is a bare/unfolded line break and rejected.
 *   - control characters other than TAB/CR/LF are rejected outright.
 *   - each physical line (between folds) must not exceed 998 octets
 *     (RFC 5322 Sec 2.1.1 hard limit).
 *   - RFC 2047 encoded-word spans ("=?charset?enc?text?=") embedded in
 *     the value are located structurally and validated via
 *     smtp_hdr_validate_encoded_word() from smtp_header_encoding.h.
 *     A leading "=?" that doesn't structurally resolve into a full
 *     candidate is treated as ordinary text (RFC 5322 unstructured
 *     text permits '=' and '?' as plain characters) - only a fully-
 *     shaped but content-invalid encoded-word is an error.
 *
 * Does NOT decode encoded-words or interpret charset content - purely
 * a syntax validator, same scope boundary as the address validator.
*/

#define SMTP_HDRVAL_MAX_LINE_LEN 998 /* RFC 5322 Sec 2.1.1 hard limit */

typedef enum {
  SMTP_HDRVAL_OK = 0,
  SMTP_HDRVAL_ERR_EMPTY,
  SMTP_HDRVAL_ERR_CONTROL_CHAR,         /* Disallowed control char       */
  SMTP_HDRVAL_ERR_BARE_CR,              /* CR not followed by LF         */
  SMTP_HDRVAL_ERR_BARE_LF,              /* LF not preceded by CR         */
  SMTP_HDRVAL_ERR_FOLD_NOT_WSP,         /* CRLF not followed by WSP/end  */
  SMTP_HDRVAL_ERR_LINE_TOO_LONG,        /* Physical line exceeds 998     */
  SMTP_HDRVAL_ERR_ENCODED_WORD_INVALID, /* Shaped like one, failed 2047  */
  SMTP_HDRVAL_ERR_COUNT
} smtp_hdrval_err;


/*
 * Validates value (no need to be NUL-terminated, len is authoritative).
 * Returns 0 (SMTP_HDRVAL_OK) on success, non-zero smtp_hdrval_err on
 * failure. GetLastError-style reporting.
 */
int 
smtp_hdrval_validate(
  const char*   value, 
        size_t  len
);
 
const char* smtp_hdrval_get_last_error(void);
size_t smtp_hdrval_get_last_error_offset(void);

const char* 
smtp_hdrval_get_last_error_detailed(
  char*   buf, 
  size_t  len
);


#endif /* SMTP_HEADER_VALUE_H */
