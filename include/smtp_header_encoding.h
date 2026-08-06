#ifndef SMTP_HEADER_ENCODING_H
#define SMTP_HEADER_ENCODING_H

#include <stddef.h>

/*
 * RFC 2047 "encoded-word" validator.
 *
 *   encoded-word = "=?" charset "?" encoding "?" encoded-text "?="
 *
 *   charset      = token (RFC 2045 Sec 5.1)
 *   encoding     = "Q" / "q" / "B" / "b"
 *   encoded-text = 1*<printable US-ASCII, excluding '?' and SPACE>,
 *                  further constrained by the Q/B encoding rules below.
 *
 * Validates a single encoded-word token, e.g. as found embedded in a
 * Subject/From/To header value. Does NOT scan a whole header line or
 * handle folding whitespace between adjacent encoded-words - that is a
 * separate, higher-level component.
 *
 * Length: the whole encoded-word must not exceed 75 octets
 * (RFC 2047 Sec 2).
 */
 
#define SMTP_HDR_ENCODED_WORD_MAX_LEN 75


typedef enum {
    SMTP_HDR_OK = 0,
    SMTP_HDR_ERR_EMPTY,
    SMTP_HDR_ERR_TOO_LONG,
    SMTP_HDR_ERR_MISSING_OPEN_DELIM,     /* doesn't start with "=?"    */
    SMTP_HDR_ERR_CHARSET_EMPTY,
    SMTP_HDR_ERR_CHARSET_INVALID_CHAR,
    SMTP_HDR_ERR_MISSING_CHARSET_DELIM,  /* no '?' terminating charset */
    SMTP_HDR_ERR_ENCODING_INVALID,       /* not exactly one of Q/q/B/b */
    SMTP_HDR_ERR_MISSING_ENCODING_DELIM, /* no '?' terminating encoding */
    SMTP_HDR_ERR_MISSING_CLOSE_DELIM,    /* doesn't end with "?="      */
    SMTP_HDR_ERR_TEXT_EMPTY,
    SMTP_HDR_ERR_TEXT_INVALID_CHAR,
    SMTP_HDR_ERR_Q_BAD_HEX_ESCAPE,       /* '=' not followed by 2 hex  */
    SMTP_HDR_ERR_B_INVALID_CHAR,         /* char outside base64 alphabet */
    SMTP_HDR_ERR_B_BAD_LENGTH,           /* encoded-text not a multiple of 4 */
    SMTP_HDR_ERR_B_BAD_PADDING,          /* '=' padding not confined to the end */
    SMTP_HDR_ERR_COUNT /* sentinel - also bounds the string table */
} smtp_hdr_err;


/*
 * Validates word (need not be NUL-terminated; len is authoritative).
 * Returns 0 (SMTP_HDR_OK) on success, non-zero smtp_hdr_err on failure.
 *
 * GetLastError-style reporting, same semantics as the address validator:
 * valid only until the next call to smtp_hdr_validate_encoded_word() on
 * this thread.
 */
int smtp_hdr_validate_encoded_word(const char *word, size_t len);

const char* smtp_hdr_validate_get_last_error(void);
size_t      smtp_hdr_validate_get_last_error_offset(void);
const char* smtp_hdr_validate_get_last_error_detailed(char *buf, size_t buflen);


#endif /* SMTP_HEADER_ENCODING_H */
