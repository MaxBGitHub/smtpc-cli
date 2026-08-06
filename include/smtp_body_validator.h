#ifndef SMTP_BODY_VALIDATOR_H
#define SMTP_BODY_VALIDATOR_H

#include <stddef.h>

/*
** SMTP DATA content ("body") validator.
**
** Validates wire-ready message content - i.e. content the caller
** intends to send after "DATA" / 354, already dot-stuffed - against
** the structural rules that keep the DATA transaction mechanically
** correct (RFC 5321 Sec 4.5.2 dot-stuffing, Sec 4.5.3.1 line length).
**
** Does NOT perform dot-stuffing itself (that's an encoder, a separate
** concern) and does NOT interpret MIME structure.
**
** allow_8bit gates whether bytes >= 0x80 are permitted. Pass 0 for a
** strict 7-bit-clean check (no 8BITMIME negotiated with the target),
** or 1 once 8BITMIME (RFC 6152) has been negotiated. Note 8BITMIME
** only lifts the 7-bit ceiling - it does not relax control-character
** discipline, so C0 controls other than TAB/CR/LF are rejected either
** way.
*/

#define SMTP_BODY_MAX_LINE_LEN 998 /* RFC 5321 Sec 4.5.3.1 hard limit */

typedef enum {
  SMTP_BODY_OK = 0,
  SMTP_BODY_ERR_EMPTY,
  SMTP_BODY_ERR_BARE_CR,
  SMTP_BODY_ERR_BARE_LF,
  SMTP_BODY_ERR_LINE_TOO_LONG,
  SMTP_BODY_ERR_PREMATURE_TERMINATOR, /* a line is exactly "." */
  SMTP_BODY_ERR_CONTROL_CHAR,
  SMTP_BODY_ERR_8BIT_NOT_ALLOWED,
  SMTP_BODY_ERR_COUNT
} smtp_body_err;


/*
** Validates body (no need to be NUL-terminated, len is authoritative).
** Returns 0 (SMTP_BODY_OK) on success, non-zero smtp_body_err on
** failure. GetLastError-style reporting.
*/
int 
smtp_body_validate(
  const char*   body, 
        size_t  len, 
        int     allow_8bit
);

const char* smtp_body_validate_get_last_error(void);
size_t smtp_body_validate_get_last_error_offset(void);

const char* 
smtp_body_validate_get_last_error_detailed(
  char*   buf, 
  size_t  len
);


#endif /* SMTP_BODY_VALIDATOR_H */
