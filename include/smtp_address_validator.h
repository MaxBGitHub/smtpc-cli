#ifndef SMTP_ADDRESS_VALIDATOR_H
#define SMTP_ADDRESS_VALIDATOR_H

#include <stddef.h>

/*
** RFC 5321 (SMTP) Mailbox / envelope address validator.
**
** Validates against RFC 5321 Sec 4.1.2 grammar, NOT the looser RFC 5322
** header address grammar. Covers:
**   - Dot-string local-part      (john.doe)
**   - Quoted-string local-part   ("john doe", with backslash escapes)
**   - Domain                     (dot-separated labels, DNS label rules)
**   - Address literal            ([192.168.1.1], [IPv6:2001:db8::1])
**
** Length limits enforced (RFC 5321 Sec 4.5.3.1):
**   - Local-part   <= 64 octets
**   - Domain label <= 63 octets
**   - Domain       <= 255 octets
**   - Full address <= 256 octets
**
** MIME / header encoding (RFC 2047) is out of scope here.
*/


typedef enum {
    SMTP_ADDR_OK = 0,
    SMTP_ADDR_ERR_EMPTY,
    SMTP_ADDR_ERR_LOCAL_EMPTY,
    SMTP_ADDR_ERR_LOCAL_INVALID_CHAR,
    SMTP_ADDR_ERR_LOCAL_TOO_LONG,
    SMTP_ADDR_ERR_LOCAL_LEADING_DOT,
    SMTP_ADDR_ERR_LOCAL_TRAILING_DOT,
    SMTP_ADDR_ERR_LOCAL_CONSECUTIVE_DOTS,
    SMTP_ADDR_ERR_LOCAL_UNTERMINATED_QUOTE,
    SMTP_ADDR_ERR_LOCAL_BAD_ESCAPE,
    SMTP_ADDR_ERR_LOCAL_BAD_QUOTED_CHAR,
    SMTP_ADDR_ERR_MISSING_AT,
    SMTP_ADDR_ERR_MULTIPLE_AT,
    SMTP_ADDR_ERR_DOMAIN_EMPTY,
    SMTP_ADDR_ERR_DOMAIN_INVALID_CHAR,
    SMTP_ADDR_ERR_DOMAIN_LABEL_EMPTY,
    SMTP_ADDR_ERR_DOMAIN_LABEL_TOO_LONG,
    SMTP_ADDR_ERR_DOMAIN_TOO_LONG,
    SMTP_ADDR_ERR_DOMAIN_LEADING_HYPHEN,
    SMTP_ADDR_ERR_DOMAIN_TRAILING_HYPHEN,
    SMTP_ADDR_ERR_DOMAIN_LITERAL_EMPTY,
    SMTP_ADDR_ERR_DOMAIN_LITERAL_UNTERMINATED,
    SMTP_ADDR_ERR_DOMAIN_LITERAL_INVALID,
    SMTP_ADDR_ERR_TOTAL_TOO_LONG,
    SMTP_ADDR_ERR_COUNT /* counter */
} smtp_addr_err;


/*
** Validates addr (must not be NUL-terminated, len is authoritative).
** Returns 0 (SMTP_ADDR_OK) on success, non-zero smtp_addr_err on failure.
**
** On failure, error detail is stashed thread locally and can be read
** with smtp_validate_get_last_error() / _offset() / _detailed(), same
** semantics as Win32 GetLastError(): valid only until the next call to
** smtp_validate_address() on this thread.
*/
int 
smtp_address_validate(
  const char*   addr, 
        size_t  len
);
 
/* 
** Static, allocation-free string for the last error on this thread. 
*/
const char*
smtp_address_validate_get_last_error(void);
 
/* 
** Byte offset into the input where validation failed. 
*/
size_t smtp_address_validate_get_last_error_offset(void);
 
/*
** Formats "<message> at offset <N>" into caller-owned buf.
** Returns buf. Truncates safely if buflen is too small.
*/
const char*
smtp_address_validate_get_last_error_detailed(
  char*   buf, 
  size_t  len
);


#endif /* SMTP_ADDRESS_VALIDATOR_H */
