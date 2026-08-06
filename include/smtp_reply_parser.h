#ifndef SMTP_REPLY_PARSER_H
#define SMTP_REPLY_PARSER_H

#include <stddef.h>

/*
** RFC 5321 Sec 4.2 SMTP reply-line parser.
**
**   Reply-code = %x32-35 %x30-35 %x30-39     (digit1: 2-5, digit2: 0-5,
**                                             digit3: 0-9)
**   Reply-line = Reply-code "-" [text] CRLF   ; continuation line
**              / Reply-code [SP text] CRLF    ; final line
**   text       = *(HTAB / %x20-7E)            ; may be empty either way
**
** Operates on caller-supplied buffers only - no sockets, no I/O.
** Designed for incremental/streaming use: a buffer that doesn't yet
** contain a full CRLF-terminated line is reported as "incomplete", not
** an error, so the caller can read more bytes from the wire and retry.
** A genuinely invalid byte at a fixed position (e.g. a non-digit where
** the ABNF requires a digit) is always a hard error immediately,
** regardless of how much more data might follow - more bytes can't fix
** an already-wrong byte.
*/

typedef enum {
  SMTP_REPLY_LINE_OK = 0,
  SMTP_REPLY_LINE_INCOMPLETE,     /* No full line yet (including a
                                  ** zero length buffer) - read more, retry */
  SMTP_REPLY_LINE_ERR_EMPTY,      /* buf is NULL - a real contract error */
  SMTP_REPLY_LINE_ERR_CODE_DIGIT, /* A code digit is out of ABNF range   */
  SMTP_REPLY_LINE_ERR_SEPARATOR,  /* Byte after code isn't '-'/SP/CR     */
  SMTP_REPLY_LINE_ERR_TEXT_CHAR,  /* Char outside HTAB/printable ASCII   */
  SMTP_REPLY_LINE_ERR_BARE_CR,
  SMTP_REPLY_LINE_ERR_BARE_LF,
  SMTP_REPLY_LINE_ERR_COUNT
} smtp_reply_line_err;


typedef struct {
  int     code;        /* Parsed 3-digit reply code, e.g. 250            */
  int     is_final;    /* 1 = SP separator (last line), 0 = '-' (more follow) */
  size_t  text_offset; /* Offset of text portion within the input buffer */
  size_t  text_len;    /* Length of text portion (may be 0)              */
  size_t  consumed;    /* Total bytes consumed for this line, incl. CRLF */
} smtp_reply_line;


/*
** Attempts to parse one reply line starting at buf[0]. len is the
** number of valid bytes currently available.
**
** Returns 0 (SMTP_REPLY_LINE_OK) with *reply filled on success.
** Returns SMTP_REPLY_LINE_INCOMPLETE if buf doesn't yet contain a full
** line - *reply is untouched, nothing was consumed, caller should read
** more and retry with a larger len (same starting buffer position).
** Returns a smtp_reply_line_err on malformed input.
*/
int 
smtp_reply_parse_line(
  const char*             buf, 
        size_t            len, 
        smtp_reply_line*  reply
);

const char *smtp_reply_line_get_last_error(void);
size_t smtp_reply_line_get_last_error_offset(void);

const char* 
smtp_reply_line_get_last_error_detailed(
  char*   buf, 
  size_t  len
);

#endif /* SMTP_REPLY_PARSER_H */
