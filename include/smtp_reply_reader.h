#ifndef SMTP_REPLY_READER_H
#define SMTP_REPLY_READER_H

#include <stddef.h>

/*
** Accumulates a full (possibly multi-line) SMTP reply from a buffer,
** built on smtp_reply_parse_line(). Most real replies - EHLO in
** particular - are multi-line: several "NNN-text" continuation lines
** followed by a final "NNN text" (or "NNN") line, all sharing the same
** code.
**
** Operates on caller-supplied buffers only - no sockets, no I/O.
*/
 
typedef enum {
  SMTP_REPLY_READ_OK = 0,
  SMTP_REPLY_READ_INCOMPLETE,          /* Buffer doesn't yet hold the full reply                */
  SMTP_REPLY_READ_ERR_LINE,            /* A line failed - see smtp_reply_line_get_last_error()  */
  SMTP_REPLY_READ_ERR_CODE_MISMATCH,   /* Continuation line's code != first line's              */
  SMTP_REPLY_READ_ERR_TOO_MANY_LINES,  /* Exceeded the caller-supplied max_lines bound          */
  SMTP_REPLY_READ_ERR_COUNT
} smtp_reply_read_err;
 
typedef struct {
  int     code;       /* The reply's code (shared by every line)  */
  size_t  consumed;   /* Total bytes consumed across all lines    */
  size_t  line_count;
} smtp_reply;
 
/*
 * Reads a complete reply from buf[0..len). max_lines bounds how many
 * continuation lines are scanned before giving up with
 * SMTP_REPLY_READ_ERR_TOO_MANY_LINES, always pass a finite bound;
 * there is no "unlimited" option by design (a server sending endless
 * continuation lines with no final line must not hang the reader).
 *
 * Returns 0 (SMTP_REPLY_READ_OK) with *out filled on success.
 * SMTP_REPLY_READ_INCOMPLETE means read more bytes and retry from the
 * same buffer start.
 */
int 
smtp_reply_read(
  const char*       buf, 
        size_t      len, 
        size_t      max_lines, 
        smtp_reply* reply);
 
const char* smtp_reply_read_get_last_error(void);


#endif /* SMTP_REPLY_READER_H */
