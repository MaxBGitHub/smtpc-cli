#include "../include/smtp_reply_parser.h"

#include <stdio.h>
#include <stdlib.h>


#if defined(_MSC_VER)
  #define SMTP_REPLY_THREAD_LOCAL __declspec(thread)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
  #define SMTP_REPLY_THREAD_LOCAL _Thread_local
#else
  #define SMTP_REPLY_THREAD_LOCAL __thread
#endif


static void 
smtp_reply_assert_fail(
  const char* expr, 
  const char* file, 
        int   line)
{
  fprintf(stderr,
          "smtp_reply_parser: internal assertion failed: %s (%s:%d)\n",
          expr, file, line);
  abort();
}


#define SMTP_REPLY_ASSERT(cond) \
  do { \
    if (!(cond)) { \
        smtp_reply_assert_fail(#cond, __FILE__, __LINE__); \
    } \
  } while (0)


#define ASCII_TAB            9
#define ASCII_SPACE          32
#define ASCII_PRINTABLE_MIN  33
#define ASCII_PRINTABLE_MAX  126


static int
smtp_reply_parser_is_text_char(unsigned char c)
{
  return (c == ASCII_TAB)
      || (c == ASCII_SPACE)
      || (c >= ASCII_PRINTABLE_MIN && c <= ASCII_PRINTABLE_MAX);
}


static const char *const g_reply_err_strings[SMTP_REPLY_LINE_ERR_COUNT] = {
  [SMTP_REPLY_LINE_OK]              = "no error",
  [SMTP_REPLY_LINE_INCOMPLETE]      = "incomplete line - more data needed",
  [SMTP_REPLY_LINE_ERR_EMPTY]       = "buffer is empty",
  [SMTP_REPLY_LINE_ERR_CODE_DIGIT]  = "reply code digit out of range",
  [SMTP_REPLY_LINE_ERR_SEPARATOR]   = "expected '-', SP, or CRLF after reply code",
  [SMTP_REPLY_LINE_ERR_TEXT_CHAR]   = "invalid character in reply text",
  [SMTP_REPLY_LINE_ERR_BARE_CR]     = "CR not followed by LF",
  [SMTP_REPLY_LINE_ERR_BARE_LF]     = "LF not preceded by CR",
};


static SMTP_REPLY_THREAD_LOCAL smtp_reply_line_err  g_reply_last_err        = SMTP_REPLY_LINE_OK;
static SMTP_REPLY_THREAD_LOCAL size_t               g_reply_last_err_offset = 0;


static smtp_reply_line_err 
smtp_reply_fail(
  smtp_reply_line_err err, 
  size_t              offset)
{
  g_reply_last_err        = err;
  g_reply_last_err_offset = offset;

  return err;
}


/*
** Parses the 3-digit code at buf[0..2]. Requires len >= 3 to make a 
** determination. A shorter buffer is incomplete, not an error, since more
** bytes could still complete a valid code. Any digit actually present and
** out of ABNF range is a hard error immediately.
*/
static smtp_reply_line_err 
smtp_reply_parser_parse_code(
  const char*   buf, 
        size_t  len, 
        int*    code) 
{
  SMTP_REPLY_ASSERT(buf != NULL);
  SMTP_REPLY_ASSERT(code != NULL);

  if (len < 3) {
    return SMTP_REPLY_LINE_INCOMPLETE;
  }

  unsigned char d0 = (unsigned char)buf[0];
  unsigned char d1 = (unsigned char)buf[1];
  unsigned char d2 = (unsigned char)buf[2];

  if (d0 < '2' || d0 > '5') {
    return smtp_reply_fail(SMTP_REPLY_LINE_ERR_CODE_DIGIT, 0);
  }

  if (d1 < '0' || d1 > '5') {
    return smtp_reply_fail(SMTP_REPLY_LINE_ERR_CODE_DIGIT, 1);
  }

  if (d2 < '0' || d2 > '9') {
    return smtp_reply_fail(SMTP_REPLY_LINE_ERR_CODE_DIGIT, 2);
  }

  *code = (d0 - '0') * 100 + (d1 - '0') * 10 + (d2 - '0');
  return SMTP_REPLY_LINE_OK;    
}


/*
** Examines buf[3] to determine continuation ('-') vs 
** final line (SP, or CR meaning 'no text at all'). 
** Requires len >= 4.
*/
static smtp_reply_line_err
smtp_reply_parser_determine_seperator(
  const char*   buf,
        size_t  len,
        int*    is_final,
        size_t* text_start)
{
  SMTP_REPLY_ASSERT(buf != NULL);
  SMTP_REPLY_ASSERT(is_final != NULL);
  SMTP_REPLY_ASSERT(text_start != NULL);

  if (len < 4) {
    return SMTP_REPLY_LINE_INCOMPLETE;
  }

  unsigned char sep = (unsigned char)buf[3];

  if (sep == '-') {
    *is_final = 0;
    *text_start = 4;
    return SMTP_REPLY_LINE_OK;
  }

  if (sep == ' ') {
    *is_final = 1;
    *text_start = 4;
    return SMTP_REPLY_LINE_OK;
  }

  if (sep == '\r') {
    /* 'NNN\r\n' - final line, no text at all. 
    ** text_start == CR itself so text scan step below sees zero text bytes. */
    *is_final = 1;
    *text_start = 3;
    return SMTP_REPLY_LINE_OK;
  }
  return smtp_reply_fail(SMTP_REPLY_LINE_ERR_SEPARATOR, 3);
}


/*
** Scans forward from text_start for text chars, then requires CRLF.
** Incomplete if the buffer runs out before terminating CR is found,
** or right after a CR with no LF byte present.
*/
static smtp_reply_line_err
smtp_reply_parser_scan_text_and_crlf(
  const char*   buf,
        size_t  len,
        size_t  text_start,
        size_t* text_len,
        size_t* consumed)
{
  SMTP_REPLY_ASSERT(buf != NULL);
  SMTP_REPLY_ASSERT(text_len != NULL);
  SMTP_REPLY_ASSERT(consumed != NULL);
  SMTP_REPLY_ASSERT(text_start <= len);

  size_t i = text_start;
  while (i < len && buf[i] != '\r') {
    unsigned char c = (unsigned char)buf[i];

    if (c == '\n') {
      return smtp_reply_fail(SMTP_REPLY_LINE_ERR_BARE_LF, i);
    }

    if (!smtp_reply_parser_is_text_char(c)) {
      return smtp_reply_fail(SMTP_REPLY_LINE_ERR_TEXT_CHAR, i);
    }
    i++;
  }

  if (i >= len) {
    /* No CR found yet. */
    return SMTP_REPLY_LINE_INCOMPLETE;
  }

  /* buf[i] == '\r' here */
  if (i + 1 >= len) {
    return SMTP_REPLY_LINE_INCOMPLETE;
  }

  if (buf[i + 1] != '\n') {
    return smtp_reply_fail(SMTP_REPLY_LINE_ERR_BARE_CR, i);
  }

  *text_len = i - text_start;
  *consumed = i + 2;
  return SMTP_REPLY_LINE_OK;
}


int smtp_reply_parse_line(
  const char*             buf,
        size_t            len, 
        smtp_reply_line*  reply)
{
  SMTP_REPLY_ASSERT(reply != NULL);

  if (buf == NULL) {
    return smtp_reply_fail(SMTP_REPLY_LINE_ERR_EMPTY, 0);
  }

  if (len == 0) {
    /* No bytes yet... not an error */
    return SMTP_REPLY_LINE_INCOMPLETE;
  }

  int code = 0;
  smtp_reply_line_err err = smtp_reply_parser_parse_code(buf, len, &code);
  if (err != SMTP_REPLY_LINE_OK) {
    return (int)err;
  }

  int     is_final    = 0;
  size_t  text_start  = 0;
  err = smtp_reply_parser_determine_seperator(buf, len, &is_final, &text_start);
  if (err != SMTP_REPLY_LINE_OK) {
    return (int)err;
  }

  size_t text_len = 0;
  size_t consumed = 0;
  err = smtp_reply_parser_scan_text_and_crlf(
    buf, len, text_start, &text_len, &consumed);
  if (err != SMTP_REPLY_LINE_OK) {
    return (int)err;
  }

  reply->code         = code;
  reply->is_final     = is_final;
  reply->text_offset  = text_start;
  reply->text_len     = text_len;
  reply->consumed     = consumed;

  return smtp_reply_fail(SMTP_REPLY_LINE_OK, 0);
}


const char*
smtp_reply_line_get_last_error(void)
{
  SMTP_REPLY_ASSERT(g_reply_last_err < SMTP_REPLY_LINE_ERR_COUNT);
  return g_reply_err_strings[g_reply_last_err];
}


size_t
smtp_reply_line_get_last_error_offset(void)
{
  return g_reply_last_err_offset;
}


const char*
smtp_reply_line_get_last_error_detailed(
  char*   buf,
  size_t  len)
{
  if (buf == NULL || len == 0) {
    return buf;
  }

  SMTP_REPLY_ASSERT(g_reply_last_err < SMTP_REPLY_LINE_ERR_COUNT);

  snprintf(buf, len, "%s at offset %zu",
    g_reply_err_strings[g_reply_last_err], g_reply_last_err_offset);

  return buf;
}
