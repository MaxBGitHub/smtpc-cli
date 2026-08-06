#include "../include/smtp_reply_reader.h"
#include "../include/smtp_reply_parser.h"

#include <stdio.h>
#include <stdlib.h>


#if defined(_MSC_VER)
  #define SMTP_REPLY_READ_THREAD_LOCAL __declspec(thread)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
  #define SMTP_REPLY_READ_THREAD_LOCAL _Thread_local
#else
  #define SMTP_REPLY_READ_THREAD_LOCAL __thread
#endif

 
static void 
smtp_reply_read_assert_fail(
  const char* expr, 
  const char* file, 
        int   line)
{
  fprintf(stderr,
          "smtp_reply_reader: internal assertion failed: %s (%s:%d)\n",
          expr, file, line);
  abort();
}
 
#define SMTP_REPLY_READ_ASSERT(cond) \
  do { \
    if (!(cond)) { \
        smtp_reply_read_assert_fail(#cond, __FILE__, __LINE__); \
    } \
  } while (0)
 
static const char *const g_reply_read_err_strings[SMTP_REPLY_READ_ERR_COUNT] = {
  [SMTP_REPLY_READ_OK]                  = "no error",
  [SMTP_REPLY_READ_INCOMPLETE]          = "incomplete reply - more data needed",
  [SMTP_REPLY_READ_ERR_LINE]            = "malformed line - see smtp_reply_line_get_last_error()",
  [SMTP_REPLY_READ_ERR_CODE_MISMATCH]   = "continuation line's code doesn't match the first line's",
  [SMTP_REPLY_READ_ERR_TOO_MANY_LINES]  = "reply exceeded the maximum allowed line count",
};
 
static SMTP_REPLY_READ_THREAD_LOCAL smtp_reply_read_err g_reply_read_last_err = SMTP_REPLY_READ_OK;

static smtp_reply_read_err
smtp_reply_read_fail(smtp_reply_read_err err) 
{
  g_reply_read_last_err = err;
  return err;  
}

int 
smtp_reply_read(
  const char*       buf,
        size_t      len,
        size_t      max_lines,
        smtp_reply* reply)
{
  SMTP_REPLY_READ_ASSERT(reply != NULL);
  SMTP_REPLY_READ_ASSERT(max_lines > 0);

  size_t  offset      = 0;
  size_t  line_count  = 0;
  int     first_code  = 0;

  while (line_count < max_lines) {
    smtp_reply_line line;
    int rc = smtp_reply_parse_line(buf + offset, len - offset, &line);
    if (rc == SMTP_REPLY_LINE_INCOMPLETE) {
      return smtp_reply_read_fail(SMTP_REPLY_READ_INCOMPLETE);
    }

    if (rc != SMTP_REPLY_LINE_OK) {
      return smtp_reply_read_fail(SMTP_REPLY_READ_ERR_LINE);
    }

    if (line_count == 0) {
      first_code = line.code;
    }
    else if (line.code != first_code) {
      return smtp_reply_read_fail(SMTP_REPLY_READ_ERR_CODE_MISMATCH);
    }

    offset += line.consumed;
    line_count++;

    if (line.is_final) {
      reply->code = first_code;
      reply->consumed = offset;
      reply->line_count = line_count;
      return smtp_reply_read_fail(SMTP_REPLY_READ_OK);
    }
  }
  return smtp_reply_read_fail(SMTP_REPLY_READ_ERR_TOO_MANY_LINES);
}

const char*
smtp_reply_read_get_last_error(void)
{
  SMTP_REPLY_READ_ASSERT(g_reply_read_last_err < SMTP_REPLY_READ_ERR_COUNT);
  return g_reply_read_err_strings[g_reply_read_last_err];
}
