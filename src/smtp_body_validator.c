#include "../include/smtp_body_validator.h"

#include <stdio.h>
#include <stdlib.h>


#if defined(_MSC_VER)
    #define SMTP_BODY_THREAD_LOCAL __declspec(thread)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
    #define SMTP_BODY_THREAD_LOCAL _Thread_local
#else
    #define SMTP_BODY_THREAD_LOCAL __thread
#endif


static void 
smtp_body_assert_fail(
  const char* expr, 
  const char* file, 
        int   line)
{
  fprintf(stderr,
          "smtp_body_validator: internal assertion failed: %s (%s:%d)\n",
          expr, file, line);
  abort();
}

#define SMTP_BODY_ASSERT(cond) \
  do { \
    if (!(cond)) { \
        smtp_body_assert_fail(#cond, __FILE__, __LINE__); \
    } \
  } while (0)


#define ASCII_TAB 9

/*
** C0 control chars other than TAB/CR/LF, plus DEL, are disallowed
** regardless of the 8-bit setting (8BITMIME lifts 7-bit ceiling,
** not control character discipline).
*/
static int 
smtp_bodyval_is_disallowed_control(unsigned char c)
{
  if (c == '\r' || c == '\n' || c == ASCII_TAB) {
    return 0;
  }
  return c <= 0x1F || c == 0x7F;
}


static const char *const g_body_err_strings[SMTP_BODY_ERR_COUNT] = {
  [SMTP_BODY_OK]                          = "no error",
  [SMTP_BODY_ERR_EMPTY]                   = "body is empty",
  [SMTP_BODY_ERR_BARE_CR]                 = "CR not followed by LF",
  [SMTP_BODY_ERR_BARE_LF]                 = "LF not preceded by CR",
  [SMTP_BODY_ERR_LINE_TOO_LONG]           = "line exceeds 998 octets",
  [SMTP_BODY_ERR_PREMATURE_TERMINATOR]    = "line is a bare '.' - would prematurely terminate DATA",
  [SMTP_BODY_ERR_CONTROL_CHAR]            = "disallowed control character",
  [SMTP_BODY_ERR_8BIT_NOT_ALLOWED]        = "8-bit byte present but allow_8bit was not set",
};

static SMTP_BODY_THREAD_LOCAL smtp_body_err g_body_last_err         = SMTP_BODY_OK;
static SMTP_BODY_THREAD_LOCAL size_t        g_body_last_err_offset  = 0;

static smtp_body_err 
smtp_body_fail(
  smtp_body_err err, 
  size_t        offset)
{
  g_body_last_err         = err;
  g_body_last_err_offset  = offset;

  return err;
}


/*
** Checks whether the line spanning body[line_start..line_end) is
** exactly a single '.' - the dot stuffing failure this module exists
** to catch (RFC 5321 Sec 4.5.2: an un-stuffed line consisting only of
** "." would be read by the server as the DATA terminator).
*/
static int 
smtp_bodyval_is_bare_dot_line(
  const char*   body, 
        size_t  line_start, 
        size_t  line_end)
{
  SMTP_BODY_ASSERT(body != NULL);
  SMTP_BODY_ASSERT(line_start <= line_end);

  return (line_end - line_start == 1) && (body[line_start] == '.');
}


/*
** Handles a '\r' encountered at body[i]. Requires an immediate '\n'.
** On success, checks the completed line for the bare dot violation,
** advances *i past the CRLF, and resets *line_start and *line_len for
** the next physical line.
*/
static smtp_body_err 
smtp_bodyval_step_handle_crlf(
  const char*   body, 
        size_t  len, 
        size_t* i,
        size_t* line_start, 
        size_t* line_len)
{
  SMTP_BODY_ASSERT(body != NULL);
  SMTP_BODY_ASSERT(i != NULL);
  SMTP_BODY_ASSERT(line_start != NULL);
  SMTP_BODY_ASSERT(line_len != NULL);
  SMTP_BODY_ASSERT(*i < len);
  SMTP_BODY_ASSERT(body[*i] == '\r');

  size_t cr = *i;

  if (cr + 1 >= len || body[cr + 1] != '\n') {
    return smtp_body_fail(SMTP_BODY_ERR_BARE_CR, cr);
  }

  if (smtp_bodyval_is_bare_dot_line(body, *line_start, cr)) {
    return smtp_body_fail(SMTP_BODY_ERR_PREMATURE_TERMINATOR, *line_start);
  }

  *i          = cr + 2;
  *line_start = cr + 2;
  *line_len   = 0;
  return SMTP_BODY_OK;
}


/*
** Validates a single content byte against the always-on control char
** rule and the configurable 8-bit rule.
*/
static smtp_body_err
smtp_bodyval_step_check_byte(
  unsigned char c,
  size_t        i,
  int           allow_8bit)
{
  if (smtp_bodyval_is_disallowed_control(c)) {
    return smtp_body_fail(SMTP_BODY_ERR_CONTROL_CHAR, i);
  }

  if (!allow_8bit && c >= 0x80) {
    return smtp_body_fail(SMTP_BODY_ERR_8BIT_NOT_ALLOWED, i);
  }
  return SMTP_BODY_OK;
}


int
smtp_body_validate(
  const char*   body,
        size_t  len,
        int     allow_8bit)
{
  if (body == NULL || len == 0) {
    return smtp_body_fail(SMTP_BODY_ERR_EMPTY, 0);
  }

  size_t i          = 0;
  size_t line_start = 0;
  size_t line_len   = 0;

  while (i < len) {
    unsigned char c = (unsigned char)body[i];

    if (c == '\r') {
      smtp_body_err err = smtp_bodyval_step_handle_crlf(
        body, len, &i, &line_start, &line_len);
      if (err != SMTP_BODY_OK) {
        return (int)err;
      }  
      continue;
    }

    if (c == '\n') {
      return smtp_body_fail(SMTP_BODY_ERR_BARE_LF, i);
    }

    smtp_body_err err = smtp_bodyval_step_check_byte(c, i, allow_8bit);
    if (err != SMTP_BODY_OK) {
      return (int)err;
    }

    i++;
    line_len++;
    if (line_len > SMTP_BODY_MAX_LINE_LEN) {
      return smtp_body_fail(SMTP_BODY_ERR_LINE_TOO_LONG, i);
    }
  }

  /* Trailing content with no final CRLF is allowed (the callers
  ** command layer is responsible for framing the DATA terminator
  ** seperately) - but it still needs the bare-dot check applied. */
  if (smtp_bodyval_is_bare_dot_line(body, line_start, len)) {
    return smtp_body_fail(SMTP_BODY_ERR_PREMATURE_TERMINATOR, line_start);
  }

  return smtp_body_fail(SMTP_BODY_OK, 0);
}


const char*
smtp_body_validate_get_last_error(void) 
{
  SMTP_BODY_ASSERT(g_body_last_err < SMTP_BODY_ERR_COUNT);
  return g_body_err_strings[g_body_last_err];
}


size_t
smtp_body_validate_get_last_error_offset(void)
{
  return g_body_last_err_offset;
}


const char*
smtp_body_validate_get_last_error_detailed(
  char*   buf,
  size_t  len)
{
  if (buf == NULL || len == 0) {
    return buf;
  }

  SMTP_BODY_ASSERT(g_body_last_err < SMTP_BODY_ERR_COUNT);

  snprintf(buf, len, "%s at offset %zu",
          g_body_err_strings[g_body_last_err],
          g_body_last_err_offset);

  return buf;
}
