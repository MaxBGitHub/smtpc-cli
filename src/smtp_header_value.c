#include "../include/smtp_header_value.h"
#include "../include/smtp_header_encoding.h"
 
#include <stdio.h>
#include <stdlib.h>

 
#if defined(_MSC_VER)
    #define SMTP_HDRVAL_THREAD_LOCAL __declspec(thread)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
    #define SMTP_HDRVAL_THREAD_LOCAL _Thread_local
#else
    #define SMTP_HDRVAL_THREAD_LOCAL __thread
#endif

 
static void 
smtp_hdrval_assert_fail(
  const char* expr, 
  const char* file, 
        int   line)
{
    fprintf(stderr,
            "smtp_header_value: internal assertion failed: %s (%s:%d)\n",
            expr, file, line);
    abort();
}

 
#define SMTP_HDRVAL_ASSERT(cond) \
    do { \
        if (!(cond)) { \
            smtp_hdrval_assert_fail(#cond, __FILE__, __LINE__); \
        } \
    } while (0)


#define ASCII_TAB             9
#define ASCII_SPACE           32
#define ASCII_PRINTABLE_MIN   33
#define ASCII_PRINTABLE_MAX   126

static int
smtp_hdrval_is_wsp(unsigned char c) 
{
  return c == ASCII_SPACE || c == ASCII_TAB;
}


/* VCHAR (RFC 5234): any visible printing character. */
static int
smtp_hdrval_is_vchar(unsigned char c)
{
  return c >= ASCII_PRINTABLE_MIN && c <= ASCII_PRINTABLE_MAX;
}


/* Any byte that is neither VCHAR, WSP, CR, nor LF is a disallowed
** control character (or a raw 8-bit byte - RFC 5322 headers are
** strictly 7-bit US-ASCII; non-ASCII content belongs in an
** RFC 2047 encoded-word instead). */
static int 
smtp_hdrval_is_disallowed_control(unsigned char c)
{
    if (c == '\r' || c == '\n') {
        return 0; /* handled separately by the fold logic */
    }
    return !smtp_hdrval_is_vchar(c) && !smtp_hdrval_is_wsp(c);
}


static const char *const g_hdrval_err_strings[SMTP_HDRVAL_ERR_COUNT] = {
    [SMTP_HDRVAL_OK]                          = "no error",
    [SMTP_HDRVAL_ERR_EMPTY]                   = "header value is empty",
    [SMTP_HDRVAL_ERR_CONTROL_CHAR]            = "disallowed control character",
    [SMTP_HDRVAL_ERR_BARE_CR]                 = "CR not followed by LF",
    [SMTP_HDRVAL_ERR_BARE_LF]                 = "LF not preceded by CR",
    [SMTP_HDRVAL_ERR_FOLD_NOT_WSP]            = "folded CRLF not followed by whitespace",
    [SMTP_HDRVAL_ERR_LINE_TOO_LONG]           = "physical line exceeds 998 octets",
    [SMTP_HDRVAL_ERR_ENCODED_WORD_INVALID]    = "malformed RFC 2047 encoded-word",
};
 

static SMTP_HDRVAL_THREAD_LOCAL smtp_hdrval_err g_hdrval_last_err         = SMTP_HDRVAL_OK;
static SMTP_HDRVAL_THREAD_LOCAL size_t          g_hdrval_last_err_offset  = 0;


static smtp_hdrval_err 
smtp_hdrval_fail(
  smtp_hdrval_err err, 
  size_t          offset)
{
    g_hdrval_last_err         = err;
    g_hdrval_last_err_offset  = offset;
    return err;
}


/*
** Handles a '\r' encountered at value[i]. Requires an immediate '\n'.
** If the CRLF is the last two bytes of value, it's a valid terminator.
** Otherwise the byte right after CRLF must be WSP (a fold) - anything
** else is an unfolded line break.
**
** On success, *i is advanced past the CRLF (leaving the following WSP,
** if any, for the main loop to process as an ordinary char) and
** *line_len is reset to 0 for the new physical line.
*/
static smtp_hdrval_err 
smtp_hdrval_step_handle_fold(
  const char*   value, 
        size_t  len,
        size_t* i, 
        size_t* line_len)
{
  SMTP_HDRVAL_ASSERT(value != NULL);
  SMTP_HDRVAL_ASSERT(i != NULL);
  SMTP_HDRVAL_ASSERT(line_len != NULL);
  SMTP_HDRVAL_ASSERT(*i < len);
  SMTP_HDRVAL_ASSERT(value[*i] == '\r');

  size_t cr = *i;

  if (cr + 1 >= len || value[cr + 1] != '\n') {
    return smtp_hdrval_fail(SMTP_HDRVAL_ERR_BARE_CR, cr);
  }

  if (cr + 2 == len) {
    /* CRLF is the final two bytes: valid terminator, nothing follows. */
    *i = len;
    return SMTP_HDRVAL_OK;
  }

  if (!smtp_hdrval_is_wsp((unsigned char)value[cr + 2])) {
    return smtp_hdrval_fail(SMTP_HDRVAL_ERR_FOLD_NOT_WSP, cr + 2);
  }

  *i        = cr + 2;
  *line_len = 0;
  return SMTP_HDRVAL_OK;
}


/*
 * Attempts to structurally locate a candidate RFC 2047 encoded-word
 * starting at value[start] (value[start] == '=', value[start+1] == '?').
 * Since '?' can never legally appear inside encoded-text, the first
 * '?' found after the encoding delimiter is unambiguously the closing
 * delimiter - no need to guess with substring search.
 *
 * Sets *found to 1 and *end to the exclusive end offset if a complete
 * "=?...?...?...?=" shape is located (content not yet validated).
 * Sets *found to 0 if no such shape is found before end-of-value or a
 * fold - in that case the caller should treat value[start] as an
 * ordinary text character, since RFC 5322 unstructured text permits
 * '=' and '?' as plain characters.
*/
static void
smtp_hdrval_locate_encoded_word_candidate(
  const char*   value,
        size_t  len,
        size_t  start,
        int*    found,
        size_t* end)
{
  SMTP_HDRVAL_ASSERT(value != NULL);
  SMTP_HDRVAL_ASSERT(found != NULL);
  SMTP_HDRVAL_ASSERT(end != NULL);
  SMTP_HDRVAL_ASSERT(start + 1 < len);
  SMTP_HDRVAL_ASSERT(value[start] == '=' && value[start + 1] == '?');

  *found = 0;

  /* Charset ends at the first '?' (charset token cannot contain '?') */
  size_t charset_end = start + 2;
  while (charset_end < len 
    && value[charset_end] != '?'
    && value[charset_end] != '\r')
  {
    charset_end++;    
  }

  if (charset_end >= len || value[charset_end] != '?') {
    return;
  }

  /* Encoding is exactly one char, then a '?' */
  size_t encoding_pos = charset_end + 1;
  size_t encoding_delim = encoding_pos + 1;
  if (encoding_delim >= len || value[encoding_delim] != '?') {
    return;
  }

  /* Encoded text ends at the first '?' after the encoding delimiter
  ** unambiguous since '?' cannot appear inside valid encoded text. */
  size_t text_end = encoding_delim + 1;
  while (text_end < len 
    && value[text_end] != '?' 
    && value[text_end] != '\r') 
  {
    text_end++;
  }

  if (text_end + 1 >= len 
    || value[text_end] != '?' 
    || value[text_end + 1] != '=') 
  {
    return;
  }

  *found = 1;
  *end = text_end + 2; /* One past the closing '=' */
}


int
smtp_hdrval_validate(
  const char*   value,
        size_t  len)
{
  if (value == NULL || len == 0) {
    return smtp_hdrval_fail(SMTP_HDRVAL_ERR_EMPTY, 0);
  }

  size_t i        = 0;
  size_t line_len = 0;

  while (i < len) {
    unsigned char c = (unsigned char)value[i];

    if (c == '\r') {
      smtp_hdrval_err err = smtp_hdrval_step_handle_fold(
        value, len, &i, &line_len);
      if (err != SMTP_HDRVAL_OK) {
        return (int)err;
      }
      continue;
    }

    if (c == '\n') {
      return smtp_hdrval_fail(SMTP_HDRVAL_ERR_BARE_LF, i);
    }

    if (smtp_hdrval_is_disallowed_control(c)) {
      return smtp_hdrval_fail(SMTP_HDRVAL_ERR_CONTROL_CHAR, i);
    }

    if (c == '=' && i + 1 < len && value[i + 1] == '?') {
      int found = 0;
      size_t end = 0;
      smtp_hdrval_locate_encoded_word_candidate(value, len, i, &found, &end);

      if (found) {
        size_t word_len = end - i;
        int rc = smtp_hdr_validate_encoded_word(value + i, word_len);
        if (rc != SMTP_HDR_OK) {
          return smtp_hdrval_fail(SMTP_HDRVAL_ERR_ENCODED_WORD_INVALID, i);
        }
        i = end;
        line_len += word_len;
        if (line_len > SMTP_HDRVAL_MAX_LINE_LEN) {
          return smtp_hdrval_fail(SMTP_HDRVAL_ERR_LINE_TOO_LONG, i);
        }
        continue;
      }
      /* Not a structural candidate - fall through, '=' is plain text */
    }
    i++;
    line_len++;
    if (line_len > SMTP_HDRVAL_MAX_LINE_LEN) {
      return smtp_hdrval_fail(SMTP_HDRVAL_ERR_LINE_TOO_LONG, i);
    }
  }
  return smtp_hdrval_fail(SMTP_HDRVAL_OK, 0);
}


const char*
smtp_hdrval_get_last_error(void) 
{
  SMTP_HDRVAL_ASSERT(g_hdrval_last_err < SMTP_HDRVAL_ERR_COUNT);
  return g_hdrval_err_strings[g_hdrval_last_err];
}


size_t
smtp_hdrval_get_last_error_offset(void)
{
  return g_hdrval_last_err_offset;
}


const char*
smtp_hdrval_get_last_error_detailed(
  char*   buf, 
  size_t  len)
{
  if (buf == NULL || len == 0) {
    return buf;
  }

  SMTP_HDRVAL_ASSERT(g_hdrval_last_err < SMTP_HDRVAL_ERR_COUNT);

  snprintf(buf, len, "%s at offset %zu",
    g_hdrval_err_strings[g_hdrval_last_err],
    g_hdrval_last_err_offset);

  return buf;
}
