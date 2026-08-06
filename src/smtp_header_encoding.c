#include "../include/smtp_header_encoding.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/* 
** Thread-local storage portability shim (same rationale as the address
** validator: MSVC only supports _Thread_local under /std:c11 or later,
** so don't depend on that build flag being set correctly). 
*/
#if defined(_MSC_VER)
  #define SMTP_HDR_THREAD_LOCAL __declspec(thread)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
  #define SMTP_HDR_THREAD_LOCAL _Thread_local
#else
  #define SMTP_HDR_THREAD_LOCAL __thread
#endif


/* 
** Always-on internal invariant check (JPL Rule 5) - deliberately not
** built on <assert.h>'s assert(), which compiles to a no-op under
** NDEBUG. A failure here means this module's own logic is wrong, not
** that the caller supplied bad input (bad input -> smtp_hdr_err). 
*/
static void
smtp_hdr_assert_fail(
  const char* expr,
  const char* file,
        int   line)
{
  fprintf(stderr, 
          "smtp_header_encoding: internal assertion failed: %s (%s:%d)\n",
          expr, file, line);

  abort();
}


#define SMTP_HDR_ASSERT(cond) \
  do { \
    if (!(cond)) { \
      smtp_hdr_assert_fail(#cond, __FILE__, __LINE__); \
    } \
  } while (0) 



/* Bounds of the printbale ASCII range. */
#define ASCII_SPACE         32
#define ASCII_PRINTABLE_MIN 33  /* '!' */
#define ASCII_PRINTABLE_MAX 126 /* '~' */

#define SMTP_HDR_CHAR_CLASS_TABLE_SIZE 256 /* One entry per possible byte val */

/* Char classification bitmask flags, indexed by unsigned char val. */
#define CH_TOKEN    0x01u /* RFC 2045 token char (charset alphabet) */ 
#define CH_ENCTEXT  0x02u /* RFC 2047 encoded-text char             */
#define CH_HEX      0x04u /* Hex digit, case insensitive            */
#define CH_B64      0x08u /* Base64 alphabet char                   */

static unsigned char  g_hdr_char_class[SMTP_HDR_CHAR_CLASS_TABLE_SIZE];
static int            g_hdr_char_class_ready = 0;

/* 
** Deterministic, idempotent one-time build 
*/
static void
smtp_hdr_build_char_class_table(void) 
{
  for (int c = 0; c < 256; c++) {
    unsigned char flags = 0;

    int is_printable = (c >= ASCII_PRINTABLE_MIN && c <= ASCII_PRINTABLE_MAX);

    /* RFC 2045 Sec 5.1 tspecials: excluded from "token". */
    int is_tspecial =
      c == '(' || c == ')' || c == '<' || c == '>' || c == '@' ||
      c == ',' || c == ';' || c == ':' || c == '\\' || c == '"' ||
      c == '/' || c == '[' || c == ']' || c == '?' || c == '=';

    if (is_printable && !is_tspecial) {
      flags |= CH_TOKEN;
    }

    /* Encoded text = printable ASCII except '?'
    ** (SPACE already excluded since is_printable starts at 33). */
    if (is_printable && c != '?') {
      flags |= CH_ENCTEXT;
    }

    if ((c >= '0' && c <= '9') 
     || (c >= 'A' && c <= 'F') 
     || (c >= 'a' && c <= 'f')) 
    {
      flags |= CH_HEX;
    }

    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') 
     || (c >= '0' && c <= '9') 
     ||  c == '+' || c == '/') 
    {
      flags |= CH_B64;
    }
    g_hdr_char_class[c] = flags;
  }
  g_hdr_char_class_ready = 1;
}


static int 
smtp_hdr_is_token_char(unsigned char c)   
{ 
  return (g_hdr_char_class[c] & CH_TOKEN) != 0; 
}


static int 
smtp_hdr_is_enctext_char(unsigned char c) 
{ 
  return (g_hdr_char_class[c] & CH_ENCTEXT) != 0; 
}


static int 
smtp_hdr_is_hex_digit(unsigned char c)    
{ 
  return (g_hdr_char_class[c] & CH_HEX) != 0; 
}


static int 
smtp_hdr_is_b64_char(unsigned char c)     
{ 
  return (g_hdr_char_class[c] & CH_B64) != 0; 
}


static const char *const g_hdr_err_strings[SMTP_HDR_ERR_COUNT] = {
    [SMTP_HDR_OK]                          = "no error",
    [SMTP_HDR_ERR_EMPTY]                   = "encoded-word is empty",
    [SMTP_HDR_ERR_TOO_LONG]                = "encoded-word exceeds 75 octets",
    [SMTP_HDR_ERR_MISSING_OPEN_DELIM]      = "missing '=?' opening delimiter",
    [SMTP_HDR_ERR_CHARSET_EMPTY]           = "charset is empty",
    [SMTP_HDR_ERR_CHARSET_INVALID_CHAR]    = "invalid character in charset",
    [SMTP_HDR_ERR_MISSING_CHARSET_DELIM]   = "missing '?' after charset",
    [SMTP_HDR_ERR_ENCODING_INVALID]        = "encoding must be exactly one of Q/q/B/b",
    [SMTP_HDR_ERR_MISSING_ENCODING_DELIM]  = "missing '?' after encoding",
    [SMTP_HDR_ERR_MISSING_CLOSE_DELIM]     = "missing '?=' closing delimiter",
    [SMTP_HDR_ERR_TEXT_EMPTY]              = "encoded-text is empty",
    [SMTP_HDR_ERR_TEXT_INVALID_CHAR]       = "invalid character in encoded-text",
    [SMTP_HDR_ERR_Q_BAD_HEX_ESCAPE]        = "'=' in Q-encoding not followed by 2 hex digits",
    [SMTP_HDR_ERR_B_INVALID_CHAR]          = "character outside the base64 alphabet",
    [SMTP_HDR_ERR_B_BAD_LENGTH]            = "base64 encoded-text length is not a multiple of 4",
    [SMTP_HDR_ERR_B_BAD_PADDING]           = "base64 '=' padding must be confined to the end",
};


static SMTP_HDR_THREAD_LOCAL smtp_hdr_err g_hdr_last_err        = SMTP_HDR_OK;
static SMTP_HDR_THREAD_LOCAL size_t       g_hdr_last_err_offset = 0;


static smtp_hdr_err
smtp_hdr_fail(
  smtp_hdr_err  err, 
  size_t        offset)
{
  g_hdr_last_err        = err;
  g_hdr_last_err_offset = offset;

  return err;
} 


/*
** Scans the charset token starting at word[start].
** On success returns SMTP_HDR_OK and sets *end
** to index of '?' that terminates it.
*/
static smtp_hdr_err
smtp_hdr_parse_charset(
  const char*   word,
        size_t  len,
        size_t  start,
        size_t* end)
{
  SMTP_HDR_ASSERT(word != NULL);
  SMTP_HDR_ASSERT(end != NULL);
  SMTP_HDR_ASSERT(start <= len);

  size_t i = start;

  if (i >= len || word[i] == '?') {
    return smtp_hdr_fail(SMTP_HDR_ERR_CHARSET_EMPTY, i);
  }

  for (; i < len; i++) {
    unsigned char c = (unsigned char)word[i];

    if (c == '?') {
      *end = i;
      return SMTP_HDR_OK;
    }
    if (!smtp_hdr_is_token_char(c)) {
      return smtp_hdr_fail(SMTP_HDR_ERR_CHARSET_INVALID_CHAR, i);
    }
  }
  return smtp_hdr_fail(SMTP_HDR_ERR_MISSING_CHARSET_DELIM, len);
}


/*
** Validates the single char encoding token at word[start]
** and confirms word[start+1] is the following '?'.
** Sets *is_base64 accordingly.
*/
static smtp_hdr_err
smtp_hdr_parse_encoding(
  const char*   word,
        size_t  len,
        size_t  start,
        int*    is_base64,
        size_t* end)
{
  SMTP_HDR_ASSERT(word != NULL);
  SMTP_HDR_ASSERT(is_base64 != NULL);
  SMTP_HDR_ASSERT(end != NULL);
  SMTP_HDR_ASSERT(start <= len);

  if (start >= len) {
    return smtp_hdr_fail(SMTP_HDR_ERR_ENCODING_INVALID, start);
  }

  unsigned char c = (unsigned char)word[start];

  if (c == 'Q' || c == 'q') {
    *is_base64 = 0;
  }
  else if (c == 'B' || c == 'b') {
    *is_base64 = 1;
  }
  else {
    return smtp_hdr_fail(SMTP_HDR_ERR_ENCODING_INVALID, start);
  }

  size_t delim = start + 1;
  if (delim >= len || word[delim] != '?') {
    return smtp_hdr_fail(SMTP_HDR_ERR_MISSING_ENCODING_DELIM, delim);
  }
  *end = delim;
  return SMTP_HDR_OK;
}


/*
** Validates Q encoded text (RFC 2047 sec 4.2) over word[start..end].
** '_' and any encoded text char stand for themselves.
** '=' must be followed by exactly 2 hex digits.
*/
static smtp_hdr_err
smtp_hdr_validate_q_text(
  const char*   word,
        size_t  start,
        size_t  end)
{
  SMTP_HDR_ASSERT(word != NULL);
  SMTP_HDR_ASSERT(start <= end);

  size_t i = start;

  while (i < end) {
    unsigned char c = (unsigned char)word[i];

    if (c == '=') {
      unsigned char _c1 = (unsigned char)word[i + 1];
      unsigned char _c2 = (unsigned char)word[i + 2];
      if (i + 2 >= end
       || !smtp_hdr_is_hex_digit(_c1)
       || !smtp_hdr_is_hex_digit(_c2))
      {
        return smtp_hdr_fail(SMTP_HDR_ERR_Q_BAD_HEX_ESCAPE, i);
      }
      i += 3;
    }
    else if (smtp_hdr_is_enctext_char(c)) {
      i += 1;
    }
    else {
      return smtp_hdr_fail(SMTP_HDR_ERR_TEXT_INVALID_CHAR, i);
    }
  }
  return SMTP_HDR_OK;
}


/*
** Validates B encoded text (base64, RFC 2045 sec 6.8) over word[start...end].
** Alphabet checked per char, then length and padding checked as
** a whole once the scan completes.
*/
static smtp_hdr_err
smtp_hdr_validate_b_text(
  const char*   word,
        size_t  start,
        size_t  end)
{
  SMTP_HDR_ASSERT(word != NULL);
  SMTP_HDR_ASSERT(start <= end);

  size_t len        = end - start;
  size_t pad_count  = 0;

  for (size_t i = start; i < end; i++) {
    unsigned char c = (unsigned char)word[i];

    if (c == '=') {
      pad_count++;
    }
    else if (pad_count > 0) {
      /* Non '-' char appeared after padding started */
      return smtp_hdr_fail(SMTP_HDR_ERR_B_BAD_PADDING, i);
    }
    else if (!smtp_hdr_is_b64_char(c)) {
      return smtp_hdr_fail(SMTP_HDR_ERR_B_INVALID_CHAR, i);
    }
  }

  if (pad_count > 2) {
    return smtp_hdr_fail(SMTP_HDR_ERR_B_BAD_PADDING, end - pad_count);    
  }

  if (len % 4 != 0) {
    return smtp_hdr_fail(SMTP_HDR_ERR_B_BAD_LENGTH, end);
  }

  return SMTP_HDR_OK;
}


int 
smtp_hdr_validate_encoded_word(
  const char*   word,
        size_t  len)
{
  if (!g_hdr_char_class_ready) {
    smtp_hdr_build_char_class_table();
  }

  if (word == NULL || len == 0) {
    return smtp_hdr_fail(SMTP_HDR_ERR_EMPTY, 0);
  }

  if (len > SMTP_HDR_ENCODED_WORD_MAX_LEN) {
    return smtp_hdr_fail(SMTP_HDR_ERR_TOO_LONG, SMTP_HDR_ENCODED_WORD_MAX_LEN);
  }

  if (len < 2 || word[0] != '=' || word[1] != '?') {
    return smtp_hdr_fail(SMTP_HDR_ERR_MISSING_OPEN_DELIM, 0);
  }

  /* len >= 2 guaranteed from here on by the check above. */
  if (word[len - 2] != '?' || word[len - 1] != '=') {
    return smtp_hdr_fail(SMTP_HDR_ERR_MISSING_CLOSE_DELIM, len - 2);
  }

  size_t charset_end = 0;
  smtp_hdr_err err = smtp_hdr_parse_charset(word, len, 2, &charset_end);
  if (err != SMTP_HDR_OK) {
    return (int)err;
  }

  int     is_base64     = 0;
  size_t  encoding_end  = 0;
  err = smtp_hdr_parse_encoding(
    word, len, charset_end + 1, &is_base64, &encoding_end);
  if (err != SMTP_HDR_OK) {
    return (int)err;
  }

  /* Encoded text spans (encoding_end + 1) .. (len - 2),
  ** exclusive end, since final 2 bytes are the '?='
  ** close delimiter. */
  size_t text_start = encoding_end + 1;
  size_t text_end   = len - 2;

  SMTP_HDR_ASSERT(text_start <= len);
  SMTP_HDR_ASSERT(text_end <= len);

  if (text_start >= text_end) {
    return smtp_hdr_fail(SMTP_HDR_ERR_TEXT_EMPTY, text_start);
  }

  err = is_base64
      ? smtp_hdr_validate_b_text(word, text_start, text_end)
      : smtp_hdr_validate_q_text(word, text_start, text_end);

  if (err != SMTP_HDR_OK) {
    return (int)err;
  }
  return smtp_hdr_fail(SMTP_HDR_OK, 0);
}


const char*
smtp_hdr_validate_get_last_error(void)
{
  SMTP_HDR_ASSERT(g_hdr_last_err < SMTP_HDR_ERR_COUNT);
  return g_hdr_err_strings[g_hdr_last_err];
}


size_t
smtp_hdr_validate_get_last_error_offset(void)
{
  return g_hdr_last_err_offset;
}


const char*
smtp_hdr_validate_gate_last_error_detailed(
  char*   buf,
  size_t  len)
{
  if (buf == NULL || len == 0) {
    return buf;
  }

  SMTP_HDR_ASSERT(g_hdr_last_err < SMTP_HDR_ERR_COUNT);

  snprintf(buf, len, "%s at offset %zu",
    g_hdr_err_strings[g_hdr_last_err],
    g_hdr_last_err_offset);

  return buf;
}
