#include "../include/smtp_address_validator.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Thread-local storage portability shim.
 *
 * _Thread_local (C11) requires MSVC to be invoked with /std:c11 or
 * /std:c17 (VS 2019 16.8+). Rather than depend on that build flag being
 * set correctly on the Windows side, fall back to the compiler-specific
 * spelling so this compiles under any MSVC C mode.
*/
#if defined(_MSC_VER)
    #define SMTP_THREAD_LOCAL __declspec(thread)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
    #define SMTP_THREAD_LOCAL _Thread_local
#else
    #define SMTP_THREAD_LOCAL __thread
#endif


static void
SMTP_ADDR_ASSERT_fail(
  const char* expr, 
  const char* file, 
        int   line)
{
  fprintf(stderr,
    "smtp_address_validate: internal assertion failed: %s (%s:%d)\n",
    expr, file, line);
  abort();
}


#define SMTP_ADDR_ASSERT(cond) \
  do { \
    if (!(cond)) { \
      SMTP_ADDR_ASSERT_fail(#cond, __FILE__, __LINE__); \
    } \
  } while (0)


#define SMTP_CHAR_CLASS_TABLE_SIZE  256  /* one entry per possible byte value */
#define LOCAL_PART_MAX_LEN          64
#define DOMAIN_LABEL_MAX_LEN        63
#define DOMAIN_MAX_LEN              255
#define ADDRESS_MAX_LEN             256

/* Bounds of the printable US-ASCII range (RFC 5321/5322 Appendix B). */
#define ASCII_SPACE          32 
#define ASCII_PRINTABLE_MIN  33  /* '!' - first printable char after space */
#define ASCII_PRINTABLE_MAX  126 /* '~' - last printable char              */

/* Char classification bitmask flags, indexed by unsigned char val.  */
#define CH_ATEXT  0x01u /* RFC 5321 atext = unquoted local-part char */
#define CH_ALPHA  0x02u 
#define CH_DIGIT  0x04u
#define CH_QTEXT  0x08u /* quoted-string safe char (excludes " and \)*/
#define CH_DLIT   0x10u /* dcontent = printable, excludes [ ] \      */


static unsigned char  g_smtp_addr_char_class[SMTP_CHAR_CLASS_TABLE_SIZE];
static          int   g_smtp_addr_char_class_ready = 0;


/*
 * One-time table build. Deterministic and idempotent, so a benign race
 * across threads on first use is fine - every thread computes the same
 * bytes; no lock needed.
 */
static void 
smtp_addr_build_char_class_table(void)
{
  for (int c = 0; c < SMTP_CHAR_CLASS_TABLE_SIZE; c++) {
    unsigned char flags = 0;

    if (c >= 'A' && c <= 'Z') {
      flags |= CH_ALPHA;
    }
    else if (c >= 'a' && c <= 'z') {
      flags |= CH_ALPHA;
    }

    if (c >= '0' && c <= '9') {
      flags |= CH_DIGIT;
    }

    if (flags & (CH_ALPHA | CH_DIGIT)) {
      flags |= CH_ATEXT;
    }

    switch (c) {
      case '!': case '#': case '$': case '%': case '&': case '\'':
      case '*': case '+': case '-': case '/': case '=': case '?':
      case '^': case '_': case '`': case '{': case '|': case '}':
      case '~':
        flags |= CH_ATEXT;
        break;
      default:
        break;
    }

    /*
     * qtextSMTP (RFC 5321 Sec 4.1.2) = printable ASCII, excluding the
     * two chars that need backslash-escaping inside a quoted string:
     * '"' and '\'.
    */
    if (c >= ASCII_SPACE 
     && c <= ASCII_PRINTABLE_MAX
     && c != '"' && c != '\\') 
    {
      flags |= CH_QTEXT;
    }

    /*
     * dcontent (RFC 5321 Sec 4.1.3) = printable ASCII, excluding the
     * address-literal delimiters '[' / ']' and the escape char '\'.
     * (Also excludes space, unlike qtextSMTP above.)
    */
    if (c >= ASCII_PRINTABLE_MIN 
     && c <= ASCII_PRINTABLE_MAX
     && c != '[' && c != ']' && c != '\\') 
    {
      flags |= CH_DLIT;
    } 
    g_smtp_addr_char_class[c] = flags;
  } 
  g_smtp_addr_char_class_ready = 1;
}



static int 
smtp_addr_is_atext(
  unsigned char c) 
{
  return (g_smtp_addr_char_class[c] & CH_ATEXT) != 0;
}

static int
smtp_addr_is_qtext(
  unsigned char c)
{
  return (g_smtp_addr_char_class[c] & CH_QTEXT) != 0;
}

static int
smtp_addr_is_dlit(
  unsigned char c)
{
  return (g_smtp_addr_char_class[c] & CH_DLIT) != 0;
}

static int 
smtp_addr_is_alnum(
  unsigned char c) 
{
  return (g_smtp_addr_char_class[c] 
    & (CH_ALPHA | CH_DIGIT)) != 0;
}

static const char *const g_smtp_addr_err_strings[SMTP_ADDR_ERR_COUNT] = {
    [SMTP_ADDR_OK]                              = "no error",
    [SMTP_ADDR_ERR_EMPTY]                       = "address is empty",
    [SMTP_ADDR_ERR_LOCAL_EMPTY]                 = "local-part is empty",
    [SMTP_ADDR_ERR_LOCAL_INVALID_CHAR]          = "invalid character in local-part",
    [SMTP_ADDR_ERR_LOCAL_TOO_LONG]              = "local-part exceeds 64 octets",
    [SMTP_ADDR_ERR_LOCAL_LEADING_DOT]           = "local-part starts with '.'",
    [SMTP_ADDR_ERR_LOCAL_TRAILING_DOT]          = "local-part ends with '.'",
    [SMTP_ADDR_ERR_LOCAL_CONSECUTIVE_DOTS]      = "local-part has consecutive dots",
    [SMTP_ADDR_ERR_LOCAL_UNTERMINATED_QUOTE]    = "unterminated quoted local-part",
    [SMTP_ADDR_ERR_LOCAL_BAD_ESCAPE]            = "invalid escape sequence in quoted local-part",
    [SMTP_ADDR_ERR_LOCAL_BAD_QUOTED_CHAR]       = "invalid character inside quoted local-part",
    [SMTP_ADDR_ERR_MISSING_AT]                  = "missing '@' separator",
    [SMTP_ADDR_ERR_MULTIPLE_AT]                 = "multiple unquoted '@' characters",
    [SMTP_ADDR_ERR_DOMAIN_EMPTY]                = "domain is empty",
    [SMTP_ADDR_ERR_DOMAIN_INVALID_CHAR]         = "invalid character in domain",
    [SMTP_ADDR_ERR_DOMAIN_LABEL_EMPTY]          = "domain has an empty label",
    [SMTP_ADDR_ERR_DOMAIN_LABEL_TOO_LONG]       = "domain label exceeds 63 octets",
    [SMTP_ADDR_ERR_DOMAIN_TOO_LONG]             = "domain exceeds 255 octets",
    [SMTP_ADDR_ERR_DOMAIN_LEADING_HYPHEN]       = "domain label starts with '-'",
    [SMTP_ADDR_ERR_DOMAIN_TRAILING_HYPHEN]      = "domain label ends with '-'",
    [SMTP_ADDR_ERR_DOMAIN_LITERAL_EMPTY]        = "address literal is empty",
    [SMTP_ADDR_ERR_DOMAIN_LITERAL_UNTERMINATED] = "address literal missing closing ']'",
    [SMTP_ADDR_ERR_DOMAIN_LITERAL_INVALID]      = "invalid character in address literal",
    [SMTP_ADDR_ERR_TOTAL_TOO_LONG]              = "address exceeds 256 octets",
};

static SMTP_THREAD_LOCAL smtp_addr_err  g_smtp_addr_last_err        = SMTP_ADDR_OK;
static SMTP_THREAD_LOCAL size_t         g_smtp_addr_last_err_offset = 0;

static int 
smtp_addr_fail(
  smtp_addr_err err,
  size_t        offset)
{
  g_smtp_addr_last_err         = err;
  g_smtp_addr_last_err_offset  = offset;
  return (int)err;
}


typedef enum {
    LOCAL_START,
    LOCAL_ATOM,
    LOCAL_DOT,
    LOCAL_QUOTED_START,
    LOCAL_QUOTED_CHAR,
    LOCAL_QUOTED_ESCAPE
} smtp_addr_local_state;


static smtp_addr_err 
smtp_addr_step_local_start(
  unsigned char           c, 
  size_t                  i,
  smtp_addr_local_state*  state,
  size_t*                 local_len)
{
  SMTP_ADDR_ASSERT(state != NULL);
  SMTP_ADDR_ASSERT(local_len != NULL);

  if (c == '"') {
    *state = LOCAL_QUOTED_START;
    return SMTP_ADDR_OK;
  }

  if (c == '.') {
    return smtp_addr_fail(SMTP_ADDR_ERR_LOCAL_LEADING_DOT, i);
  }

  if (c == '@') {
    return smtp_addr_fail(SMTP_ADDR_ERR_LOCAL_EMPTY, i);
  }

  if (smtp_addr_is_atext(c)) {
    *state      = LOCAL_ATOM;
    *local_len  = 1;
    return SMTP_ADDR_OK;
  }
  return smtp_addr_fail(SMTP_ADDR_ERR_LOCAL_INVALID_CHAR, i);
}


static smtp_addr_err 
smtp_addr_step_local_atom(
  unsigned char           c,
  size_t                  i,
  smtp_addr_local_state*  state,
  size_t*                 local_len,
  int*                    found_at)
{
  SMTP_ADDR_ASSERT(state != NULL);
  SMTP_ADDR_ASSERT(local_len != NULL);
  SMTP_ADDR_ASSERT(found_at != NULL);

  if (c == '@') {
    *found_at = 1;
    return SMTP_ADDR_OK;
  }

  if (c == '.') {
    *state = LOCAL_DOT;
    (*local_len)++;
  }
  else if (smtp_addr_is_atext(c)) {
    (*local_len)++;
  }
  else {
    return smtp_addr_fail(SMTP_ADDR_ERR_LOCAL_INVALID_CHAR, i);
  }

  if (*local_len > LOCAL_PART_MAX_LEN) {
    return smtp_addr_fail(SMTP_ADDR_ERR_LOCAL_TOO_LONG, i);
  }
  return SMTP_ADDR_OK;
}


static smtp_addr_err 
smtp_addr_step_local_dot(
  unsigned char           c,
  size_t                  i,
  smtp_addr_local_state*  state,
  size_t*                 local_len)
{
  SMTP_ADDR_ASSERT(state != NULL);
  SMTP_ADDR_ASSERT(local_len != NULL);

  if (c == '.') {
    return smtp_addr_fail(SMTP_ADDR_ERR_LOCAL_CONSECUTIVE_DOTS, i);    
  }

  if (c == '@') {
    return smtp_addr_fail(SMTP_ADDR_ERR_LOCAL_TRAILING_DOT, i);
  }

  if (smtp_addr_is_atext(c)) {
    *state = LOCAL_ATOM;
    (*local_len)++;
  }
  else {
    return smtp_addr_fail(SMTP_ADDR_ERR_LOCAL_INVALID_CHAR, i);
  }

  if (*local_len > LOCAL_PART_MAX_LEN) {
    return smtp_addr_fail(SMTP_ADDR_ERR_LOCAL_TOO_LONG, i);
  }
  return SMTP_ADDR_OK;
}


static smtp_addr_err 
smtp_addr_step_local_quoted_start(
  unsigned char           c,
  size_t                  i,
  smtp_addr_local_state*  state,
  size_t*                 local_len)
{
  SMTP_ADDR_ASSERT(state != NULL);
  SMTP_ADDR_ASSERT(local_len != NULL);

  if (c == '"') {
    return smtp_addr_fail(SMTP_ADDR_ERR_LOCAL_EMPTY, i);
  }

  if (c == '\\') {
    *state = LOCAL_QUOTED_ESCAPE;
    return SMTP_ADDR_OK;
  }

  if (smtp_addr_is_qtext(c)) {
    *state = LOCAL_QUOTED_CHAR;
    (*local_len)++;
    return SMTP_ADDR_OK;
  }
  return smtp_addr_fail(SMTP_ADDR_ERR_LOCAL_BAD_QUOTED_CHAR, i);
}


static smtp_addr_err 
smtp_addr_step_local_quoted_char(
  unsigned char           c,
  size_t                  i,
  smtp_addr_local_state*  state,
  size_t*                 local_len)
{
  SMTP_ADDR_ASSERT(state != NULL);
  SMTP_ADDR_ASSERT(local_len != NULL);

  if (c == '"') {
    *state = LOCAL_ATOM;
    return SMTP_ADDR_OK;
  }

  if (c == '\\') {
    *state = LOCAL_QUOTED_ESCAPE;
    return SMTP_ADDR_OK;
  }

  if (smtp_addr_is_qtext(c)) {
    (*local_len)++;
  }
  else {
    return smtp_addr_fail(SMTP_ADDR_ERR_LOCAL_BAD_QUOTED_CHAR, i);
  }

  if (*local_len > LOCAL_PART_MAX_LEN) {
    return smtp_addr_fail(SMTP_ADDR_ERR_LOCAL_TOO_LONG, i);
  }
  return SMTP_ADDR_OK;
}


static smtp_addr_err
smtp_addr_step_local_quoted_escape(
  unsigned char           c,
  size_t                  i,
  smtp_addr_local_state*  state,
  size_t*                 local_len)
{
  SMTP_ADDR_ASSERT(state != NULL);
  SMTP_ADDR_ASSERT(local_len != NULL);

  if (c < ASCII_SPACE || c > ASCII_PRINTABLE_MAX) {
    return smtp_addr_fail(SMTP_ADDR_ERR_LOCAL_BAD_ESCAPE, i);
  }

  (*local_len)++;
  *state = LOCAL_QUOTED_CHAR;

  if (*local_len > LOCAL_PART_MAX_LEN) {
    return smtp_addr_fail(SMTP_ADDR_ERR_LOCAL_TOO_LONG, i);
  }
  return SMTP_ADDR_OK;
}


static smtp_addr_err
smtp_addr_parse_local_part(
  const char*   addr,
        size_t  len,
        size_t* at_index)
{
  SMTP_ADDR_ASSERT(addr != NULL);
  SMTP_ADDR_ASSERT(at_index != NULL);
  SMTP_ADDR_ASSERT(len <= ADDRESS_MAX_LEN);

  smtp_addr_local_state state     = LOCAL_START;
  size_t                local_len = 0;
  int                   found_at  = 0;
  size_t                i;

  for (i = 0; i < len && i < ADDRESS_MAX_LEN; i++) {
    unsigned char c = (unsigned char)addr[i];
    smtp_addr_err err = SMTP_ADDR_OK;

    switch (state) {
      case LOCAL_START:
        err = smtp_addr_step_local_start(c, i, &state, &local_len);
        break;
      case LOCAL_ATOM:
        err = smtp_addr_step_local_atom(c, i, &state, &local_len, &found_at);
        break;
      case LOCAL_DOT:
        err = smtp_addr_step_local_dot(c, i, &state, &local_len);
        break;
      case LOCAL_QUOTED_START:
        err = smtp_addr_step_local_quoted_start(c, i, &state, &local_len);
        break;
      case LOCAL_QUOTED_CHAR:
        err = smtp_addr_step_local_quoted_char(c, i, &state, &local_len);
        break;
      case LOCAL_QUOTED_ESCAPE:
        err = smtp_addr_step_local_quoted_escape(c, i, &state, &local_len);
        break;
      default:
        SMTP_ADDR_ASSERT(0);
        return smtp_addr_fail(SMTP_ADDR_ERR_LOCAL_INVALID_CHAR, i);
    }

    if (err != SMTP_ADDR_OK) {
      return err;
    }

    if (found_at) {
      *at_index = i;
      return SMTP_ADDR_OK;
    }
  }

  if (state == LOCAL_QUOTED_START 
   || state == LOCAL_QUOTED_CHAR 
   || state == LOCAL_QUOTED_ESCAPE) 
  {
    return smtp_addr_fail(SMTP_ADDR_ERR_LOCAL_UNTERMINATED_QUOTE, len);  
  }
  return smtp_addr_fail(SMTP_ADDR_ERR_MISSING_AT, len > 0 ? len - 1 : 0);
}


typedef enum {
  DOMAIN_LABEL_START,
  DOMAIN_LABEL_CHAR,
  DOMAIN_LITERAL,
  DOMAIN_LITERAL_DONE
} smtp_addr_domain_state;


static smtp_addr_err
smtp_addr_step_domain_label_start(
  unsigned char           c,
  size_t                  i,
  smtp_addr_domain_state* state, 
  size_t*                 label_len,
  size_t*                 domain_len)
{
  SMTP_ADDR_ASSERT(state != NULL);
  SMTP_ADDR_ASSERT(label_len != NULL);
  SMTP_ADDR_ASSERT(domain_len != NULL);

  if (c == '[') {
    *state = DOMAIN_LITERAL;
    return SMTP_ADDR_OK;
  }

  if (c == '.') {
    return smtp_addr_fail(SMTP_ADDR_ERR_DOMAIN_LABEL_EMPTY, i);
  }

  if (c == '-') {
    return smtp_addr_fail(SMTP_ADDR_ERR_DOMAIN_LEADING_HYPHEN, i);
  }

  if (smtp_addr_is_alnum(c)) {
    *state = DOMAIN_LABEL_CHAR;
    *label_len = 1;
    (*domain_len)++;
    return SMTP_ADDR_OK;
  }
  return smtp_addr_fail(SMTP_ADDR_ERR_DOMAIN_INVALID_CHAR, i);
}


static smtp_addr_err
smtp_addr_step_domain_label_char(
  const char*                   addr,
        unsigned char           c,
        size_t                  i,
        smtp_addr_domain_state* state,
        size_t*                 label_len,
        size_t*                 domain_len)
{
  SMTP_ADDR_ASSERT(addr != NULL);
  SMTP_ADDR_ASSERT(state != NULL);
  SMTP_ADDR_ASSERT(label_len != NULL);
  SMTP_ADDR_ASSERT(domain_len != NULL);
  SMTP_ADDR_ASSERT(i > 0); /* state is unreachable on the first char */

  if (c == '.') {
    if (addr[i - 1] == '-') {
      return smtp_addr_fail(SMTP_ADDR_ERR_DOMAIN_TRAILING_HYPHEN, i - 1);
          
    }
    *state = DOMAIN_LABEL_START;
    *label_len = 0;
    (*domain_len)++;
  }
  else if (c == '-' || smtp_addr_is_alnum(c)) {
    (*label_len)++;
    (*domain_len)++;
  }
  else {
    return smtp_addr_fail(SMTP_ADDR_ERR_DOMAIN_INVALID_CHAR, i);
  }

  if (*label_len > DOMAIN_LABEL_MAX_LEN) {
    return smtp_addr_fail(SMTP_ADDR_ERR_DOMAIN_LABEL_TOO_LONG, i);
  }

  if (*domain_len > DOMAIN_MAX_LEN) {
    return smtp_addr_fail(SMTP_ADDR_ERR_DOMAIN_TOO_LONG, i);
  }
  return SMTP_ADDR_OK;
}


static smtp_addr_err
smtp_addr_step_domain_literal(
  unsigned char           c,
  size_t                  i,
  size_t                  len,
  smtp_addr_domain_state* state,
  size_t*                 domain_len)
{
  SMTP_ADDR_ASSERT(state != NULL);
  SMTP_ADDR_ASSERT(domain_len != NULL);
  SMTP_ADDR_ASSERT(i < len);

  if (c == ']') {
    if (*domain_len == 0) {
      return smtp_addr_fail(SMTP_ADDR_ERR_DOMAIN_LITERAL_EMPTY, i);
    }

    if (i != len - 1) {
      return smtp_addr_fail(SMTP_ADDR_ERR_DOMAIN_LITERAL_INVALID, i);
    }
    *state = DOMAIN_LITERAL_DONE;
    return SMTP_ADDR_OK;    
  }

  if (smtp_addr_is_dlit(c)) {
    (*domain_len)++;
    return SMTP_ADDR_OK;
  }
  return smtp_addr_fail(SMTP_ADDR_ERR_DOMAIN_LITERAL_INVALID, i);
}


static smtp_addr_err
smtp_addr_parse_domain(
  const char*   addr,
        size_t  len,
        size_t  start)
{
  SMTP_ADDR_ASSERT(addr != NULL);
  SMTP_ADDR_ASSERT(start <= len);
  SMTP_ADDR_ASSERT(len <= ADDRESS_MAX_LEN);

  smtp_addr_domain_state  state       = DOMAIN_LABEL_START;
  size_t                  label_len   = 0;
  size_t                  domain_len  = 0;
  size_t                  i;

  for (i = start; i < len && i < ADDRESS_MAX_LEN; i++) {
    unsigned char c = (unsigned char)addr[i];
    smtp_addr_err err = SMTP_ADDR_OK;

    switch (state) {
      case DOMAIN_LABEL_START:
        err = smtp_addr_step_domain_label_start(
          c, i, &state, &label_len, &domain_len);
        break;
      case DOMAIN_LABEL_CHAR:
        err = smtp_addr_step_domain_label_char(
          addr, c, i, &state, &label_len, &domain_len);
        break;
      case DOMAIN_LITERAL:
        err = smtp_addr_step_domain_literal(c, i, len, &state, &domain_len);
        break;
      case DOMAIN_LITERAL_DONE:
        SMTP_ADDR_ASSERT(0);
        return smtp_addr_fail(SMTP_ADDR_ERR_DOMAIN_LITERAL_INVALID, i);
      default:
        SMTP_ADDR_ASSERT(0);
        return smtp_addr_fail(SMTP_ADDR_ERR_DOMAIN_INVALID_CHAR, i);
    }

    if (err != SMTP_ADDR_OK) {
      return err;
    }

    if (state == DOMAIN_LITERAL_DONE) {
      return SMTP_ADDR_OK;
    }
  }

  switch (state) {
    case DOMAIN_LABEL_START:
      return smtp_addr_fail(SMTP_ADDR_ERR_DOMAIN_EMPTY, len);
    case DOMAIN_LABEL_CHAR:
      if (len > 0 && addr[len - 1] == '-') {
        return smtp_addr_fail(SMTP_ADDR_ERR_DOMAIN_TRAILING_HYPHEN, len - 1);
      }
      return SMTP_ADDR_OK;
    case DOMAIN_LITERAL:
      return smtp_addr_fail(SMTP_ADDR_ERR_DOMAIN_LITERAL_UNTERMINATED, len);
    default:
      return SMTP_ADDR_OK;
  }
}


int 
smtp_address_validate(
  const char*   addr, 
        size_t  len) 
{
  if (!g_smtp_addr_char_class_ready) {
    smtp_addr_build_char_class_table();
  }

  if (addr == NULL || len == 0) {
    return smtp_addr_fail(SMTP_ADDR_ERR_EMPTY, 0);
  }

  if (len > ADDRESS_MAX_LEN) {
    return smtp_addr_fail(SMTP_ADDR_ERR_TOTAL_TOO_LONG, ADDRESS_MAX_LEN);
  }

  size_t at_index = 0;
  smtp_addr_err err = smtp_addr_parse_local_part(addr, len, &at_index);
  if (err != SMTP_ADDR_OK) {
    return (int)err;
  }

  SMTP_ADDR_ASSERT(at_index < len);
  SMTP_ADDR_ASSERT(addr[at_index] == '@');

  err = smtp_addr_parse_domain(addr, len, at_index + 1);
  if (err != SMTP_ADDR_OK) {
    return (int)err;
  }
  return smtp_addr_fail(SMTP_ADDR_OK, 0);  
}


const char*
smtp_address_validate_get_last_error(void) 
{
  SMTP_ADDR_ASSERT(g_smtp_addr_last_err < SMTP_ADDR_ERR_COUNT);
  return g_smtp_addr_err_strings[g_smtp_addr_last_err];
}


size_t
smtp_address_validate_get_last_error_offset(void)
{
  return g_smtp_addr_last_err_offset;
}


const char*
smtp_address_validate_get_last_error_detailed(
  char* buf,
  size_t len)
{
  if (buf == NULL || len == 0) {
      return buf;
  }

  SMTP_ADDR_ASSERT(g_smtp_addr_last_err < SMTP_ADDR_ERR_COUNT);

  snprintf( buf, 
            len, 
            "%s at offset %zu",
            g_smtp_addr_err_strings[g_smtp_addr_last_err], 
            g_smtp_addr_last_err_offset);

  return buf;
}
