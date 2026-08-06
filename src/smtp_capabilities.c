#include "../include/smtp_capabilities.h"
#include "../include/smtp_reply_parser.h"
#include "../include/smtp_reply_reader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static void smtp_cap_assert_fail(
  const char* expr,
  const char* file,
        int   line)
{
  fprintf(stderr,
          "smtp_capabilities: internal assertion failed: %s (%s:%d)\n",
          expr, file, line);
  abort();
}


#define SMTP_CAP_ASSERT(cond) \
  do { \
    if (!(cond)) { \
      smtp_cap_assert_fail(#cond, __FILE__, __LINE__); \
    } \
  } while (0)


/*
** Case-insensitive equality between a (non-NUL-terminated) token and a
** NUL-terminated literal, avoiding any locale-dependent toupper().
*/
static int
smtp_cap_ci_equal(
  const char*   text,
        size_t  len,
  const char*   literal)
{
  SMTP_CAP_ASSERT(text != NULL);
  SMTP_CAP_ASSERT(literal != NULL);

  size_t i = 0;
  for (; i < len; i++) {
    if (literal[i] == '\0') {
      return 0; /* text is longer than literal */
    }
    unsigned char a = (unsigned char)text[i];
    unsigned char b = (unsigned char)literal[i];
    if (a >= 'a' && a <= 'z') { a -= 32; }
    if (b >= 'a' && b <= 'z') { b -= 32; }
    if (a != b) {
      return 0;
    }
  }
  return literal[i] == '\0'; /* literal must also end here */
}


/*
** Packs up to 8 bytes into a uint64_t switch key, one byte per 8-bit 
** lane (byte i at bit offset 8*i) - the exact same encoding used by both
** the runtime scan below and the SMTP_KEY_* case constants, so there
** is exactly one packing definition, never two independently 
** hand authored encodings that have to happen to agree.
*/
#define SMTP_KW_BYTE(c, shift) ((uint64_t)(unsigned char)(c) << (shift))

#define SMTP_KW3(a, b, c) \
  (SMTP_KW_BYTE(a, 0) | SMTP_KW_BYTE(b, 8) | SMTP_KW_BYTE(c, 16))

#define SMTP_KW4(a, b, c, d) \
  (SMTP_KW3(a, b, c) | SMTP_KW_BYTE(d, 24))

#define SMTP_KW8(a, b, c, d, e, f, g, h) \
  (SMTP_KW4(a, b, c, d) | SMTP_KW_BYTE(e, 32) | SMTP_KW_BYTE(f, 40) \
    | SMTP_KW_BYTE(g, 48) | SMTP_KW_BYTE(h, 56))


/* Keywords that fit entirely within 8 bytes - switch alone IS the
** full match, no seperate cofirm step needed beyond a length check. */ 
#define SMTP_KEY_DSN        SMTP_KW3('D', 'S', 'N')
#define SMTP_KEY_SIZE       SMTP_KW4('S', 'I', 'Z', 'E')
#define SMTP_KEY_AUTH       SMTP_KW4('A', 'U', 'T', 'H')
#define SMTP_KEY_STARTTLS   SMTP_KW8('S', 'T', 'A', 'R', 'T', 'T', 'L', 'S')
#define SMTP_KEY_8BITMIME   SMTP_KW8('8', 'B', 'I', 'T', 'M', 'I', 'M', 'E')
#define SMTP_KEY_CHUNKING   SMTP_KW8('C', 'H', 'U', 'N', 'K', 'I', 'N', 'G')
#define SMTP_KEY_SMTPUTF8   SMTP_KW8('S', 'M', 'T', 'P', 'U', 'T', 'F', '8')

/* Keywords longer than 8 bytes - switch narrows to a single condidate via
** the first 8 byte prefix, then one tail comparison (against bytes already
** normalized during the same scan) confirms it. Never a second read of
** the original input. */
#define SMTP_KEY_PIPELINING_PREFIX            SMTP_KW8('P', 'I', 'P', 'E', 'L', 'I', 'N', 'I')
#define SMTP_KEY_BINARYMIME_PREFIX            SMTP_KW8('B', 'I', 'N', 'A', 'R', 'Y', 'M', 'I')
#define SMTP_KEY_ENHANCEDSTATUSCODES_PREFIX   SMTP_KW8('E', 'N', 'H', 'A', 'N', 'C', 'E', 'D')

#define SMTP_CAP_TAIL_BUF_LEN   24 /* Longest keyword is ENHANCEDSTATUSCODES (19) + margin */


/*
** Single pass over text[0..len] - finds the keyword/params boundary,
** packs the first 8 bytes (uppercase-folded) into *key for switch dispatch,
** and - for keywords that run past 8 bytes - copies the uppercase-folded
** remainder into tail[] for the one confirming once, regardless of which path
** a keyword ends up taking.
*/
static void
smtp_cap_extract_keyword_and_key(
  const char*     text,
        size_t    len,
        uint64_t* key,
        size_t*   kw_len,
        char*     tail,
        size_t    tail_cap,
        size_t*   tail_len,
        size_t*   params_start,
        size_t*   params_len)
{
  SMTP_CAP_ASSERT(text != NULL);
  SMTP_CAP_ASSERT(key != NULL);
  SMTP_CAP_ASSERT(kw_len != NULL);
  SMTP_CAP_ASSERT(tail != NULL);
  SMTP_CAP_ASSERT(tail_len != NULL);
  SMTP_CAP_ASSERT(params_start != NULL);
  SMTP_CAP_ASSERT(params_len != NULL);

  uint64_t  k   = 0;
  size_t    tn  = 0;
  size_t    i   = 0;

  for (; i < len && text[i] != ' '; i++) {
    unsigned char c = (unsigned char)text[i];
    if (c >= 'a' && c <= 'z') {
      c -= 32;  /* uppercase-fold, matching case-insensitive 
                ** EHLO keyword convention this parser already relies on. */
    }

    if (i < 8) {
      k |= SMTP_KW_BYTE(c, 8 * i);      
    }
    else if (tn < tail_cap) {
      tail[tn++] = (char)c;
    }
  }

  *key      = k;
  *kw_len   = i;
  *tail_len = tn;

  if (i < len) {
    *params_start = i + 1;
    *params_len   = len - (i + 1);
  }
  else {
    *params_start = len;
    *params_len   = 0;
  }
}


/*
** Parses a decimal, non-negative SIZE parameter. Skips leading spaces
** defensively. Sets *valid = 0 (rather than failing) on anything malformed
** or on overflow - a bad SIZE param means "we don't get a usable limit",
** not a reason to abort EHLO parsing.
*/
static void
smtp_cap_parse_size_param(
  const char*   text,
        size_t  len,
        size_t* value,
        int*    valid)
{
  SMTP_CAP_ASSERT(text != NULL);
  SMTP_CAP_ASSERT(value != NULL);
  SMTP_CAP_ASSERT(valid != NULL);

  size_t i = 0;
  while (i < len && text[i] == ' ') {
    i++;
  }

  if (i >= len || text[i] < '0' || text[i] > '9') {
    *valid = 0;
    return;
  }

  size_t result = 0;
  for (; i < len && text[i] >= '0' && text[i] <= '9'; i++) {
    unsigned digit = (unsigned)(text[i] - '0');
    if (result > (SIZE_MAX - digit) / 10) {
      *valid = 0;
      return;
    }
    result = result * 10 + digit;
  }
  *value = result;
  *valid = 1;
}


static const struct { 
  const char* name; smtp_auth_mech bit; 
} g_smtp_cap_known_auth[] = {
  { SMTP_AUTH_NAME_PLAIN,         SMTP_AUTH_MECH_PLAIN },
  { SMTP_AUTH_NAME_LOGIN,         SMTP_AUTH_MECH_LOGIN },
  { SMTP_AUTH_NAME_CRAM_MD5,      SMTP_AUTH_MECH_CRAM_MD5 },
  { SMTP_AUTH_NAME_DIGEST_MD5,    SMTP_AUTH_MECH_DIGEST_MD5 },
  { SMTP_AUTH_NAME_XOAUTH2,       SMTP_AUTH_MECH_XOAUTH2 },
  { SMTP_AUTH_NAME_SCRAM_SHA_1,   SMTP_AUTH_MECH_SCRAM_SHA_1 },
  { SMTP_AUTH_NAME_SCRAM_SHA_256, SMTP_AUTH_MECH_SCRAM_SHA_256 },
  { SMTP_AUTH_NAME_NTLM,          SMTP_AUTH_MECH_NTLM },
  { SMTP_AUTH_NAME_GSSAPI,        SMTP_AUTH_MECH_GSSAPI },
};

static const size_t g_smtp_cap_known_auth_count = 
  sizeof(g_smtp_cap_known_auth) / sizeof(g_smtp_cap_known_auth[0]);


/*
** Matches one whitespace delimited AUTH mechanism token against the
** known set, setting the corresponding bit. Unrecognised tokens set
** the UNKOWN bit rather than being dropped silently.
*/
static void
smtp_cap_match_auth_mechanism(
  const char*         token,
        size_t        token_len,
        unsigned int* mask)
{
  SMTP_CAP_ASSERT(token != NULL);
  SMTP_CAP_ASSERT(mask != NULL);

  for (size_t k = 0; k < g_smtp_cap_known_auth_count; k++) {
    if (smtp_cap_ci_equal(token, token_len, g_smtp_cap_known_auth[k].name)) {
      *mask |= (unsigned int)g_smtp_cap_known_auth[k].bit;
      return;
    }
  }
  *mask |= (unsigned int)SMTP_AUTH_MECH_UNKNOWN;
}


/*
** Splits the AUTH line's params on spaces and classifies each token.
** Bounded by len itself (each iteration consumes >=1 byte), so this
** loop is terminating - no seperate cap needed. 
*/
static void 
smtp_cap_parse_auth_mechanisms(
  const char*         text,
        size_t        len,
        unsigned int* mask)
{
  SMTP_CAP_ASSERT(text != NULL);
  SMTP_CAP_ASSERT(mask != NULL);

  size_t i = 0;
  while (i < len) {
    while (i < len && text[i] == ' ') {
      i++;
    }
    size_t token_start = i;
    while (i < len && text[i] != ' ') {
      i++;
    }
    if (i > token_start) {
      smtp_cap_match_auth_mechanism(text + token_start, i - token_start, mask);
    }
  }
}


/*
** Bounded copy into dst[dst_size], NUL-terminated, reporting truncation
** instead of just silently losing data.
*/
static int
smtp_cap_bounded_copy(
        char*   dst,
        size_t  dst_size,
  const char*   src,
        size_t  src_len)
{
  SMTP_CAP_ASSERT(dst != NULL);
  SMTP_CAP_ASSERT(dst_size > 0);
  SMTP_CAP_ASSERT(src != NULL);

  int truncated = src_len > dst_size - 1;
  size_t copy_len = truncated
                  ? dst_size - 1
                  : src_len;

  memcpy(dst, src, copy_len);
  dst[copy_len] = '\0';

  return truncated;
}


static void smtp_cap_store_unknown(
        smtp_capabilities*  caps,
  const char*               kw,
        size_t              kw_len,
  const char*               params,
        size_t              params_len)
{
  SMTP_CAP_ASSERT(caps != NULL);
  SMTP_CAP_ASSERT(kw != NULL);
  SMTP_CAP_ASSERT(params != NULL);

  if (caps->unknown_count >= SMTP_CAP_MAX_UNKNOWN) {
    caps->unknown_overflow_count++;
    return;
  }

  smtp_cap_unknown* slot = &caps->unknown[caps->unknown_count];

  int trunc_kw = smtp_cap_bounded_copy(
    slot->keyword, 
    sizeof(slot->keyword), 
    kw, 
    kw_len);
    
  int trunc_params = smtp_cap_bounded_copy(
    slot->params, 
    sizeof(slot->params), 
    params, 
    params_len);

  slot->truncated = trunc_kw || trunc_params;

  caps->unknown_count++;
}


void 
smtp_cap_init(
  smtp_capabilities* caps)
{
  SMTP_CAP_ASSERT(caps != NULL);
  memset(caps, 0, sizeof(*caps));
}


void 
smtp_cap_parse_line(
        smtp_capabilities*  caps,
  const char*               text,
        size_t              len)
{
  SMTP_CAP_ASSERT(caps != NULL);

  if (text == NULL || len == 0) {
    return; /* Blank continuation line */
  }

  uint64_t  key     = 0;
  size_t    kw_len  = 0;
  
  char    tail[SMTP_CAP_TAIL_BUF_LEN];
  size_t  tail_len = 0;
  
  size_t params_start  = 0;
  size_t params_len    = 0;

  smtp_cap_extract_keyword_and_key( text, len, 
                                    &key, &kw_len, 
                                    tail, sizeof(tail), &tail_len, 
                                    &params_start, &params_len);

  const char* params = text + params_start;

  switch (key) {
    case SMTP_KEY_DSN:
      if (kw_len == 3) {
        caps->has_dsn = 1;
        return;
      }
      break;      
    case SMTP_KEY_SIZE:
      if (kw_len == 4) {
        caps->has_size = 1;
        smtp_cap_parse_size_param(params, 
                                  params_len, 
                                  &caps->size_limit, 
                                  &caps->size_limit_valid);
        return;
      }
      break;      
    case SMTP_KEY_AUTH:
      if (kw_len == 4) {
        caps->has_auth = 1;
        smtp_cap_parse_auth_mechanisms( params, 
                                        params_len, 
                                        &caps->auth_mechs);                                        
        smtp_cap_bounded_copy(caps->auth_raw, 
                              sizeof(caps->auth_raw), 
                              params, 
                              params_len);
        return;
      }
      break;      
    case SMTP_KEY_STARTTLS:
      if (kw_len == 8) {
        caps->has_starttls = 1;
        return;
      }
      break;      
    case SMTP_KEY_8BITMIME:
      if (kw_len == 8) {
        caps->has_8bitmime = 1;
        return;
      }
      break;
    case SMTP_KEY_CHUNKING:
      if (kw_len == 8) {
        caps->has_chunking = 1;
        return;
      }
      break;
    case SMTP_KEY_SMTPUTF8:
      if (kw_len == 8) {
        caps->has_smtputf8 = 1;
        return;
      }
      break;
    case SMTP_KEY_PIPELINING_PREFIX:
      if (kw_len == 10 
        && tail_len == 2 
        && tail[0] == 'N' 
        && tail[1] == 'G') 
      {
        caps->has_pipelining = 1;
        return;
      }
      break;
    case SMTP_KEY_BINARYMIME_PREFIX:
      if (kw_len == 10
        && tail_len == 2
        && tail[0] == 'M'
        && tail[1] == 'E')
      {
        caps->has_binarymime = 1;
        return;        
      }
      break;
    case SMTP_KEY_ENHANCEDSTATUSCODES_PREFIX:
      if (kw_len == 19 
        && tail_len == 11
        && memcmp(tail, "STATUSCODES", 11) == 0)
      {
        caps->has_enhancedstatuscodes = 1;
        return;
      }
      break;
    default:
      break;
  }
  smtp_cap_store_unknown(caps, text, kw_len, params, params_len);
}


int
smtp_cap_parse_ehlo_response(
        smtp_capabilities*  caps,
  const char*               buf,
        size_t              len,
        size_t              max_lines)
{
  SMTP_CAP_ASSERT(caps != NULL);

  smtp_reply reply;
  int rc = smtp_reply_read(buf, len, max_lines, &reply);
  if (rc != SMTP_REPLY_READ_OK) {
    return rc;
  }

  smtp_cap_init(caps);

  size_t offset = 0;
  for (size_t i = 0; i < reply.line_count; i++) {
    smtp_reply_line line;
    int line_rc = smtp_reply_parse_line(buf + offset, len - offset, &line);
    /* Already validated by smtp_reply_read */
    SMTP_CAP_ASSERT(line_rc == SMTP_REPLY_LINE_OK); 

    /* Line 0 is greeting text, not a capability */
    if (i > 0) {
      smtp_cap_parse_line(caps, buf + offset + line.text_offset, line.text_len);
    }
    offset += line.consumed;
  }
  return SMTP_REPLY_READ_OK;
}


/*
** Appends one token to dst, space separating from anything already written.
** Shares the same bounded append shape used throughout this projects
** string building helpers. Always safe to call regardless of how much room
** is left, never overruns dst_size.
*/
static size_t smtp_cap_append_summary_token(
        char*   dst, 
        size_t  dst_size,
        size_t  pos,
        int     wrote_any,
  const char*   token)
{
  SMTP_CAP_ASSERT(dst != NULL);
  SMTP_CAP_ASSERT(token != NULL);

  size_t remaining = pos < dst_size
                    ? dst_size - pos
                    : 0;
  size_t offset = pos < dst_size 
                ? pos 
                : dst_size;

  int n = snprintf( dst + offset, 
                    remaining, 
                    "%s%s", 
                    wrote_any ? " " : "", 
                    token);

  return (n > 0) 
        ? pos + (size_t)n 
        : pos;  
}


void 
smtp_cap_format_summary(
  const smtp_capabilities*  caps, 
        char*               dst, 
        size_t              dst_size) 
{
  SMTP_CAP_ASSERT(caps != NULL);
  SMTP_CAP_ASSERT(dst != NULL);
  SMTP_CAP_ASSERT(dst_size > 0);

  size_t  tmp_len   = 160;
  size_t  pos       = 0;
  int     any       = 0;

  char tmp[tmp_len];

  if (caps->has_pipelining) {
    pos = smtp_cap_append_summary_token(
      dst, dst_size, pos, any, SMTP_CAP_NAME_PIPELINING);
    any = 1;
  }

  if (caps->has_starttls) {
   pos = smtp_cap_append_summary_token(
    dst, dst_size, pos, any, SMTP_CAP_NAME_STARTTLS);
   any = 1;
  }

  if (caps->has_8bitmime) {
    pos = smtp_cap_append_summary_token(
      dst, dst_size, pos, any, SMTP_CAP_NAME_8BITMIME);
    any = 1;
  }

  if (caps->has_enhancedstatuscodes) {
    pos = smtp_cap_append_summary_token(
      dst, dst_size, pos, any, SMTP_CAP_NAME_ENHANCEDSTATUSCODES);
    any = 1;
  }

  if (caps->has_chunking) {
    pos = smtp_cap_append_summary_token(
      dst, dst_size, pos, any, SMTP_CAP_NAME_CHUNKING);
    any = 1;
  }

  if (caps->has_dsn) { 
      pos = smtp_cap_append_summary_token(
        dst, dst_size, pos, any, SMTP_CAP_NAME_DSN);
      any = 1;
  }
  if (caps->has_binarymime) {
      pos = smtp_cap_append_summary_token(
        dst, dst_size, pos, any, SMTP_CAP_NAME_BINARYMIME);
      any = 1;
  }
  if (caps->has_smtputf8) {
      pos = smtp_cap_append_summary_token(
        dst, dst_size, pos, any, SMTP_CAP_NAME_SMTPUTF8);
      any = 1;
  }

  if (caps->has_size) {
      if (caps->size_limit_valid) {
          snprintf( tmp, sizeof(tmp), "%s=%zu", 
                    SMTP_CAP_NAME_SIZE, caps->size_limit);
      }
      else {
          snprintf(tmp, sizeof(tmp), "%s", SMTP_CAP_NAME_SIZE);
      }
      pos = smtp_cap_append_summary_token(dst, dst_size, pos, any, tmp);
      any = 1;
  }

  if (caps->has_auth) {
      snprintf(tmp, sizeof(tmp), "%s=%s", SMTP_CAP_NAME_AUTH, caps->auth_raw);
      pos = smtp_cap_append_summary_token(dst, dst_size, pos, any, tmp);
      any = 1;
  }

  for (size_t i = 0; i < caps->unknown_count; i++) {
      pos = smtp_cap_append_summary_token(
        dst, dst_size, pos, any, caps->unknown[i].keyword);
      any = 1;
  }

  if (!any) {
      snprintf(dst, dst_size, "%s", SMTP_CAP_NAME_NONE);
  }
}
