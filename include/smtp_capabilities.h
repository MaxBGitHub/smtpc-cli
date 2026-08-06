#ifndef SMTP_CAPABILITIES_H
#define SMTP_CAPABILITIES_H

#include <stddef.h>

/*
** Parses an EHLO response into a capability set (RFC 1869 Sec 4, the ESMTP
** extension mechanism itself mandates that clients tolerate any extension 
** keyword they don't recognize, since the whole point of the mechanism
** is forward extensibility).
**
** Design principle: This module never hard-failes on content it doesn't
** understand. Known capabilities (RFC 1870 SIZE, RFC 3207 STARTTLS,
** RFC 2920 PIPELINING, RFC 6152 8BITMIME, RFC 4954 AUTH, etc.) get structured,
** typed fields. Anything else, vendor extensions, newer extension this code
** predates, malformed but harmless lines, is captured verbatim into a bounded
** catch-all array rather than dropped/discarded, so it's still visible for
** logging and inspection even without structured support. If that array fills
** up, further unknowns are still counted (not silently lost), just not
** stored verbatim.
**
** Unlike the other validators in this project, capability parsing has
** no GetLastError-style failure reporting: A malformed or unrecognized
** capability line is a 'we don't get to use that feature' outcome, not 
** a protocol violation worth aborting the connection over.
** The EHLO response's own structural validity is smtp_reply_reader's job,
** not this module's.
*/ 


#define SMTP_CAP_MAX_UNKNOWN      32 /* Bounded catch-all slot count */
#define SMTP_CAP_MAX_KEYWORD_LEN  32
#define SMTP_CAP_MAX_PARAM_LEN    128

/*
** Named constants for every known capability's wire keyword - the
** single source of truth for the string form of each, shared by this
** module's own parsing internals and by smtp_cap_format_summary()
** below, so a caller never needs to re-derive or duplicate the list
** of known capability names itself.
*/
#define SMTP_AUTH_NAME_PLAIN         "PLAIN"
#define SMTP_AUTH_NAME_LOGIN         "LOGIN"
#define SMTP_AUTH_NAME_CRAM_MD5      "CRAM-MD5"
#define SMTP_AUTH_NAME_DIGEST_MD5    "DIGEST-MD5"
#define SMTP_AUTH_NAME_XOAUTH2       "XOAUTH2"
#define SMTP_AUTH_NAME_SCRAM_SHA_1   "SCRAM-SHA-1"
#define SMTP_AUTH_NAME_SCRAM_SHA_256 "SCRAM-SHA-256"
#define SMTP_AUTH_NAME_NTLM          "NTLM"
#define SMTP_AUTH_NAME_GSSAPI        "GSSAPI"


/*
 * Named constants for every known capability's wire keyword - the
 * single source of truth for the string form of each, shared by this
 * module's own parsing internals and by smtp_cap_format_summary()
 * below, so a caller never needs to re-derive or duplicate the list
 * of known capability names itself.
 */
#define SMTP_CAP_NAME_PIPELINING          "PIPELINING"
#define SMTP_CAP_NAME_STARTTLS            "STARTTLS"
#define SMTP_CAP_NAME_8BITMIME            "8BITMIME"
#define SMTP_CAP_NAME_ENHANCEDSTATUSCODES "ENHANCEDSTATUSCODES"
#define SMTP_CAP_NAME_CHUNKING            "CHUNKING"
#define SMTP_CAP_NAME_DSN                 "DSN"
#define SMTP_CAP_NAME_BINARYMIME          "BINARYMIME"
#define SMTP_CAP_NAME_SMTPUTF8            "SMTPUTF8"
#define SMTP_CAP_NAME_SIZE                "SIZE"
#define SMTP_CAP_NAME_AUTH                "AUTH"
#define SMTP_CAP_NAME_NONE                "(none)" /* summary of an empty capability set */



typedef enum {
  SMTP_AUTH_MECH_PLAIN          = 1u << 0,
  SMTP_AUTH_MECH_LOGIN          = 1u << 1,
  SMTP_AUTH_MECH_CRAM_MD5       = 1u << 2,
  SMTP_AUTH_MECH_DIGEST_MD5     = 1u << 3,
  SMTP_AUTH_MECH_XOAUTH2        = 1u << 4,
  SMTP_AUTH_MECH_SCRAM_SHA_1    = 1u << 5,
  SMTP_AUTH_MECH_SCRAM_SHA_256  = 1u << 6,
  SMTP_AUTH_MECH_NTLM           = 1u << 7,
  SMTP_AUTH_MECH_GSSAPI         = 1u << 8,
  SMTP_AUTH_MECH_UNKNOWN        = 1u << 9 /* saw >=1 unrecognized AUTH token */
} smtp_auth_mech;


typedef struct {
  char  keyword[SMTP_CAP_MAX_KEYWORD_LEN];
  char  params[SMTP_CAP_MAX_PARAM_LEN];
  int   truncated; /* 1 if ketword and/or oarams didn't fully fit */
} smtp_cap_unknown;


typedef struct {
  int has_pipelining;
  int has_starttls;
  int has_8bitmime;
  int has_enhancedstatuscodes;
  int has_chunking;
  int has_dsn;
  int has_binarymime;
  int has_smtputf8;

  int     has_size;         /* Saw the SIZE keyword at all                  */
  int     size_limit_valid; /* size_limit holds a successfully parsed value */
  size_t  size_limit;

  int           has_auth;
  unsigned int  auth_mechs;                       /* bitmask of smtp_auth_mech    */
  char          auth_raw[SMTP_CAP_MAX_PARAM_LEN]; /* Raw AUTH line text, verbatim */

  smtp_cap_unknown unknown[SMTP_CAP_MAX_UNKNOWN];
  size_t unknown_count;
  size_t unknown_overflow_count; /* Unrecognized lines seen after the array filled up  */
} smtp_capabilities;


/*
** Resets caps to all-empty/false. 
** Call once before parsing a fresh EHLO response.
*/
void smtp_cap_init(smtp_capabilities* caps);

/*
** Parses one capability line's text (the part of an EHLO continuation
** line after the reply code, e.g. "AUTH LOGIN PLAIN" or "SIZE 35882577"
** or "X-VENDOR-FOO bar baz") and merges it into *caps. Never fails.
*/
void 
smtp_cap_parse_line(
        smtp_capabilities*  caps, 
  const char*               text, 
        size_t              len
);


/*
** Convenience wrapper: parses a full EHLO response buffer. 
** The first line of an EHLO response is greeting text (server name + hello),
** NOT a capability, and is skipped automatically. Delegates structural
** validation (line framing, code consistency, the line-count bound) to
** smtp_reply_read() and returns whatever it returns.
** On success, caps is populated from every line after the first.
*/
int 
smtp_cap_parse_ehlo_response(
        smtp_capabilities*  caps,
  const char*               buf,
        size_t              len,
        size_t              max_lines
);


/*
** Renders a compact, human readable summary of caps (e.g. 
** 'PIPELINING STARTTLS SIZE=######### AUTH=LOGIN,PLAIN X-VENDOR-FOO'),
** suitable for a single log line. Always NUL-terminated within dst_size.
** Truncates safely if the result doesn't fit. This is a diagnostic summary,
** not authoritative data, so truncation here costs nothing.
**
** Owned by this module rather than by callers specifically so the list of
** known capabilities has exactly one place i'ts enumerated.
** The same place that already owns parsing them.
*/
void
smtp_cap_format_summary(
  const smtp_capabilities*  caps,
        char*               dst,
        size_t              dst_size
);


#endif /* SMTP_CAPABILITIES_H */
