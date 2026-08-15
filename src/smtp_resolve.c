#if !defined(_WIN32)
  #define _DEFAULT_SOURCE /* For getaddrinfo/addrinfo/gai_strerror under 
                              -std=c11, which disables GNU/BSD extensions
                              by default. Must precede every system header,
                              including the ones smtp_resolve.h itself
                              pulls in below */

#endif

#include "../include/smtp_resolve.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
  #include <netdb.h>
  #include <arpa/inet.h>
#endif


static void
smtp_resolve_assert_fail(
  const char* expr,
  const char* file,
        int   line)
{
  fprintf(stderr,
          "smtp_resolve: internal assertion failed: %s (%s:%d)\n",
          expr, file, line);
  abort();
}


#define SMTP_RESOLVE_ASSERT(cond) \
  do { \
    if (!(cond)) { \
      smtp_resolve_assert_fail(#cond, __FILE__, __LINE__); \
    } \
  } while (0)



#define SMTP_RESOLVE_ERR_DETAIL_LEN   160

typedef enum {
  SMTP_RESOLVE_ERR_OK = 0,
  SMTP_RESOLVE_ERR_INVALID_ARG,
  SMTP_RESOLVE_ERR_WSASTARTUP_FAILED, /* Windows only. */
  SMTP_RESOLVE_ERR_GETADDRINFO_FAILED,
  SMTP_RESOLVE_ERR_NO_USABLE_ADDRESS,
  SMTP_RESOLVE_ERR_COUNT
} smtp_resolve_err;


static const char *const g_smtp_resolve_err_strings[SMTP_RESOLVE_ERR_COUNT] = {
    [SMTP_RESOLVE_ERR_OK]                     = "no error",
    [SMTP_RESOLVE_ERR_INVALID_ARG]            = "invalid argument",
    [SMTP_RESOLVE_ERR_WSASTARTUP_FAILED]      = "WSAStartup failed",
    [SMTP_RESOLVE_ERR_GETADDRINFO_FAILED]     = "getaddrinfo failed",
    [SMTP_RESOLVE_ERR_NO_USABLE_ADDRESS]      = "host resolved but no usable address was returned",
};

static _Thread_local smtp_resolve_err g_smtp_resolve_last_err = SMTP_RESOLVE_ERR_OK;

/* Populated only for SMTP_RESOLVE_ERR_GETADDRINFO_FAILED, where
** gai_strerror() gives a real, specific reason (e.g. "Name or service
** not known"). Empty for every other error, where the fixed string
** above is already the whole story. */
static _Thread_local char g_smtp_resolve_last_err_detail[SMTP_RESOLVE_ERR_DETAIL_LEN];


static void
smtp_resolve_fail(
        smtp_resolve_err  err,
  const char*             detail)
{
  g_smtp_resolve_last_err = err;
  g_smtp_resolve_last_err_detail[0] = '\0';

  if (detail != NULL) {
    size_t n = strlen(detail);
    if (n >= sizeof(g_smtp_resolve_last_err_detail)) {
      n = sizeof(g_smtp_resolve_last_err_detail) - 1;
    }
    memcpy(g_smtp_resolve_last_err_detail, detail, n);
    g_smtp_resolve_last_err_detail[n] = '\0';
  }
}


const char*
smtp_resolve_get_last_error(void)
{
  SMTP_RESOLVE_ASSERT(g_smtp_resolve_last_err < SMTP_RESOLVE_ERR_COUNT);
  if (g_smtp_resolve_last_err_detail[0] != '\0') {
    return g_smtp_resolve_last_err_detail;
  }
  return g_smtp_resolve_err_strings[g_smtp_resolve_last_err];
}


int 
smtp_resolve_host(
  const char*                     host,
        uint16_t                  port,
        struct sockaddr_storage*  out_addr,
        size_t*                   out_addr_len)
{
  if (host == NULL || out_addr == NULL || out_addr_len == NULL) {
    smtp_resolve_fail(SMTP_RESOLVE_ERR_INVALID_ARG, NULL);
    return -1;
  }

#if defined(_WIN32)
  /* WSAStartup/WSACleanup are reference-counted by design (documented
  ** Winsock behavior) - bracketing just this call is safe regardless
  ** of whatever the reactor or anything else does with its own
  ** separate WSAStartup/WSACleanup pair elsewhere. */
  WSADATA wsa_data;
  if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
    smtp_resolve_fail(SMTP_RESOLVE_ERR_WSASTARTUP_FAILED, NULL);
    return -1;
  }
#endif

  char port_str[8];
  snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC; /* IPv4 or IPv6, whichever the host has or
                                    the resolver prefers */
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  struct addrinfo* result = NULL;
  int rc = getaddrinfo(host, port_str, &hints, &result);

  if (rc != 0) {
    smtp_resolve_fail(SMTP_RESOLVE_ERR_GETADDRINFO_FAILED, gai_strerror(rc));
#if defined(_WIN32)
    WSACleanup();
#endif
    return -1;
  }

  if (result == NULL 
    || result->ai_addrlen == 0
    || (size_t)result->ai_addrlen > sizeof(*out_addr)) 
  {
    freeaddrinfo(result);
#if defined(_WIN32)
    WSACleanup();
#endif
    smtp_resolve_fail(SMTP_RESOLVE_ERR_NO_USABLE_ADDRESS, NULL);
    return -1;
  }

  memcpy(out_addr, result->ai_addr, result->ai_addrlen);
  *out_addr_len = (size_t)result->ai_addrlen;

  freeaddrinfo(result);
#if defined(_WIN32)
  WSACleanup();
#endif

  smtp_resolve_fail(SMTP_RESOLVE_ERR_OK, NULL);
  return 0;
}
