#if !defined(_WIN32)
  /* clock_gettime, gmtime_r must precede sys header */
  #define _POSIX_C_SOURCE 200809L 
#endif

#include "../include/smtp_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#if defined(_WIN32)
  #include <windows.h>
#else
  #include <time.h>
  #include <pthread.h>
#endif


static void
smtp_log_assert_fail(
  const char* expr,
  const char* file,
        int   line)
{
  fprintf(stderr,
          "smtp_log: internal assertion failed: %s (%s:%d)\n",
          expr, file, line);
  abort();
}


#define SMTP_LOG_ASSERT(cond) \
    do { \
        if (!(cond)) { \
            smtp_log_assert_fail(#cond, __FILE__, __LINE__); \
        } \
    } while (0)


/*
** Mutex abstraction. Real wrapper functions rather than macros, so
** each side is type-checked and readable on its own - a comma-operator
** macro trick to paper over CRITICAL_SECTION having no failure return
** would be exactly the kind of clever-but-opaque code this project
** avoids.
 */
#if defined(_WIN32)
  typedef CIRITICAL_SECTION smtp_log_mutex;
  static int  mutex_init(smtp_log_mutex* m)     { InitializeCriticalSection(m); return 0; }
  static void mutex_destroy(smtp_log_mutex* m)  { DeleteCriticalSection(m); }
  static void mutex_lock(smtp_log_mutex* m)     { EnterCriticalSection(m); }
  static void mutex_unlock(smtp_log_mutex* m)   { LeaveCriticalSection(m); }
#else
  typedef pthread_mutex_t smtp_log_mutex;
  static int  mutex_init(smtp_log_mutex* m)    { return pthread_mutex_init(m, NULL); }
  static void mutex_destroy(smtp_log_mutex* m) { pthread_mutex_destroy(m); }
  static void mutex_lock(smtp_log_mutex* m)    { pthread_mutex_lock(m); }
  static void mutex_unlock(smtp_log_mutex* m)  { pthread_mutex_unlock(m); }
#endif


/*
** UTC timestamp abstraction, millisecond precision. Numeric fields
** only - never routed through strftime()'s locale-dependent %a/%b.
*/
typedef struct {
  int year;
  int month;
  int day;
  int hour;
  int minute;
  int second;
  int ms;
} smtp_log_timestamp;


static void
smtp_log_get_utc_timestamp(
  smtp_log_timestamp* ts)
{
  SMTP_LOG_ASSERT(ts != NULL);

#if defined(_WIN32)
  FILETIME    ft;
  SYSTEMTIME  st;
  GetSystemTimePreciseAsFileTime(&ft);
  FileTimeToSystemTime(&ft, &st);

  ts->year    = st.wYear;
  ts->month   = st.wMonth;
  ts->day     = st.wDay;
  ts->hour    = st.wHour;
  ts->minute  = st.wMinute;
  ts->second  = st.wSecond;
  ts->ms      = st.wMilliseconds;
#else
  struct timespec tp;
  clock_gettime(CLOCK_REALTIME, &tp);

  struct tm tm_utc;
  /* _r variant: gmtime() alone shares a static buffer
  ** across threads and would corrupt timestamps
  ** under concurrent bulk-mode logging. */  
  gmtime_r(&tp.tv_sec, &tm_utc); 

  ts->year    = tm_utc.tm_year + 1900;
  ts->month   = tm_utc.tm_mon + 1;
  ts->day     = tm_utc.tm_mday;
  ts->hour    = tm_utc.tm_hour;
  ts->minute  = tm_utc.tm_min;
  ts->second  = tm_utc.tm_sec;
  ts->ms      = (int)(tp.tv_nsec / 1000000);
#endif
}

/*
** Event vocabulary = fixed uppercase token, same order as smtp_log_event.
*/
static const char *const g_smtp_log_event_names[SMTP_LOG_EVENT_COUNT] = {
    [SMTP_LOG_RESOLVED]         = "RESOLVED",
    [SMTP_LOG_CONNECTING]       = "CONNECTING",
    [SMTP_LOG_CONNECTED]        = "CONNECTED",
    [SMTP_LOG_EHLO]             = "EHLO",
    [SMTP_LOG_REPLY]            = "REPLY",
    [SMTP_LOG_CAPABILITIES]     = "CAPABILITIES",
    [SMTP_LOG_STARTTLS]         = "STARTTLS",
    [SMTP_LOG_TLS_BEGIN]        = "TLS_BEGIN",
    [SMTP_LOG_TLS_OK]           = "TLS_OK",
    [SMTP_LOG_TLS_FAIL]         = "TLS_FAIL",
    [SMTP_LOG_TLS_CERT_WARNING] = "TLS_CERT_WARNING",
    [SMTP_LOG_MAIL_FROM]        = "MAIL_FROM",
    [SMTP_LOG_RCPT_TO]          = "RCPT_TO",
    [SMTP_LOG_DATA_BEGIN]       = "DATA_BEGIN",
    [SMTP_LOG_DATA_END]         = "DATA_END",
    [SMTP_LOG_RSET]             = "RSET",
    [SMTP_LOG_QUIT]             = "QUIT",
    [SMTP_LOG_DISCONNECT]       = "DISCONNECT",
    [SMTP_LOG_ERROR]            = "ERROR",
    [SMTP_LOG_TIMEOUT]          = "TIMEOUT",
};


static int
smtp_log_contains_cr_or_lf(const char* s)
{
  SMTP_LOG_ASSERT(s != NULL);
  for (const char* p = s; *p != '\0'; p++) {
    if (*p == '\r' || *p == '\n') {
      return 1;
    }
  }
  return 0;
}

/* 
**Renders the ID bracket contents: "T####.C####" or "T####.C####.M####". 
*/
static void
smtp_log_format_id(
  const smtp_log_id*  id,
        char*         dst,
        size_t        dst_size)
{
  SMTP_LOG_ASSERT(id != NULL);
  SMTP_LOG_ASSERT(dst != NULL);

  if (id->has_message_seq) {
    snprintf( dst, dst_size, "T%04" PRIu64 ".C%04" PRIu64 ".M%04" PRIu64,
              id->thread_id, id->connection_id, id->message_seq);
  }
  else {
    snprintf( dst, dst_size, "T%04" PRIu64 ".C%04" PRIu64,
              id->thread_id, id->connection_id);
  }
}


/*
** Global logger state. init/shutdown are single-call, startup/teardown
** operations (not safe concurrently with each other or with emit,
** per the header contract); emit itself is safe from many threads
** once init has succeeded, serialized by g_smtp_log_mutex.
*/
static smtp_log_mutex g_smtp_log_mutex;
static FILE*          g_smtp_log_file       = NULL;
static int            g_smtp_log_ready      = 0;

typedef enum {
  SMTP_LOG_INIT_OK = 0,
  SMTP_LOG_INIT_ERR_NULL_PATH,
  SMTP_LOG_INIT_ERR_OPEN_FAILED,
  SMTP_LOG_INIT_ERR_MUTEX_FAILED,
  SMTP_LOG_INIT_ERR_COUNT,
} smtp_log_init_err;

static const char *const g_smtp_log_init_err_strings[SMTP_LOG_INIT_ERR_COUNT] = {
    [SMTP_LOG_INIT_OK]               = "no error",
    [SMTP_LOG_INIT_ERR_NULL_PATH]    = "filepath is NULL",
    [SMTP_LOG_INIT_ERR_OPEN_FAILED]  = "failed to open log file",
    [SMTP_LOG_INIT_ERR_MUTEX_FAILED] = "failed to initialize log mutex",
};

static smtp_log_init_err g_smtp_log_last_err = SMTP_LOG_INIT_OK;


int 
smtp_log_init(
  const char* filepath)
{
  SMTP_LOG_ASSERT(!g_smtp_log_ready); /* Init called twice without shutdown */

  if (filepath == NULL) {
    g_smtp_log_last_err = SMTP_LOG_INIT_ERR_NULL_PATH;
    return -1;
  }

  g_smtp_log_file = fopen(filepath, "a"); /* append: never clobber */
  if (g_smtp_log_file == NULL) {
    g_smtp_log_last_err = SMTP_LOG_INIT_ERR_OPEN_FAILED;
    return -1;
  }

  /* pthread_mutex_init can genuinely fail per POSIX */
  if (mutex_init(&g_smtp_log_mutex) != 0) {
    g_smtp_log_last_err = SMTP_LOG_INIT_ERR_MUTEX_FAILED;
    fclose(g_smtp_log_file);
    g_smtp_log_file = NULL;
    return -1;
  }

  g_smtp_log_last_err = SMTP_LOG_INIT_OK;
  g_smtp_log_ready = 1;
  return 0;
}


void 
smtp_log_shutdown(void) 
{
  if (!g_smtp_log_ready) {
    return;
  }  

  mutex_lock(&g_smtp_log_mutex);
  if (g_smtp_log_file != NULL) {
    fflush(g_smtp_log_file);
    fclose(g_smtp_log_file);
    g_smtp_log_file = NULL;
  }
  mutex_unlock(&g_smtp_log_mutex);
  mutex_destroy(&g_smtp_log_mutex);
  g_smtp_log_ready = 0;
}


const char*
smtp_log_get_last_error(void)
{
  SMTP_LOG_ASSERT(g_smtp_log_last_err < SMTP_LOG_INIT_ERR_COUNT);
  return g_smtp_log_init_err_strings[g_smtp_log_last_err];
}


void
smtp_log_emit(
        smtp_log_event  type, 
  const smtp_log_id*    id, 
  const char*           actor, 
  const char*           detail)
{
  SMTP_LOG_ASSERT(g_smtp_log_ready);
  SMTP_LOG_ASSERT(id != NULL);
  SMTP_LOG_ASSERT(actor != NULL);
  SMTP_LOG_ASSERT(detail != NULL);
  SMTP_LOG_ASSERT(type < SMTP_LOG_EVENT_COUNT);
  SMTP_LOG_ASSERT(!smtp_log_contains_cr_or_lf(actor));
  SMTP_LOG_ASSERT(!smtp_log_contains_cr_or_lf(detail));

  smtp_log_timestamp ts;
  smtp_log_get_utc_timestamp(&ts);

  char id_buf[64];
  smtp_log_format_id(id, id_buf, sizeof(id_buf));

  char line[2048];
  int n = snprintf(line, sizeof(line),
      "[%04d-%02d-%02d] [%02d:%02d:%02d.%03d] [%s] [%s] [%s] '%s'\n",
      ts.year, ts.month, ts.day, ts.hour, ts.minute, ts.second, ts.ms,
      id_buf, actor, g_smtp_log_event_names[type], detail);

  if (n < 0) {
    return; /* snprintf encoding failure */
  }

  size_t write_len = (size_t)n < sizeof(line)
                    ? (size_t)n
                    : sizeof(line) - 1;

  mutex_lock(&g_smtp_log_mutex);
  fwrite(line, 1, write_len, g_smtp_log_file);
  /* Flush per line: this log is meant to be tailed live during a bulk run,
  ** so durability wins over the cost of one flush syscall per event */
  fflush(g_smtp_log_file);

  mutex_unlock(&g_smtp_log_mutex);
}


/*
** ----------------------------------------------------------------------------
**                                General Info
** ----------------------------------------------------------------------------
** All four helpers share one contract: append to dst[*pos] if and only if
** the whole append fits within dst_size - 1 (one byte for NUL terminator).
** Otherwise, write nothing and report failure. This makes every call site
** a simple size check with no partial write tracking.
*/

#define SMTP_LOG_HEX_DIGIT_LEN  16

static const char g_hex_digits[SMTP_LOG_HEX_DIGIT_LEN] = "0123456789ABCDEF";


static int
smtp_log_append_char(
  char*   dst,
  size_t  dst_size, 
  size_t* pos,
  char    c)
{
  if (*pos + 1 > dst_size - 1) {
    return 0;
  }
  dst[(*pos)++] = c;
  return 1;
}


static int
smtp_log_append_str(
        char*   dst,
        size_t  dst_size,
        size_t* pos,
  const char*   s)
{
  size_t len = strlen(s);
  if (*pos + len > dst_size - 1) {
    return 0;
  }
  memcpy(dst + *pos, s, len);
  *pos += len;
  return 1;
}


static int
smtp_log_append_hex_byte(
  char*         dst,
  size_t        dst_size,
  size_t        *pos,
  unsigned char b)
{
  if (*pos + 2 > dst_size - 1) {
    return 0;
  }

  dst[(*pos)++] = g_hex_digits[(b >> 4) & 0xF];
  dst[(*pos)++] = g_hex_digits[b & 0xF];
  return 1;
}


static int
smtp_log_append_uint(
  char*   dst, 
  size_t  dst_size,
  size_t* pos,
  size_t  value)
{
  char tmp[24];
  int n = 0;

  if (value == 0) {
    tmp[n++] = '0';
  }
  else {
    while (value > 0 && n < (int)sizeof(tmp)) {
      tmp[n++] = (char)('0' + (value % 10));
      value /= 10;
    } 
  }

  if (*pos + (size_t)n > dst_size - 1) {
    return 0;
  }

  for (int i = n - 1; i >= 0; i--) {
    dst[(*pos)++] = tmp[i];
  }
  return 1;
}


size_t
smtp_log_hex_dump(
        char*           dst,
        size_t          dst_size,
  const unsigned char*  src,
        size_t          src_len,
        size_t          max_bytes)
{
  if (dst == NULL || dst_size == 0) {
    return 0;
  }

  if (src == NULL) {
    src_len = 0;
  }

  size_t pos = 0;
  smtp_log_append_char(dst, dst_size, &pos, '[');

  size_t dump_count = src_len < max_bytes 
                    ? src_len 
                    : max_bytes;

  for (size_t i = 0; i < dump_count; i++) {
    if (i > 0 && !smtp_log_append_char(dst, dst_size, &pos, ' ')) {
      break;
    }
    if (!smtp_log_append_hex_byte(dst, dst_size, &pos, src[i])) {
      break;
    }
  }

  if (src_len > dump_count) {
    if (dump_count > 0) {
      smtp_log_append_char(dst, dst_size, &pos, ' ');
    }
    smtp_log_append_char(dst, dst_size, &pos, '+');
    smtp_log_append_uint(dst, dst_size, &pos, src_len - dump_count);
    smtp_log_append_str(dst, dst_size, &pos, " more bytes");
  }

  smtp_log_append_char(dst, dst_size, &pos, ']');

  SMTP_LOG_ASSERT(pos < dst_size);
  dst[pos] = '\0';

  return pos;
}
