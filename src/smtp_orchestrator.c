#include "../include/smtp_orchestrator.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

#if defined(_WIN32)
  /* See smtp_reactor.h for the full explanation. */
  #if !defined(_WIN32_WINNT) || (_WIN32_WINNT < 0x0600)
    #undef _WIN32_WINNT
    #define _WIN32_WINNT 0x0600
  #endif
  #if !defined(WINVER) || (WINVER < 0x0600)
    #undef WINVER
    #define WINVER 0x0600
  #endif
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <time.h>
  #include <unistd.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
#endif


static void
smtp_orch_assert_fail(
  const char* expr,
  const char* file,
        int   line)
{
  fprintf(stderr,
          "smtp_orchestrator: internal assertion failed: %s (%s:%d)\n",
          expr, file, line);
  abort();
}


#define SMTP_ORCH_ASSERT(cond) \
  do { \
    if (!(cond)) { \
      smtp_orch_assert_fail(#cond, __FILE__, __LINE__); \
    } \
  } while (0)


/* Safety net upper bound on how long a single reactor poll() call may block,
** even with nothing due to time out soon. Guarantees 
** smtp_orchestrator_request_stop() is noticed within this long in the worst
** case and keeps the loop from ever blocking indefinitely. */
#define SMTP_ORCH_MAX_POLL_INTERVAL_MS 1000ull

/* One poll() call drains at most this many completions before the loop goes
** back to check for new work to start and deadlines to enforce.
** Generous for any reasonable max_connections. */
#define SMTP_ORCH_POLL_BATCH      64

#define SMTP_ORCH_ACTOR_SIZE      384 /* deliberately larger than
                                        smtp_connection's own 320-byte
                                        actor destination - this buffer
                                        holds the full "ip:port -
                                        hostname:port" rendering before it
                                        reaches that already-tested
                                        bounded copy, so truncation (if
                                        any is ever needed) happens in
                                        exactly one place, not compounded
                                        across two */
#define SMTP_ORCH_IDENTITY_SIZE   256


struct smtp_orchestrator {
  smtp_reactor*           reactor;  /* Owned */  
  smtp_capabilities       caps;     /* Thread-scoped scratch, embedded. 
                                        This is the one-per-orchestrator 
                                        instance, reused across every 
                                        connection it runs */                                        
  smtp_tls_ctx*           tls_ctx;  /* Owned. NULL when tls_mode 
                                        is SMTP_TLS_MODE_NONE */
                                        
  smtp_orchestrator_slot* slots;    /* Owned. Allocated once, 
                                        sized max_connections */                                    
  size_t                  max_connections;
  
  struct sockaddr_storage target_addr;
  size_t                  target_addr_len;

  char                    actor[SMTP_ORCH_ACTOR_SIZE]; /* Derived once from 
                                                        target_addr at create
                                                        time - every connection
                                                        this orchestrator runs
                                                        shares the same remote
                                                        target, so the same 
                                                        actor string */
  char                    ehlo_identity[SMTP_ORCH_IDENTITY_SIZE];
  
  smtp_tls_mode           tls_mode;
  int                     tls_trust_without_validation;
  uint64_t                connect_timeout_ms;

  uint32_t                thread_id;
  uint32_t                next_connection_id;
  
  atomic_int              stop_requested; /* NOT volatile - volatile only
                                            prevents compiler-level
                                            reordering/caching, it does not
                                            provide the cross-thread 
                                            visibility/synchronization 
                                            guarantees C11 actually requires for
                                            safe inter-thread signaling, even
                                            though it often happens to work on
                                            common architectures like x86 in 
                                            practice */ 
  
  smtp_orchestrator_stats stats;
};


#if defined(_WIN32) /* Win32 milliseconds */
static uint64_t
smtp_orch_now_ms(void) 
{
  return (uint64_t)GetTickCount64();
}

static void 
smtp_orch_close_socket(
  smtp_socket sock)
{
  closesocket(sock);  
}
 
#else /* POSIX milliseconds */
static uint64_t
smtp_orch_now_ms(void) 
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static void
smtp_orch_close_socket(
  smtp_socket sock)
{
  close(sock);
}

#endif /* Win32 and POSIX milliseconds */


/*
** Recovers the enclosing slot from the smtp_connection* a reactor completions
** user_data carries - the same offsetof/CONTAINING_RECORD-style 
** pointer-arithmetic technique already used in smtp_reactor_windows.c to 
** recover an smtp_io_op* from the OVERLAPPED* Windows hands back.
** O(1) and avoids a linear scan over every slot on every single completion.
*/
static smtp_orchestrator_slot*
smtp_orch_slot_from_conn(
  smtp_connection* conn)
{
  return (smtp_orchestrator_slot*)((char*)conn 
          - offsetof(smtp_orchestrator_slot, conn));
}


static int
smtp_orch_is_terminal(
  smtp_conn_state conn_state)
{
  return conn_state == SMTP_CONN_STATE_READY
      || conn_state == SMTP_CONN_STATE_ERROR
      || conn_state == SMTP_CONN_STATE_TIMED_OUT; 
}


/*
** Fills dst with the actor string used throughout this orchestrator's logging:
** "ip:port - hostname:port" when target_host is a real, distinct hostname, 
** or "ip:port - n/a" when it isn't (NULL, empty, or textually identical
** to addr's own numeric rendering, meaning the caller gave the IP directly).
** Both ports are the same port, the one actually being connected to, taken
** directly from addr's own sin_port/sin6_port, not a separately tracked
** value. target_host itself never carries a port of its own.
** The connection always uses addr regardless of what this produces.
** This is for logging/displaying only.
*/
static void
smtp_orch_format_actor(
  const struct sockaddr*  addr,
  const char*             target_host,
        char*             dst,
        size_t            dst_size)
{
  SMTP_ORCH_ASSERT(dst_size > 0);

  char ip[64];
  ip[0] = '\0';
  uint16_t port = 0;

  if (addr->sa_family == AF_INET) {
    const struct sockaddr_in* a4 = (const struct sockaddr_in*)addr;
    inet_ntop(AF_INET, &a4->sin_addr, ip, (socklen_t)sizeof(ip));
    port = ntohs(a4->sin_port);
  }
  else if (addr->sa_family == AF_INET6) {
    const struct sockaddr_in6* a6 = (const struct sockaddr_in6*)addr;
    inet_ntop(AF_INET6, &a6->sin6_addr, ip, (socklen_t)sizeof(ip));
    port = ntohs(a6->sin6_port);
  }

  /* Any other family: ip stays empty - not a condition this project's target
  ** platforms produce in practice (TCP over IPv4/IPv6 only). */

  int have_distinct_host = (target_host != NULL
                          && target_host[0] != '\0'
                          && strcmp(target_host, ip) != 0);

  if (have_distinct_host) {
    snprintf(dst, dst_size, "%s:%u - %s:%u", 
      ip, (unsigned)port, target_host, (unsigned)port);
  }
  else {
    snprintf(dst, dst_size, "%s:%u - n/a", 
          ip, (unsigned)port);
  }
}


smtp_orchestrator*
smtp_orchestrator_create(
        size_t            max_connections,
  const struct sockaddr*  target_addr,
        size_t            target_addr_len,
  const char*             target_host,
  const char*             ehlo_identity,
        smtp_tls_mode     tls_mode,
        int               tls_trust_without_validation,
        uint64_t          connect_timeout_ms,
        uint32_t          thread_id)
{
  SMTP_ORCH_ASSERT(max_connections > 0);
  SMTP_ORCH_ASSERT(target_addr != NULL);
  SMTP_ORCH_ASSERT(target_addr_len > 0 
    && target_addr_len <= sizeof(struct sockaddr_storage));
  SMTP_ORCH_ASSERT(ehlo_identity != NULL);

  smtp_orchestrator* orch = calloc(1, sizeof(*orch));
  if (orch == NULL) {
    return NULL;
  }

  orch->reactor = smtp_reactor_create(max_connections);
  if (orch->reactor == NULL) {
    free(orch);
    return NULL;
  }

  if (tls_mode != SMTP_TLS_MODE_NONE) {
    orch->tls_ctx = smtp_tls_ctx_create();
    if (orch->tls_ctx == NULL) {
      smtp_reactor_destroy(orch->reactor);
      free(orch);
      return NULL;
    }
  }

  orch->slots = calloc(max_connections, sizeof(*orch->slots));
  if (orch->slots == NULL) {
    if (orch->tls_ctx == NULL) {
      smtp_tls_ctx_destroy(orch->tls_ctx);
    }
    smtp_reactor_destroy(orch->reactor);
    free(orch);
    return NULL;
  }

  orch->max_connections = max_connections;

  memcpy(&orch->target_addr, target_addr, target_addr_len);
  orch->target_addr_len = target_addr_len;
  smtp_orch_format_actor( target_addr, 
                          target_host, 
                          orch->actor, 
                          sizeof(orch->actor));

  size_t id_len = strlen(ehlo_identity);
  if (id_len >= sizeof(orch->ehlo_identity)) {
    id_len = sizeof(orch->ehlo_identity) - 1;
  }
  memcpy(orch->ehlo_identity, ehlo_identity, id_len);
  orch->ehlo_identity[id_len] = '\0';

  orch->tls_mode                      = tls_mode;
  orch->tls_trust_without_validation  = tls_trust_without_validation;
  orch->connect_timeout_ms            = connect_timeout_ms;
  orch->thread_id                     = thread_id;
  orch->next_connection_id            = 1;

  return orch;
}


void
smtp_orchestrator_destroy(
  smtp_orchestrator* orch)
{
  if (orch == NULL) {
    return;
  }

  /* Any slot still in use here means the caller destroyed the 
  ** orchestrator without letting run() finish. Best-effort cleanup of 
  ** whatever is left, rather than leaking sockets/TLS engines. */
  for (size_t i = 0; i < orch->max_connections; i++) {
    if (orch->slots[i].in_use) {
      smtp_connection_close(&orch->slots[i].conn);
      smtp_orch_close_socket(orch->slots[i].sock);
    }
  }

  free(orch->slots);
  if (orch->tls_ctx != NULL) {
    smtp_tls_ctx_destroy(orch->tls_ctx);
  }
  smtp_reactor_destroy(orch->reactor);
  free(orch);
}


void
smtp_orchestrator_request_stop(
  smtp_orchestrator* orch)
{
  SMTP_ORCH_ASSERT(orch != NULL);
  atomic_store(&orch->stop_requested, 1);
}


smtp_orchestrator_stats 
smtp_orchestrator_get_stats(
  const smtp_orchestrator* orch)
{
  SMTP_ORCH_ASSERT(orch != NULL);
  return orch->stats;
}


/*
** Starts a fresh connection attempt in slot. Every attempt, whether it gets
** as far as a real connection or fails immediately at socket()/submit_connect,
** counts toward total_started, so a bounded run always makes progress toward
** total_target and terminates even under persistent local failures
** (e.g. fd exhaustion).
** Returns 1 if the slot is now in flight, 0 if the attempt failed 
** immediately (already counted as a completed, failed attempt).
*/
static int
smtp_orch_start_slot(
  smtp_orchestrator*      orch,
  smtp_orchestrator_slot* slot,
  uint64_t                now_ms)
{
  smtp_socket sock = socket(orch->target_addr.ss_family, SOCK_STREAM, 0);

#if defined(_WIN32)
  int sock_failed = (sock == INVALID_SOCKET);
#else
  int sock_failed = (sock < 0);
#endif

  orch->stats.total_started++;

  if (sock_failed) {
    orch->stats.total_completed++;
    orch->stats.total_failed++;
    return 0;
  }

  smtp_log_id log_id;
  log_id.thread_id        = orch->thread_id;
  log_id.connection_id    = orch->next_connection_id++;
  log_id.message_seq      = 0;
  log_id.has_message_seq  = 0;

  smtp_connection_init( &slot->conn, 
                        &orch->caps, 
                        log_id, 
                        orch->actor,
                        orch->tls_mode, 
                        orch->tls_ctx, 
                        orch->tls_trust_without_validation);

  int rc = smtp_connection_start(&slot->conn,
                                  orch->reactor,
                                  sock,
                                  (const struct sockaddr*)&orch->target_addr,
                                  orch->target_addr_len,
                                  now_ms,
                                  orch->connect_timeout_ms);

  slot->sock = sock;

  if (rc != 0) {
    /* submit_connect itself rejected this - e.g. reactor at capacity, which 
    ** should not normally happen given the reactor is sized to 
    ** max_connections, but handled rather than assumed impossible. */
    smtp_orch_close_socket(sock);
    orch->stats.total_completed++;
    orch->stats.total_failed++;
    return 0;
  }

  slot->in_use = 1;
  return 1;
}


static void 
smtp_orch_finish_slot(
  smtp_orchestrator*                orch,
  smtp_orchestrator_slot*           slot,
  smtp_conn_state                   final_state,
  smtp_orchestrator_on_terminal_fn  on_terminal,
  void*                             on_terminal_userdata)
{
  if (on_terminal != NULL) {
    on_terminal(&slot->conn, final_state, on_terminal_userdata);
  }

  smtp_connection_close(&slot->conn);
  smtp_reactor_forget(orch->reactor, slot->sock);
  smtp_orch_close_socket(slot->sock);

  slot->in_use = 0;

  orch->stats.total_completed++;
  if (final_state == SMTP_CONN_STATE_READY) {
    orch->stats.total_succeeded++;
  }
  else {
    orch->stats.total_failed++;
  }
}


/*
** The soonest deadline across every in-use slot, bounded below by "now"
** (never negative) and above by SMTP_ORCH_MAX_POLL_INTERVAL_MS (the safety
** net - guarantees the loop periodically wakes even with nothing due soon,
** so a stop request or a newly-fillable slot is never left 
** waiting indefinitely).
*/
static uint64_t
smtp_orch_next_poll_timeout_ms(
  const smtp_orchestrator*  orch,
        uint64_t            now_ms)
{
  uint64_t soonest = 0;
  int any = 0;

  for (size_t i = 0; i < orch->max_connections; i++) {
    if (!orch->slots[i].in_use) {
      continue;
    }
    uint64_t d = orch->slots[i].conn.deadline_ms;
    if (!any || d < soonest) {
      soonest = d;
      any = 1;
    }
  }

  if (!any) {
    return SMTP_ORCH_MAX_POLL_INTERVAL_MS;
  }

  if (soonest <= now_ms) {
    return 0;
  }

  uint64_t remaining = soonest - now_ms;
  return remaining < SMTP_ORCH_MAX_POLL_INTERVAL_MS 
    ? remaining 
    : SMTP_ORCH_MAX_POLL_INTERVAL_MS;
}


void
smtp_orchestrator_run(
  smtp_orchestrator*                orch,
  size_t                            total_target,
  smtp_orchestrator_on_terminal_fn  on_terminal,
  void*                             on_terminal_userdata)
{
  SMTP_ORCH_ASSERT(orch != NULL);

  atomic_store(&orch->stop_requested, 0);

  for (;;) {
    if (atomic_load(&orch->stop_requested)) {
      break;
    }

    uint64_t now_ms = smtp_orch_now_ms();

    /* Fill every free slot with a new attempt, up to total_target (0 = 
    ** unbounded) and max_connections. A failure inside the hleper breaks 
    ** out of this inner loop rather than immediately retrying another slot -
    ** a failure here (e.g. fd exhaustion) is likely to recur immediately
    ** on the very next socket() call too, so waiting for the next full
    ** iteration (after poll() has had a chance to free something up) is more
    ** sensible than hammering a failing syscall every remaining slot in 
    ** one burst. */
    for (size_t i = 0; i < orch->max_connections; i++) {
      smtp_orchestrator_slot* slot = &orch->slots[i];
      if (slot->in_use) {
        continue;
      }

      if (total_target != 0 && orch->stats.total_started >= total_target) {
        break;
      }

      if (!smtp_orch_start_slot(orch, slot, now_ms)) {
        break;
      }
    }

    /* Done: every attempt requested has been started and every one of them 
    ** has already reached a terminal state. */
    if (total_target != 0
      && orch->stats.total_started >= total_target
      && orch->stats.total_completed >= total_target) 
    {
      break;
    }

    int any_in_use = 0;
    for (size_t i = 0; i < orch->max_connections; i++) {
      if (orch->slots[i].in_use) {
        any_in_use = 1;
        break;
      }
    }

    if (!any_in_use 
      && total_target != 0
      && orch->stats.total_started >= total_target)
    {
      break; /* Nothing in flight and nothing left to start */
    }

    uint64_t poll_timeout_ms = smtp_orch_next_poll_timeout_ms(orch, now_ms);

    smtp_io_result results[SMTP_ORCH_POLL_BATCH];
    size_t n = smtp_reactor_poll( orch->reactor, 
                                  results, 
                                  SMTP_ORCH_POLL_BATCH, 
                                  (int)poll_timeout_ms);

    now_ms = smtp_orch_now_ms();

    for (size_t i = 0; i < n; i++) {
      smtp_connection* conn = (smtp_connection*)results[i].user_data;
      smtp_orchestrator_slot* slot = smtp_orch_slot_from_conn(conn);

      smtp_conn_state conn_state = smtp_connection_on_io( conn, 
                                                          orch->reactor, 
                                                          &results[i], 
                                                          orch->ehlo_identity, 
                                                          now_ms);

      if (smtp_orch_is_terminal(conn_state)) {
        smtp_orch_finish_slot(orch, 
                              slot, 
                              conn_state, 
                              on_terminal, 
                              on_terminal_userdata);
      }
    }

    /* Periodic timeout check, independent of what poll() returned.
    ** A connection can time out even if nothing else ever arrives for it */
    for (size_t i = 0; i < orch->max_connections; i++) {
      smtp_orchestrator_slot* slot = &orch->slots[i];
      if (!slot->in_use) {
        continue;
      }
      smtp_conn_state conn_state = smtp_connection_check_timeout(&slot->conn, now_ms);
      if (smtp_orch_is_terminal(conn_state)) {
        smtp_orch_finish_slot(orch, 
                              slot, 
                              conn_state, 
                              on_terminal, 
                              on_terminal_userdata);
      }
    }
  }
}
