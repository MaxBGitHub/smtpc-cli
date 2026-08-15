#ifndef SMTP_ORCHESTRATOR_H
#define SMTP_ORCHESTRATOR_H

#include <stddef.h>
#include <stdint.h>

#include "smtp_reactor.h"
#include "smtp_connection.h"
#include "smtp_capabilities.h"
#include "smtp_tls.h"
#include "smtp_log.h"

/* Drives up to max_connections smtp_connection instances concurrently
** on one reactor, recycling each slot into a fresh connection attempt
** the instant the previous one reaches a terminal state, until 
** total_target attempts have been made (0 means run indefinitely until
** smtp_orchestrator_request_stop() is called).
**
** This is the one place in the architecture where "always explicit, always
** caller-driven" is not followed: every other module is driven by
** explicit calls specifically so something above it can interleave other work
** on the same thread. This module IS that "something above" - per the 
** projects own design (n threads, n connection per thread), an orchestrator's
** entire job on its thread is to run connections, so owning its own blocking
** loop is the natural, correct place for the loop to live, not an 
** inconsistency with the modules underneath it.
**
** Owns one smtp_reactor, one smtp_capabilities scratch buffer, and (if any
** TLS mode besides NONE is configured) one smtp_tls_ctx. All thread-scoped
** resources per their own module's design, created here and reused across 
** every connection this orchestrator runs, never recreated per attempt.
**
** No dynamic allocation after smtp_orchestrator_create(): the slot array is
** sized and allocated once.
*/

typedef struct {
  smtp_socket     sock;
  smtp_connection conn;
  int             in_use;
} smtp_orchestrator_slot;


/*
** Called once per connection reaching a terminal state (READY/ERROR/TIMED_OUT),
** after the state transition but before the slot is torn down and recycled.
** conn is fully valid and inspectible (final state, capabilities, cert info
** if TLS was used) for the duration of this call only. Do not retain conn or
** any pointer derived from it past this call returning. The slot behind it
** may be reused for a different connection immediately afterward.
*/
typedef void (*smtp_orchestrator_on_terminal_fn)(
  smtp_connection*  conn,
  smtp_conn_state   final_state,
  void*             userdata
);

typedef struct smtp_orchestrator smtp_orchestrator;

typedef struct {
  size_t total_started;
  size_t total_completed;
  size_t total_succeeded; /* Reached READY */
  size_t total_failed;    /* Reached ERROR or TIMED_OUT, including a 
                              socket()/submit failure before a connection
                              attempt could even begin - every attempt consumes
                              one unit of total_target whether it succeeds 
                              or not, so a run always terminates */
} smtp_orchestrator_stats;


/*
** Creates an orchestrator for up to max_connections concurrent
** connections against target_addr, all sharing the given TLS mode,
** trust setting, and EHLO identity. target_addr must already be
** resolved - see smtp_resolve.h's smtp_resolve_host() for turning a
** hostname or IP string into one; this deliberately stays a fast,
** synchronous, non-blocking setup call like every other _create() in
** this project, so it never performs DNS resolution itself.
**
** target_host is the original hostname or IP string as the caller/
** config specified it, used ONLY for the actor string in logging -
** never for the actual connection, which always uses target_addr
** regardless. May be NULL (falls back to formatting target_addr's
** numeric address alone). Passing the original hostname here, when
** there was one, is what lets the log read "mail.example.com
** (192.0.2.1)" instead of just the bare IP - the difference matters
** to an admin who configured a hostname and would otherwise have no
** way to tell which target a given log line even refers to.
**
** The TLS context (if needed) is created internally here, not passed
** in - it is entirely this orchestrator's own thread-scoped resource,
** matching how each reactor thread owns its own smtp_capabilities
** scratch buffer too, never shared across orchestrators/threads.
** thread_id is used purely for log correlation.
** Returns NULL on failure - see smtp_reactor_get_last_error() or
** smtp_tls_get_last_error() depending on which allocation failed.
*/
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
        uint32_t          thread_id
);


void 
smtp_orchestrator_destroy(
  smtp_orchestrator* orch  
);


/*
** Runs until total_target connection attempts have been made and all of them
** have reached a terminal state (0 means run indefinitely, until
** smtp_orchestrator_request_stop() is called). Blocks the calling thread for 
** the duration. See the module doc comment on why this module owns its loop,
** unlike every other one in this project. on_terminal is called once per
** connection reaching a terminal state. May be NULL if the caller has no need
** to inspect individual outcomes (smtp_orechstrator_get_stats() still 
** accumulates either way).
*/
void 
smtp_orchestrator_run(
  smtp_orchestrator*                orch,
  size_t                            total_target,
  smtp_orchestrator_on_terminal_fn  on_terminal,
  void*                             on_terminal_userdata
);


/*
** Requests that a running smtp_orchestrator_run() call return after its
** current iteration, rather than continuing toward total_target.
** Safe to call from a signal handler or another thread. Sets a single 
** flag and does nothing else.
*/
void 
smtp_orchestrator_request_stop(
  smtp_orchestrator* orch
);

/*
** Readable at any time, including from within on_terminal or after run()
** returns, for reporting progress.
*/
smtp_orchestrator_stats 
smtp_orchestrator_get_stats(
  const smtp_orchestrator* orch
);

#endif /* SMTP_ORCHESTRATOR_H */
