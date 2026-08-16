#ifndef SMTP_RESOLVE_H
#define SMTP_RESOLVE_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
  /* See smtp_reactor.h for the full explanation */
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
  #include <sys/socket.h>
#endif


/*
** Hostname/IP resolution, deliberately kept as its own small module rather
** than folded into smtp_orchestrator_create() for two reasons:
**
**  - getaddrinfo() is a real, blocking, potentially slow (DNS round-trip)
**    call. Every other *_create() in this project (reactor, tls_ctx, 
**    orchestrator itself) is fast and synchronous by design, with all actual
**    I/O happening asynchronously afterward. Burying one blocking call inside
**    an otherwise instant setup function would be a real inconsistency, not a
**    convenience.
**  - A hostname can resolve to more than one address (round-robin DNS, or a 
**    host with both IPv4 and IPv6 records). Which one to use, or whether 
**    to fall back to a second one if connections to the first keep failing,
**    is a real policy decision that deserves to be visibile to the caller, 
**    not silently buried inside a single "just give me a host string" call.
**
** Call this once, before creating any orchestrator, never from inside a
** reactor thread's own loop, since a slow or hanging DNS server would block
** that entire thread's connection handling.
*/


/*
** Resolves host (a hostname or numeric IPv4/IPv6 address string) - 
** getaddrinfo() accepts both transparently, skipping the network round-trip 
** entirely when host is already numeric) and port into a concrete address,
** suitable for smtp_orchestrator_create()'s target_addr parameter.
**
** If host resolves to multiple addresses, out_addr receives the FIRST one
** getaddrinfo() returns, which for most resolver configurations already 
** honors a sensible default ordering (RFC 6724). Callers needing genuine
** multi-address fallback should call getaddrinfo() directly instead of this
** convenience wrapper.
**
** Returns 0 on success, non-zero on failure (unknown host, no address of a
** usable family, DNS timeout, etc.). See smtp_resolve_get_last_error() for
** a specific, human-readable reason (the real getaddrinfo() failure text,
** not just a fixed category like "Name or service not known" tells an admin
** far more than "lookup failed" would).
*/
int 
smtp_resolve_host(
  const char*                     host,
        uint16_t                  port,
        struct sockaddr_storage*  out_addr,
        size_t*                   out_addr_len
);

const char* smtp_resolve_get_last_error(void);


#endif /* SMTP_RESOLVE_H */
