/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — Copyright (C) 2026 Joeri Van Dooren
 */
#ifndef SVX_NET_H
#define SVX_NET_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

#define SVX_MAX_SRV 8

typedef struct {
    char     host[256];
    uint16_t port;
    uint16_t priority;
    uint16_t weight;
} svx_srv;

/* Resolve _svxreflector._tcp.<domain>.
 *
 * Returns the number of records written to `out` (0 if there are none, which
 * is not an error — it just means "use the configured host and port"). The
 * array comes back sorted: priority ascending, then weight descending, so
 * out[0] is the one to try first and the rest are failover candidates. */
int net_srv_resolve(const char *domain, svx_srv *out, int max);

/* Connect a TCP socket, blocking, with a timeout. Returns the fd or -1.
 * The socket is left in BLOCKING mode; the caller switches it after the
 * pre-TLS handshake, which is much easier to get right blocking.
 * `out_addr`, if given, receives the address actually connected to — which is
 * what the UDP socket should then be pointed at, so both channels reach the
 * same server even when the name resolves to several addresses. */
int net_tcp_connect(const char *host, uint16_t port, int timeout_ms,
                    struct sockaddr_in *out_addr);

/* Create an unconnected UDP socket and resolve host:port into *out_addr.
 *
 * Deliberately NOT connect()ed: a reflector behind NAT can answer from a
 * different source port than the one we send to, and a connected socket would
 * silently discard those replies. We filter on nothing and let the AES-GCM tag
 * be the authentication, which it is. */
int net_udp_create(const char *host, uint16_t port, struct sockaddr_in *out_addr);

/* Set O_NONBLOCK. Returns 0 on success. */
int net_set_nonblock(int fd);

/* Disable Nagle. Control frames are small and latency-sensitive. */
int net_set_nodelay(int fd);

/* Format an address as "1.2.3.4:5300" for logging. */
void net_addr_str(char *dst, size_t cap, const struct sockaddr_in *a);

#endif
