/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "net.h"
#include "log.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <resolv.h>
#include <arpa/nameser.h>

int net_set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int net_set_nodelay(int fd) {
    int one = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

void net_addr_str(char *dst, size_t cap, const struct sockaddr_in *a) {
    char ip[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &a->sin_addr, ip, sizeof(ip));
    snprintf(dst, cap, "%s:%u", ip, ntohs(a->sin_port));
}

/* ------------------------------------------------------------------ SRV */

static int srv_cmp(const void *pa, const void *pb) {
    const svx_srv *a = pa, *b = pb;
    if (a->priority != b->priority) return a->priority < b->priority ? -1 : 1;
    if (a->weight   != b->weight)   return a->weight   > b->weight   ? -1 : 1;
    return 0;
}

int net_srv_resolve(const char *domain, svx_srv *out, int max) {
    char qname[512];
    snprintf(qname, sizeof(qname), "_svxreflector._tcp.%s", domain);

    unsigned char answer[NS_PACKETSZ];
    int alen = res_query(qname, ns_c_in, ns_t_srv, answer, sizeof(answer));
    if (alen <= 0) return 0;                 /* no SRV is normal, not an error */

    ns_msg msg;
    if (ns_initparse(answer, alen, &msg) < 0) return 0;

    int n = ns_msg_count(msg, ns_s_an);
    if (n <= 0) return 0;

    int got = 0;
    for (int i = 0; i < n && got < max; i++) {
        ns_rr rr;
        if (ns_parserr(&msg, ns_s_an, i, &rr) < 0) continue;
        if (ns_rr_type(rr) != ns_t_srv) continue;
        if (ns_rr_rdlen(rr) < 7) continue;

        const unsigned char *rd = ns_rr_rdata(rr);
        char target[256];
        if (dn_expand(ns_msg_base(msg), ns_msg_end(msg), rd + 6,
                      target, sizeof(target)) < 0) continue;
        /* "." means "no service here" per RFC 2782. */
        if (target[0] == '\0' || (target[0] == '.' && target[1] == '\0')) continue;

        out[got].priority = (uint16_t)((rd[0] << 8) | rd[1]);
        out[got].weight   = (uint16_t)((rd[2] << 8) | rd[3]);
        out[got].port     = (uint16_t)((rd[4] << 8) | rd[5]);
        snprintf(out[got].host, sizeof(out[got].host), "%s", target);
        got++;
    }

    if (got > 1) qsort(out, (size_t)got, sizeof(*out), srv_cmp);
    return got;
}

/* ------------------------------------------------------------------ TCP */

static int connect_one(const struct addrinfo *ai, int timeout_ms,
                       struct sockaddr_in *out_addr) {
    int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) return -1;

    /* Connect non-blocking so the timeout is ours rather than the kernel's
     * default, which can be well over a minute on an unreachable host. */
    if (net_set_nonblock(fd) != 0) { close(fd); return -1; }

    int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (rc != 0) {
        if (errno != EINPROGRESS) { close(fd); return -1; }

        struct pollfd p = { .fd = fd, .events = POLLOUT };
        int pr;
        do { pr = poll(&p, 1, timeout_ms); } while (pr < 0 && errno == EINTR);
        if (pr <= 0) { close(fd); errno = ETIMEDOUT; return -1; }

        int       err = 0;
        socklen_t el  = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) {
            close(fd);
            errno = err ? err : ECONNREFUSED;
            return -1;
        }
    }

    /* Back to blocking: the pre-TLS handshake is a strict request/response
     * exchange and is far simpler to get right that way. */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    net_set_nodelay(fd);

    if (out_addr && ai->ai_addrlen <= sizeof(*out_addr))
        memcpy(out_addr, ai->ai_addr, ai->ai_addrlen);
    return fd;
}

int net_tcp_connect(const char *host, uint16_t port, int timeout_ms,
                    struct sockaddr_in *out_addr) {
    char portbuf[8];
    snprintf(portbuf, sizeof(portbuf), "%u", port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;      /* the reflector protocol is IPv4 today */
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(host, portbuf, &hints, &res);
    if (rc != 0 || !res) {
        log_err("cannot resolve %s:%u: %s", host, port, gai_strerror(rc));
        return -1;
    }

    /* Try every address the name resolves to before giving up. */
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = connect_one(ai, timeout_ms, out_addr);
        if (fd >= 0) break;
        char ip[INET_ADDRSTRLEN] = "?";
        inet_ntop(AF_INET, &((struct sockaddr_in *)ai->ai_addr)->sin_addr, ip, sizeof(ip));
        log_dbg("connect %s (%s):%u failed: %s", host, ip, port, strerror(errno));
    }
    freeaddrinfo(res);

    if (fd < 0) log_err("TCP connect to %s:%u failed: %s", host, port, strerror(errno));
    return fd;
}

/* ------------------------------------------------------------------ UDP */

int net_udp_create(const char *host, uint16_t port, struct sockaddr_in *out_addr) {
    char portbuf[8];
    snprintf(portbuf, sizeof(portbuf), "%u", port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    int rc = getaddrinfo(host, portbuf, &hints, &res);
    if (rc != 0 || !res) {
        log_err("UDP cannot resolve %s:%u: %s", host, port, gai_strerror(rc));
        return -1;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    if (out_addr && res->ai_addrlen <= sizeof(*out_addr))
        memcpy(out_addr, res->ai_addr, res->ai_addrlen);

    freeaddrinfo(res);
    net_set_nonblock(fd);
    return fd;
}
