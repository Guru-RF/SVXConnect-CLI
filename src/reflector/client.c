/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — Copyright (C) 2026 Joeri Van Dooren
 */
#include "client.h"
#include "handshake.h"

#include "common/log.h"
#include "common/net.h"
#include "common/proto.h"
#include "common/tls.h"
#include "common/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>

#define RC_MAX_FRAME   (256 * 1024)
#define RC_UDP_MTU     2048
#define RC_MAX_MONITOR 64

/* Reconnect backoff, in seconds. The first two are short because the common
 * case is a brief network blip; after that we stop hammering the reflector. */
static const int BACKOFF_S[] = { 3, 3, 5, 10, 20, 30, 60 };
#define N_BACKOFF ((int)(sizeof(BACKOFF_S) / sizeof(BACKOFF_S[0])))

struct rc_client {
    const svx_config *cfg;
    rc_callbacks      cb;

    rc_state          state;
    char              last_error[256];

    handshake_result  conn;          /* valid only while RC_CONNECTED */
    int               have_conn;

    /* connect worker */
    pthread_t         worker;
    int               worker_running;
    _Atomic int       worker_done;    /* worker sets (release); main reads (acquire) */
    handshake_result  worker_result;
    int               worker_rc;
    volatile sig_atomic_t worker_abort;
    int               wake_pipe[2];   /* worker -> main loop wakeup */

    /* timers */
    uint64_t          next_tcp_hb;
    uint64_t          next_udp_hb;
    uint64_t          backoff_until;
    int               backoff_idx;
    int               user_stopped;   /* rc_stop() was called: do not retry */

    /* talkgroup state, re-asserted after every reconnect */
    uint32_t          selected_tg;
    uint32_t          monitor[RC_MAX_MONITOR];
    size_t            n_monitor;

    /* stats */
    rc_stats          stats;
    uint64_t          stats_epoch;
    uint64_t          rx_at_epoch, tx_at_epoch;

    uint8_t          *frame;          /* reassembly scratch for TCP frames */
};

const char *rc_state_name(rc_state s) {
    switch (s) {
    case RC_IDLE:       return "idle";
    case RC_CONNECTING: return "connecting";
    case RC_CONNECTED:  return "connected";
    case RC_BACKOFF:    return "reconnecting";
    default:            return "?";
    }
}

static void set_state(rc_client *c, rc_state st, const char *detail) {
    if (c->state == st && !detail) return;
    c->state = st;
    if (c->cb.on_state) c->cb.on_state(c->cb.user, st, detail);
}

/* ------------------------------------------------------------- lifetime */

rc_client *rc_new(const svx_config *cfg, const rc_callbacks *cb) {
    rc_client *c = calloc(1, sizeof(*c));
    if (!c) return NULL;

    c->cfg   = cfg;
    c->cb    = *cb;
    c->state = RC_IDLE;

    c->frame = malloc(RC_MAX_FRAME);
    if (!c->frame) { free(c); return NULL; }

    if (pipe(c->wake_pipe) != 0) { free(c->frame); free(c); return NULL; }
    net_set_nonblock(c->wake_pipe[0]);
    net_set_nonblock(c->wake_pipe[1]);

    c->conn.tcp_fd = c->conn.udp_fd = -1;
    c->conn.tls.fd = -1;
    return c;
}

static void drop_connection(rc_client *c) {
    if (!c->have_conn) return;
    handshake_release(&c->conn);
    memset(&c->conn, 0, sizeof(c->conn));
    c->conn.tcp_fd = c->conn.udp_fd = -1;
    c->conn.tls.fd = -1;
    c->have_conn   = 0;
}

static void join_worker(rc_client *c) {
    if (!c->worker_running) return;
    c->worker_abort = 1;
    pthread_join(c->worker, NULL);
    c->worker_running = 0;
    c->worker_abort   = 0;
    /* If it succeeded while we were tearing down, release what it produced. */
    if (c->worker_done && c->worker_rc == 0) handshake_release(&c->worker_result);
    c->worker_done = 0;
}

void rc_free(rc_client *c) {
    if (!c) return;
    join_worker(c);
    drop_connection(c);
    if (c->wake_pipe[0] >= 0) close(c->wake_pipe[0]);
    if (c->wake_pipe[1] >= 0) close(c->wake_pipe[1]);
    free(c->frame);
    free(c);
}

/* --------------------------------------------------------- the worker */

static void *worker_main(void *arg) {
    rc_client *c = arg;
    c->worker_rc = handshake_run(c->cfg, &c->worker_result, &c->worker_abort);

    /* Publish the result, then flag done with a RELEASE store, then wake the
     * loop. The main thread reads worker_done with an acquire load before it
     * has joined, so the release/acquire pair is what makes worker_rc and
     * worker_result visible to it — the later pthread_join reaps the thread but
     * is not what synchronises the data. (A plain int flag here is a data race
     * TSan flags, even though the join makes the result itself safe.) */
    atomic_store_explicit(&c->worker_done, 1, memory_order_release);
    ssize_t ignored = write(c->wake_pipe[1], "c", 1);
    (void)ignored;
    return NULL;
}

static void begin_connect(rc_client *c) {
    if (c->worker_running) return;

    memset(&c->worker_result, 0, sizeof(c->worker_result));
    c->worker_result.tcp_fd = c->worker_result.udp_fd = -1;
    c->worker_result.tls.fd = -1;
    c->worker_rc    = -1;
    c->worker_done  = 0;
    c->worker_abort = 0;

    if (pthread_create(&c->worker, NULL, worker_main, c) != 0) {
        snprintf(c->last_error, sizeof(c->last_error), "cannot start the connect thread");
        set_state(c, RC_BACKOFF, c->last_error);
        c->backoff_until = now_ms() + 5000;
        return;
    }
    c->worker_running = 1;
    set_state(c, RC_CONNECTING, NULL);
}

void rc_start(rc_client *c) {
    c->user_stopped = 0;
    if (c->state == RC_CONNECTED || c->state == RC_CONNECTING) return;
    c->backoff_idx = 0;
    begin_connect(c);
}

void rc_stop(rc_client *c, const char *reason) {
    c->user_stopped = 1;
    join_worker(c);
    drop_connection(c);
    snprintf(c->last_error, sizeof(c->last_error), "%s", reason ? reason : "disconnected");
    set_state(c, RC_IDLE, c->last_error);
}

void rc_reconnect_now(rc_client *c) {
    c->user_stopped = 0;
    join_worker(c);
    drop_connection(c);
    c->backoff_idx   = 0;
    c->backoff_until = 0;
    begin_connect(c);
}

/* Schedule the next attempt after losing (or failing to make) a connection. */
static void enter_backoff(rc_client *c, const char *why) {
    drop_connection(c);
    snprintf(c->last_error, sizeof(c->last_error), "%s", why ? why : "connection lost");

    if (c->user_stopped) { set_state(c, RC_IDLE, c->last_error); return; }

    int secs = BACKOFF_S[c->backoff_idx < N_BACKOFF ? c->backoff_idx : N_BACKOFF - 1];
    if (c->backoff_idx < N_BACKOFF - 1) c->backoff_idx++;
    c->backoff_until = now_ms() + (uint64_t)secs * 1000;

    char detail[320];
    snprintf(detail, sizeof(detail), "%s — retrying in %ds", c->last_error, secs);
    set_state(c, RC_BACKOFF, detail);
}

/* ---------------------------------------------------------------- send */

static int send_frame(rc_client *c, const uint8_t *buf, size_t len) {
    if (!c->have_conn) return -1;
    if (tls_queue(&c->conn.tls, buf, len) != 0) return -1;
    return tls_flush(&c->conn.tls);
}

static int send_udp(rc_client *c, uint16_t type, const uint8_t *body, size_t body_len) {
    if (!c->have_conn || c->conn.udp_fd < 0) return -1;

    uint8_t pt[RC_UDP_MTU];
    size_t  ptlen;
    if (proto_build_udp_plaintext(pt, sizeof(pt), &ptlen, type, body, body_len) != 0)
        return -1;

    uint8_t wire[RC_UDP_MTU + 32];
    ssize_t wn = crypto_encrypt_wire(&c->conn.crypto, pt, ptlen, wire, sizeof(wire));
    if (wn < 0) return -1;

    ssize_t sent = sendto(c->conn.udp_fd, wire, (size_t)wn, 0,
                          (struct sockaddr *)&c->conn.udp_remote,
                          sizeof(c->conn.udp_remote));
    if (sent < 0) {
        /* A transient ENOBUFS/EAGAIN is not worth dropping the link over. */
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) return 0;
        log_dbg("UDP send failed: %s", strerror(errno));
        return -1;
    }
    c->stats.tx_packets++;
    c->stats.tx_bytes += (uint64_t)sent;
    c->next_udp_hb = now_ms() + SVX_UDP_HEARTBEAT_MS;
    return 0;
}

static int cmp_u32(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

/* Send the monitor set. Must follow every MsgSelectTG, because selecting a
 * talkgroup clears the server's monitor list. */
static int send_monitor(rc_client *c) {
    uint8_t buf[8 + 4 * RC_MAX_MONITOR];
    size_t  n;
    if (proto_build_tg_monitor(buf, sizeof(buf), &n, c->monitor, c->n_monitor) != 0)
        return -1;
    return send_frame(c, buf, n);
}

int rc_select_tg(rc_client *c, uint32_t tg) {
    c->selected_tg = tg;
    if (!c->have_conn) return 0;      /* re-asserted after the next connect */

    uint8_t buf[64];
    size_t  n;
    if (proto_build_select_tg(buf, sizeof(buf), &n, tg) != 0) return -1;
    if (send_frame(c, buf, n) != 0) return -1;

    /* Immediately re-open the NAT pinhole: after a talkgroup change the
     * server may start sending straight away, and if the mapping has lapsed
     * we would lose the first seconds of the over. */
    send_udp(c, UDP_MSG_HEARTBEAT, NULL, 0);

    return send_monitor(c);
}

int rc_set_monitor(rc_client *c, const uint32_t *ids, size_t n) {
    if (n > RC_MAX_MONITOR) n = RC_MAX_MONITOR;
    memcpy(c->monitor, ids, n * sizeof(uint32_t));
    c->n_monitor = n;
    if (n > 1) qsort(c->monitor, n, sizeof(uint32_t), cmp_u32);
    if (!c->have_conn) return 0;
    return send_monitor(c);
}

int rc_send_audio(rc_client *c, const uint8_t *opus, size_t len) {
    return send_udp(c, UDP_MSG_AUDIO, opus, len);
}

int rc_send_flush(rc_client *c) {
    return send_udp(c, UDP_MSG_FLUSH_SAMPLES, NULL, 0);
}

/* ------------------------------------------------------- receive: TCP */

static void handle_frame(rc_client *c, const uint8_t *body, size_t len) {
    if (len < 2) return;
    uint16_t type = be_get_u16(body);

    switch (type) {
    case MSG_HEARTBEAT: {
        /* Mirror it. The server treats an unanswered heartbeat as a dead node. */
        uint8_t buf[16];
        size_t  n;
        if (proto_build_heartbeat(buf, sizeof(buf), &n) == 0) send_frame(c, buf, n);
        break;
    }

    case MSG_TALKER_START: {
        uint32_t tg = 0;
        char     call[64];
        if (proto_parse_talker(body, len, &tg, call, sizeof(call)) == 0) {
            if (c->cb.on_talker_start) c->cb.on_talker_start(c->cb.user, tg, call);
        }
        break;
    }

    case MSG_TALKER_STOP: {
        uint32_t tg = 0;
        char     call[64];
        if (proto_parse_talker(body, len, &tg, call, sizeof(call)) == 0) {
            if (c->cb.on_talker_stop) c->cb.on_talker_stop(c->cb.user, tg, call);
        }
        break;
    }

    case MSG_NODE_JOINED:
    case MSG_NODE_LEFT: {
        char call[64];
        if (proto_parse_node_event(body, len, call, sizeof(call)) == 0) {
            int joined = (type == MSG_NODE_JOINED);
            c->conn.node_count += joined ? 1 : -1;
            if (c->conn.node_count < 0) c->conn.node_count = 0;
            if (c->cb.on_node) c->cb.on_node(c->cb.user, joined, call);
        }
        break;
    }

    case MSG_ERROR: {
        char e[512];
        if (proto_parse_error(body, len, e, sizeof(e)) == 0) {
            log_warn("reflector: %s", e);
            if (c->cb.on_error) c->cb.on_error(c->cb.user, e);
        }
        break;
    }

    case MSG_PROTO_VER_DOWNGRADE: {
        /* SvxBridge ignores this and then behaves oddly. Say so and give up:
         * there is nothing useful a 3.0-only client can do here. */
        uint16_t maj = 0, min = 0;
        proto_parse_proto_ver_downgrade(body, len, &maj, &min);
        char msg[160];
        snprintf(msg, sizeof(msg),
                 "reflector wants protocol %u.%u, this client only speaks %u.%u",
                 maj, min, PROTO_MAJOR, PROTO_MINOR);
        log_err("%s", msg);
        enter_backoff(c, msg);
        break;
    }

    case MSG_AUTH_OK:
    case MSG_SERVER_INFO:
        break;                                 /* already handled at login */

    default:
        log_dbg("ignoring %s (%u), %zu bytes", proto_msg_name(type), type, len);
        break;
    }
}

static void pump_tcp(rc_client *c) {
    if (!c->have_conn) return;

    if (tls_pump_in(&c->conn.tls) < 0) {
        enter_backoff(c, "the reflector closed the connection");
        return;
    }

    /* Drain every complete frame we now hold. One TLS record can carry
     * several, and poll() cannot see the ones already inside OpenSSL. */
    for (;;) {
        size_t         have = 0;
        const uint8_t *p    = tls_peek(&c->conn.tls, &have);
        if (have < 4) break;

        uint32_t L = be_get_u32(p);
        if (L > RC_MAX_FRAME) {
            enter_backoff(c, "the reflector sent an oversized frame");
            return;
        }
        if (have < 4 + (size_t)L) break;              /* wait for the rest */

        memcpy(c->frame, p + 4, L);
        tls_consume(&c->conn.tls, 4 + (size_t)L);

        handle_frame(c, c->frame, L);
        if (!c->have_conn) return;   /* handle_frame may have torn us down */
    }
}

/* ------------------------------------------------------- receive: UDP */

static void pump_udp(rc_client *c) {
    if (!c->have_conn || c->conn.udp_fd < 0) return;

    for (;;) {
        uint8_t wire[RC_UDP_MTU + 64];
        ssize_t n = recv(c->conn.udp_fd, wire, sizeof(wire), MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            /* ECONNREFUSED can surface on an unconnected socket after an ICMP
             * port-unreachable. Not fatal — keep reading. */
            log_dbg("UDP recv: %s", strerror(errno));
            return;
        }
        if (n == 0) continue;

        uint8_t  pt[RC_UDP_MTU + 64];
        uint32_t counter = 0;
        int      gap     = 0;
        ssize_t  ptlen   = crypto_decrypt_wire(&c->conn.crypto, wire, (size_t)n,
                                               pt, sizeof(pt), &counter, &gap);
        if (ptlen < 0) continue;      /* replay, forgery or corruption: drop */

        c->stats.rx_packets++;
        c->stats.rx_bytes += (uint64_t)n;
        if (gap > 0) c->stats.rx_lost += (uint64_t)gap;

        uint16_t       type = 0;
        const uint8_t *body = NULL;
        size_t         blen = 0;
        if (proto_parse_udp_plaintext(pt, (size_t)ptlen, &type, &body, &blen) != 0)
            continue;

        switch (type) {
        case UDP_MSG_AUDIO:
            if (c->cb.on_audio) c->cb.on_audio(c->cb.user, body, blen, gap);
            break;
        case UDP_MSG_HEARTBEAT:
            break;
        case UDP_MSG_FLUSH_SAMPLES:
        case UDP_MSG_ALL_SAMPLES_FLUSHED:
            if (c->cb.on_flushed) c->cb.on_flushed(c->cb.user);
            break;
        default:
            log_dbg("unexpected UDP message type %u", type);
            break;
        }
    }
}

/* ----------------------------------------------------------- poll glue */

int rc_poll_fds(rc_client *c, struct pollfd *p, int max) {
    int n = 0;

    if (n < max) {
        p[n].fd      = c->wake_pipe[0];
        p[n].events  = POLLIN;
        p[n].revents = 0;
        n++;
    }
    if (c->have_conn && c->conn.tls.fd >= 0 && n < max) {
        p[n].fd      = c->conn.tls.fd;
        p[n].events  = (short)(POLLIN | (tls_want_write(&c->conn.tls) ? POLLOUT : 0));
        p[n].revents = 0;
        n++;
    }
    if (c->have_conn && c->conn.udp_fd >= 0 && n < max) {
        p[n].fd      = c->conn.udp_fd;
        p[n].events  = POLLIN;
        p[n].revents = 0;
        n++;
    }
    return n;
}

int rc_next_timeout_ms(rc_client *c, uint64_t now) {
    uint64_t next = now + 1000;      /* the 1 Hz statistics tick */

    if (c->state == RC_CONNECTED) {
        if (c->next_tcp_hb < next) next = c->next_tcp_hb;
        if (c->next_udp_hb < next) next = c->next_udp_hb;
    } else if (c->state == RC_BACKOFF && c->backoff_until > 0) {
        if (c->backoff_until < next) next = c->backoff_until;
    }
    if (next <= now) return 0;
    uint64_t d = next - now;
    return d > 1000 ? 1000 : (int)d;
}

/* ------------------------------------------------------------ service */

static void adopt_connection(rc_client *c) {
    c->conn      = c->worker_result;
    c->have_conn = 1;
    memset(&c->worker_result, 0, sizeof(c->worker_result));

    c->backoff_idx = 0;
    uint64_t now   = now_ms();
    c->next_tcp_hb = now + SVX_TCP_HEARTBEAT_MS;
    c->next_udp_hb = now + SVX_UDP_HEARTBEAT_MS;

    /* Restore the talkgroup state the user had before the drop, in the same
     * order the protocol requires: select first, monitor second. */
    if (c->selected_tg > 0) {
        uint8_t buf[64];
        size_t  n;
        if (proto_build_select_tg(buf, sizeof(buf), &n, c->selected_tg) == 0)
            send_frame(c, buf, n);
    }
    send_monitor(c);

    set_state(c, RC_CONNECTED, NULL);
}

static void tick_stats(rc_client *c, uint64_t now) {
    if (now - c->stats_epoch < 1000) return;

    uint64_t drx = c->stats.rx_packets - c->rx_at_epoch;
    uint64_t dtx = c->stats.tx_packets - c->tx_at_epoch;
    uint64_t dt  = now - c->stats_epoch;
    if (dt == 0) dt = 1;

    c->stats.rx_pps = (int)((drx * 1000) / dt);
    c->stats.tx_pps = (int)((dtx * 1000) / dt);

    uint64_t expected = c->stats.rx_packets + c->stats.rx_lost;
    c->stats.loss_pct = expected ? (100.0 * (double)c->stats.rx_lost / (double)expected) : 0.0;

    if (c->have_conn) {
        c->stats.rx_replayed  = c->conn.crypto.n_replayed;
        c->stats.rx_auth_fail = c->conn.crypto.n_auth_fail;
    }

    c->stats_epoch = now;
    c->rx_at_epoch = c->stats.rx_packets;
    c->tx_at_epoch = c->stats.tx_packets;
}

void rc_service(rc_client *c, uint64_t now) {
    /* Drain the wakeup pipe. */
    {
        uint8_t sink[64];
        while (read(c->wake_pipe[0], sink, sizeof(sink)) > 0) { }
    }

    /* Has the connect worker finished? Acquire, to pair with the worker's
     * release store and see everything it published. */
    if (c->worker_running &&
        atomic_load_explicit(&c->worker_done, memory_order_acquire)) {
        pthread_join(c->worker, NULL);
        c->worker_running = 0;
        atomic_store_explicit(&c->worker_done, 0, memory_order_relaxed);

        if (c->worker_rc == 0) {
            adopt_connection(c);
        } else {
            enter_backoff(c, c->worker_result.err[0] ? c->worker_result.err
                                                     : "connection failed");
        }
    }

    if (c->state == RC_CONNECTED) {
        pump_tcp(c);
        if (c->have_conn) pump_udp(c);

        if (c->have_conn) {
            if (tls_flush(&c->conn.tls) != 0) {
                enter_backoff(c, "the reflector closed the connection");
            }
        }

        if (c->have_conn && now >= c->next_tcp_hb) {
            uint8_t buf[16];
            size_t  n;
            if (proto_build_heartbeat(buf, sizeof(buf), &n) == 0) {
                if (send_frame(c, buf, n) != 0)
                    enter_backoff(c, "the reflector stopped responding");
            }
            c->next_tcp_hb = now + SVX_TCP_HEARTBEAT_MS;
        }

        if (c->have_conn && now >= c->next_udp_hb) {
            send_udp(c, UDP_MSG_HEARTBEAT, NULL, 0);
            c->next_udp_hb = now + SVX_UDP_HEARTBEAT_MS;
        }
    }

    if (c->state == RC_BACKOFF && !c->user_stopped &&
        c->backoff_until > 0 && now >= c->backoff_until) {
        c->backoff_until = 0;
        begin_connect(c);
    }

    tick_stats(c, now);
}

/* ---------------------------------------------------------- accessors */

rc_state    rc_get_state(const rc_client *c)  { return c->state; }
uint16_t    rc_client_id(const rc_client *c)  { return c->have_conn ? c->conn.client_id : 0; }
int         rc_node_count(const rc_client *c) { return c->have_conn ? c->conn.node_count : 0; }
const char *rc_host(const rc_client *c)       { return c->have_conn ? c->conn.host : c->cfg->reflector; }
uint16_t    rc_port(const rc_client *c)       { return c->have_conn ? c->conn.port : (uint16_t)c->cfg->port; }
uint32_t    rc_current_tg(const rc_client *c) { return c->selected_tg; }
const char *rc_last_error(const rc_client *c) { return c->last_error; }

void rc_get_stats(const rc_client *c, rc_stats *out) { *out = c->stats; }
