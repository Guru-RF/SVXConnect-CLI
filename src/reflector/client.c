/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "client.h"
#include "cert.h"
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
#include <time.h>
#include <sys/socket.h>

#define RC_MAX_FRAME   (256 * 1024)
#define RC_UDP_MTU     2048
#define RC_MAX_MONITOR 64

/* The reflector sends a TCP heartbeat after about 10 s without other traffic,
 * so 30 s of silence is three missed beats: the path or the server is gone
 * even if the kernel has not noticed yet (it would keep retransmitting into a
 * dead NAT mapping for ~15 min). */
#define RC_RX_TIMEOUT_MS 30000

/* The reflector sends a UDP heartbeat about every 15 s between overs (the
 * user's log: four datagrams a minute). A minute without one while the control
 * channel is fine means the UDP path closed under us — a NAT mapping that
 * expired, a firewall change — and audio no longer reaches us, silently. A
 * new login opens a new mapping. */
#define RC_UDP_RX_TIMEOUT_MS 60000

/* A MsgError this recent is taken to be the reason for the close that
 * follows it. */
#define RC_ERROR_REASON_MS 30000

/* How long rc_free() gives an aborted worker to finish. Bounded: the worker
 * may be stuck in name resolution, which cannot be interrupted. */
#define RC_FREE_GRACE_MS 500

/* Reconnect backoff, in seconds. The first two are short because the common
 * case is a brief network blip; after that we stop hammering the reflector. */
static const int BACKOFF_S[] = { 3, 3, 5, 10, 20, 30, 60 };
#define N_BACKOFF ((int)(sizeof(BACKOFF_S) / sizeof(BACKOFF_S[0])))

/* One connect attempt, shared by the worker thread and the client.
 *
 * The client never waits for a worker. Stopping or restarting while one runs
 * sets `abort` and lets go of the job; the worker notices within ~100 ms (or,
 * inside name resolution, whenever that returns), releases whatever it built
 * and frees the job when it drops the last reference. Joining it instead froze
 * the caller — the GUI thread — for up to 15 s, or forever in SSL_connect.
 *
 * So that an abandoned worker depends on nothing the client owns, it works on
 * its own copy of the configuration, and it only writes the client's wake pipe
 * while `wake_fd` (guarded by `mu`) still names it. */
typedef struct {
    pthread_mutex_t  mu;
    int              refs;            /* worker + client; guarded by mu      */
    int              wake_fd;         /* -1 once the client let go; by mu    */
    atomic_int       abort;
    atomic_int       done;            /* result published (release/acquire)  */
    int              claimed;         /* the client adopted the result       */
    int              rc;
    handshake_result result;
    svx_config       cfg;
    char             rejected_fp[65]; /* copy of rc_client.cert_rejected */
} rc_job;

struct rc_client {
    const svx_config *cfg;
    rc_callbacks      cb;

    rc_state          state;
    char              last_error[320];

    handshake_result  conn;          /* valid only while RC_CONNECTED */
    int               have_conn;
    uint64_t          conn_since;    /* when it was adopted             */
    uint64_t          last_tcp_rx;   /* last complete TCP frame         */
    uint64_t          last_udp_rx;   /* last authenticated datagram     */
    int               rx_timeout_ms; /* 0 disables the watchdog         */
    int               udp_rx_timeout_ms; /* 0 disables the UDP watchdog */
    int               udp_seen;      /* a datagram arrived this session */
    int               udp_never_warned; /* said so once, when none ever did */
    int               rekey_needed;  /* the UDP counter ran out         */

    /* The certificate the reflector refused in a TLS handshake. Kept across
     * attempts, so that every later login goes without it and asks for a new
     * one, until one is stored or the file on disk changes. */
    char              cert_rejected[65];

    /* The reflector's most recent MsgError, kept to explain a close. */
    char              server_error[256];
    uint64_t          server_error_at;

    /* A connection dropped by rc_stop()/rc_reconnect_now(), which may run
     * outside rc_service(). Its sockets stay open until the next rc_service()
     * closes them: rc_client.h promises the descriptor set only changes inside
     * the service call, and an embedding event loop (Qt) still has notifiers
     * armed on them until then. */
    handshake_result  closing;
    int               have_closing;

    /* connect worker */
    rc_job           *job;           /* the attempt in flight, or NULL */
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

static void reset_result(handshake_result *r) {
    memset(r, 0, sizeof(*r));
    r->tcp_fd = r->udp_fd = -1;
    r->tls.fd = -1;
}

rc_client *rc_new(const svx_config *cfg, const rc_callbacks *cb) {
    rc_client *c = calloc(1, sizeof(*c));
    if (!c) return NULL;

    c->cfg   = cfg;
    c->cb    = *cb;
    c->state = RC_IDLE;
    c->rx_timeout_ms = RC_RX_TIMEOUT_MS;
    c->udp_rx_timeout_ms = RC_UDP_RX_TIMEOUT_MS;

    c->frame = malloc(RC_MAX_FRAME);
    if (!c->frame) { free(c); return NULL; }

    if (pipe(c->wake_pipe) != 0) { free(c->frame); free(c); return NULL; }
    net_set_nonblock(c->wake_pipe[0]);
    net_set_nonblock(c->wake_pipe[1]);

    reset_result(&c->conn);
    reset_result(&c->closing);
    return c;
}

static void wake(rc_client *c) {
    ssize_t ignored = write(c->wake_pipe[1], "w", 1);
    (void)ignored;
}

/* Close what a previous rc_stop()/rc_reconnect_now() set aside. Called from
 * inside rc_service() only (and rc_free()). */
static void close_deferred(rc_client *c) {
    if (!c->have_closing) return;
    handshake_release(&c->closing);
    reset_result(&c->closing);
    c->have_closing = 0;
}

/* Drop the current connection. Inside rc_service() its sockets close at once;
 * from an action they are set aside for the next rc_service(), and the loop
 * is woken so that happens promptly. */
static void drop_connection(rc_client *c, int in_service) {
    if (!c->have_conn) return;
    if (in_service) {
        handshake_release(&c->conn);
    } else {
        if (c->have_closing) handshake_release(&c->closing);   /* cannot happen: service ran in between */
        c->closing      = c->conn;
        c->have_closing = 1;
        wake(c);
    }
    reset_result(&c->conn);
    c->have_conn = 0;
}

/* Drop one reference to a job; the last one out frees it, and releases a
 * successful result nobody adopted. */
static void job_unref(rc_job *j) {
    pthread_mutex_lock(&j->mu);
    int last = (--j->refs == 0);
    pthread_mutex_unlock(&j->mu);
    if (!last) return;
    if (j->rc == 0 && !j->claimed) handshake_release(&j->result);
    pthread_mutex_destroy(&j->mu);
    free(j);
}

/* Stop caring about the attempt in flight without waiting for it. */
static void abandon_worker(rc_client *c) {
    rc_job *j = c->job;
    if (!j) return;
    c->job = NULL;
    atomic_store(&j->abort, 1);
    pthread_mutex_lock(&j->mu);
    j->wake_fd = -1;               /* from now on the worker leaves the client alone */
    pthread_mutex_unlock(&j->mu);
    job_unref(j);
}

void rc_free(rc_client *c) {
    if (!c) return;
    if (c->job) {
        /* Give an aborted worker a moment to finish, so that it is not still
         * inside OpenSSL while the process tears down — but a bounded one,
         * and without joining: it may be stuck in DNS. */
        rc_job *j = c->job;
        atomic_store(&j->abort, 1);
        uint64_t until = now_ms() + RC_FREE_GRACE_MS;
        while (!atomic_load_explicit(&j->done, memory_order_acquire) && now_ms() < until)
            msleep(10);
        abandon_worker(c);
    }
    drop_connection(c, 1);
    close_deferred(c);
    if (c->wake_pipe[0] >= 0) close(c->wake_pipe[0]);
    if (c->wake_pipe[1] >= 0) close(c->wake_pipe[1]);
    free(c->frame);
    free(c);
}

/* --------------------------------------------------------- the worker */

static void *worker_main(void *arg) {
    rc_job *j = arg;
    j->rc = handshake_run_ex(&j->cfg, &j->result, &j->abort, j->rejected_fp);

    /* Publish the result, then flag done with a RELEASE store, then wake the
     * loop. The main thread reads `done` with an acquire load, which is what
     * makes rc and result visible to it: nothing ever joins this thread. */
    pthread_mutex_lock(&j->mu);
    atomic_store_explicit(&j->done, 1, memory_order_release);
    if (j->wake_fd >= 0) {
        ssize_t ignored = write(j->wake_fd, "c", 1);
        (void)ignored;
    }
    pthread_mutex_unlock(&j->mu);

    job_unref(j);
    return NULL;
}

static void begin_connect(rc_client *c) {
    if (c->job) return;

    rc_job *j = calloc(1, sizeof(*j));
    if (!j) goto fail;
    pthread_mutex_init(&j->mu, NULL);
    j->refs    = 2;
    j->wake_fd = c->wake_pipe[1];
    j->rc      = -1;
    j->cfg     = *c->cfg;
    snprintf(j->rejected_fp, sizeof(j->rejected_fp), "%s", c->cert_rejected);
    reset_result(&j->result);

    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_t th;
    int prc = pthread_create(&th, &at, worker_main, j);
    pthread_attr_destroy(&at);
    if (prc != 0) {
        pthread_mutex_destroy(&j->mu);
        free(j);
        goto fail;
    }
    c->job = j;
    set_state(c, RC_CONNECTING, NULL);
    return;

fail:
    snprintf(c->last_error, sizeof(c->last_error), "cannot start the connect thread");
    set_state(c, RC_BACKOFF, c->last_error);
    c->backoff_until = now_ms() + 5000;
}

void rc_start(rc_client *c) {
    c->user_stopped = 0;
    if (c->state == RC_CONNECTED || c->state == RC_CONNECTING) return;
    c->backoff_idx = 0;
    begin_connect(c);
}

void rc_stop(rc_client *c, const char *reason) {
    c->user_stopped = 1;
    abandon_worker(c);
    drop_connection(c, 0);
    snprintf(c->last_error, sizeof(c->last_error), "%s", reason ? reason : "disconnected");
    set_state(c, RC_IDLE, c->last_error);
}

void rc_reconnect_now(rc_client *c) {
    c->user_stopped = 0;
    abandon_worker(c);
    drop_connection(c, 0);
    c->backoff_idx   = 0;
    c->backoff_until = 0;
    begin_connect(c);
}

void rc_set_rx_timeout(rc_client *c, int ms) { c->rx_timeout_ms = ms > 0 ? ms : 0; }
void rc_set_udp_rx_timeout(rc_client *c, int ms) { c->udp_rx_timeout_ms = ms > 0 ? ms : 0; }

/* Schedule the next attempt after losing (or failing to make) a connection. */
static void enter_backoff(rc_client *c, const char *why) {
    drop_connection(c, 1);
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
    if (wn < 0) {
        /* May be called from outside rc_service() (the TX path), so only flag
         * it; rc_service() reconnects, which brings a fresh key. */
        if (crypto_tx_exhausted(&c->conn.crypto)) c->rekey_needed = 1;
        return -1;
    }

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
            /* Usually the last thing before the reflector hangs up; keep it
             * so the close can say why. */
            snprintf(c->server_error, sizeof(c->server_error), "%s", e);
            c->server_error_at = now_ms();
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

    case MSG_CLIENT_CERT: {
        /* The reflector renews a certificate past 2/3 of its lifetime by
         * pushing it here, about ten minutes into a session — and ignores
         * everything else on that session afterwards. So reconnect whatever
         * the outcome: straight away with a new certificate, through the
         * normal backoff otherwise. */
        pki_push_result r = cert_handle_push(c->cfg, body, len, time(NULL));
        if (r == PKI_PUSH_STORED) {
            log_info("reconnecting to log in with the renewed certificate");
            rc_reconnect_now(c);
        } else {
            enter_backoff(c, "the reflector sent a certificate we cannot use");
        }
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

/* "4m51s" */
static void fmt_span(char *dst, size_t cap, uint64_t ms) {
    uint64_t s = ms / 1000;
    if (s >= 3600)    snprintf(dst, cap, "%lluh%02llum", (unsigned long long)(s / 3600),
                               (unsigned long long)(s % 3600 / 60));
    else if (s >= 60) snprintf(dst, cap, "%llum%02llus", (unsigned long long)(s / 60),
                               (unsigned long long)(s % 60));
    else              snprintf(dst, cap, "%.1fs", (double)ms / 1000.0);
}

/* The control channel failed: say how, as precisely as the socket and the
 * reflector let us, and schedule the reconnect. Every failure used to read
 * "the reflector closed the connection", whether it was the server hanging
 * up, a reset, a TLS alert or our own buffer limit — and the reflector's own
 * reason, sent just before it closed, was thrown away. */
static void connection_lost(rc_client *c) {
    const tls_conn_t *t   = &c->conn.tls;
    uint64_t          now = now_ms();

    const char *what;
    switch (t->close_kind) {
    case TLS_CLOSE_NOTIFY:
    case TLS_CLOSE_EOF:     what = "the reflector closed the connection"; break;
    case TLS_CLOSE_RESET:   what = "the connection was reset";            break;
    case TLS_CLOSE_NETWORK: what = "the connection failed";               break;
    case TLS_CLOSE_ALERT:   what = "the TLS session failed";              break;
    case TLS_CLOSE_LOCAL:   what = "dropped the connection";              break;
    default:                what = "the connection was lost";             break;
    }

    char reason[300] = "";
    if (c->server_error[0] && now - c->server_error_at <= RC_ERROR_REASON_MS)
        snprintf(reason, sizeof(reason), ": %s", c->server_error);

    char how[200], age[32], quiet[32];
    tls_close_describe(t, how, sizeof(how));
    fmt_span(age,   sizeof(age),   now - c->conn_since);
    fmt_span(quiet, sizeof(quiet), now - c->last_tcp_rx);

    char msg[sizeof(c->last_error)];
    snprintf(msg, sizeof(msg), "%s%s (%s; after %s, last data %s ago)",
             what, reason, how, age, quiet);
    enter_backoff(c, msg);
}

static void pump_tcp(rc_client *c) {
    if (!c->have_conn) return;

    int r = tls_pump_in(&c->conn.tls);

    /* Drain every complete frame we now hold — even when the read also found
     * the connection closed: the reflector's parting MsgError arrives in the
     * same breath as its close. One TLS record can carry several frames, and
     * poll() cannot see the ones already inside OpenSSL. */
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
        c->last_tcp_rx = now_ms();

        handle_frame(c, c->frame, L);
        if (!c->have_conn) return;   /* handle_frame may have torn us down */
    }

    if (r < 0 || tls_failed(&c->conn.tls)) connection_lost(c);
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
        c->last_udp_rx = now_ms();
        c->udp_seen    = 1;
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

    if (c->have_closing) return 0;   /* sockets waiting to be closed */

    if (c->state == RC_CONNECTED) {
        if (c->next_tcp_hb < next) next = c->next_tcp_hb;
        if (c->next_udp_hb < next) next = c->next_udp_hb;
        if (c->rx_timeout_ms > 0) {
            uint64_t dead = c->last_tcp_rx + (uint64_t)c->rx_timeout_ms;
            if (dead < next) next = dead;
        }
        if (c->udp_rx_timeout_ms > 0 && (c->udp_seen || !c->udp_never_warned)) {
            uint64_t dead = c->last_udp_rx + (uint64_t)c->udp_rx_timeout_ms;
            if (dead < next) next = dead;
        }
    } else if (c->state == RC_BACKOFF && c->backoff_until > 0) {
        if (c->backoff_until < next) next = c->backoff_until;
    }
    if (next <= now) return 0;
    uint64_t d = next - now;
    return d > 1000 ? 1000 : (int)d;
}

/* ------------------------------------------------------------ service */

static void adopt_connection(rc_client *c, handshake_result *r) {
    c->conn      = *r;
    c->have_conn = 1;
    reset_result(r);

    c->backoff_idx = 0;
    uint64_t now   = now_ms();
    c->next_tcp_hb = now + SVX_TCP_HEARTBEAT_MS;
    c->next_udp_hb = now + SVX_UDP_HEARTBEAT_MS;
    c->conn_since  = c->last_tcp_rx = c->last_udp_rx = now;
    c->rekey_needed    = 0;
    c->udp_seen        = 0;
    c->udp_never_warned = 0;
    c->server_error[0] = '\0';
    c->cert_rejected[0] = '\0';     /* whatever we presented was taken */

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

    /* Sockets an action dropped since the last pass: close them now, where
     * the embedding loop expects descriptors to change. */
    close_deferred(c);

    /* Has the connect worker finished? Acquire, to pair with the worker's
     * release store and see everything it published. */
    rc_job *j = c->job;
    if (j && atomic_load_explicit(&j->done, memory_order_acquire)) {
        c->job = NULL;
        if (j->rc == 0) {
            j->claimed = 1;
            adopt_connection(c, &j->result);
        } else {
            /* A certificate stored during login ends that login on purpose;
             * the retry should be the shortest one, not the next step up. */
            if (j->result.cert_renewed) c->backoff_idx = 0;
            /* Refused: the next attempt asks for a new certificate, and
             * should come as soon as a renewal's would. */
            if (j->result.cert_rejected[0]) {
                snprintf(c->cert_rejected, sizeof(c->cert_rejected), "%s",
                         j->result.cert_rejected);
                c->backoff_idx = 0;
            }
            if (j->result.cert_renewed || j->result.cert_retry) c->cert_rejected[0] = '\0';
            enter_backoff(c, j->result.err[0] ? j->result.err : "connection failed");
        }
        pthread_mutex_lock(&j->mu);
        j->wake_fd = -1;
        pthread_mutex_unlock(&j->mu);
        job_unref(j);
    }

    if (c->state == RC_CONNECTED) {
        pump_tcp(c);
        if (c->have_conn) pump_udp(c);

        if (c->have_conn && tls_flush(&c->conn.tls) != 0) connection_lost(c);

        if (c->have_conn && now >= c->next_tcp_hb) {
            uint8_t buf[16];
            size_t  n;
            if (proto_build_heartbeat(buf, sizeof(buf), &n) == 0) {
                if (send_frame(c, buf, n) != 0) connection_lost(c);
            }
            c->next_tcp_hb = now + SVX_TCP_HEARTBEAT_MS;
        }

        /* Receive watchdog. Sending proves nothing on a half-open connection:
         * the kernel queues our heartbeats happily until TCP gives up, which
         * takes about 15 minutes, while the UI says "connected" and no audio
         * arrives. The reflector speaks at least every 10 s. */
        if (c->have_conn && c->rx_timeout_ms > 0) {
            uint64_t t = now_ms();
            if (t - c->last_tcp_rx >= (uint64_t)c->rx_timeout_ms) {
                char msg[160], age[32];
                fmt_span(age, sizeof(age), t - c->conn_since);
                snprintf(msg, sizeof(msg),
                         "no data from the reflector for %d s (after %s) — assuming the link is dead",
                         c->rx_timeout_ms / 1000, age);
                enter_backoff(c, msg);
            }
        }

        /* The same for the audio path. The control channel can stay up while
         * UDP dies — the two take separate NAT mappings, and TCP's is kept
         * alive by traffic the UDP one never sees. Only once UDP has worked
         * this session, though: a reflector (or network) that never sends
         * any would otherwise be reconnected every minute for nothing. That
         * case is said once, plainly, instead. */
        if (c->have_conn && c->udp_rx_timeout_ms > 0) {
            uint64_t t = now_ms();
            if (t - c->last_udp_rx >= (uint64_t)c->udp_rx_timeout_ms) {
                char age[32];
                fmt_span(age, sizeof(age), t - c->conn_since);
                if (c->udp_seen) {
                    char msg[240];
                    snprintf(msg, sizeof(msg),
                             "no UDP from the reflector for %d s while the control channel "
                             "is up (after %s) — the audio path is gone (NAT mapping expired "
                             "or a firewall change?); logging in again",
                             c->udp_rx_timeout_ms / 1000, age);
                    enter_backoff(c, msg);
                } else if (!c->udp_never_warned) {
                    c->udp_never_warned = 1;
                    log_warn("nothing received over UDP from %s:%u in the %s since login — "
                             "audio cannot reach this machine; a firewall or NAT may be "
                             "blocking UDP", c->conn.host, c->conn.port, age);
                }
            }
        }

        if (c->have_conn && c->rekey_needed)
            enter_backoff(c, "the UDP key has been used up — reconnecting for a new one");

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
