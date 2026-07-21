/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — Copyright (C) 2026 Joeri Van Dooren
 */
#include "handshake.h"
#include "nodeinfo.h"

#include "common/log.h"
#include "common/net.h"
#include "common/pki.h"
#include "common/proto.h"
#include "common/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>

#define HS_BUF        (256 * 1024)   /* must hold a whole CA bundle frame */
#define HS_CONNECT_MS  10000
#define HS_STEP_MS     15000         /* per-message patience once connected */

#define FAIL(r, ...) do { snprintf((r)->err, sizeof((r)->err), __VA_ARGS__); goto fail; } while (0)

/* ------------------------------------------------- plain socket helpers */

static int raw_send_all(int fd, const uint8_t *p, size_t len) {
    while (len > 0) {
        ssize_t n = send(fd, p, len, 0);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) return -1;
        p += n; len -= (size_t)n;
    }
    return 0;
}

static int raw_recv_all(int fd, uint8_t *p, size_t len, int timeout_ms,
                        volatile sig_atomic_t *abort_flag) {
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    while (len > 0) {
        if (abort_flag && *abort_flag) return -1;

        uint64_t now = now_ms();
        if (now >= deadline) { errno = ETIMEDOUT; return -1; }

        struct pollfd pf = { .fd = fd, .events = POLLIN };
        int pr = poll(&pf, 1, (int)(deadline - now));
        if (pr < 0) { if (errno == EINTR) continue; return -1; }
        if (pr == 0) { errno = ETIMEDOUT; return -1; }

        ssize_t n = recv(fd, p, len, 0);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) { errno = ECONNRESET; return -1; }
        p += n; len -= (size_t)n;
    }
    return 0;
}

/* Read one pre-TLS frame: [u32 len][body]. Returns the body length or -1. */
static ssize_t raw_recv_frame(int fd, uint8_t *buf, size_t cap, int timeout_ms,
                              volatile sig_atomic_t *abort_flag) {
    uint8_t hdr[4];
    if (raw_recv_all(fd, hdr, 4, timeout_ms, abort_flag) != 0) return -1;
    uint32_t L = be_get_u32(hdr);
    if (L > cap) return -1;
    if (L == 0) return 0;
    if (raw_recv_all(fd, buf, L, timeout_ms, abort_flag) != 0) return -1;
    return (ssize_t)L;
}

/* ---------------------------------------------------------- TLS helpers */

/* Read one framed message over TLS, blocking with a timeout. The socket is
 * non-blocking by now, so this drives tls_pump_in() from poll(). */
static ssize_t tls_recv_frame(tls_conn_t *t, uint8_t *buf, size_t cap,
                              int timeout_ms, volatile sig_atomic_t *abort_flag) {
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;

    for (;;) {
        /* Serve a complete frame out of what we already hold before waiting
         * on the socket — one TLS record often carries several frames. */
        size_t         have = 0;
        const uint8_t *p    = tls_peek(t, &have);
        if (have >= 4) {
            uint32_t L = be_get_u32(p);
            if (L > cap) return -1;
            if (have >= 4 + (size_t)L) {
                memcpy(buf, p + 4, L);
                tls_consume(t, 4 + (size_t)L);
                return (ssize_t)L;
            }
        }

        if (abort_flag && *abort_flag) return -1;
        uint64_t now = now_ms();
        if (now >= deadline) { errno = ETIMEDOUT; return -1; }

        if (tls_flush(t) != 0) return -1;

        struct pollfd pf = {
            .fd     = t->fd,
            .events = (short)(POLLIN | (tls_want_write(t) ? POLLOUT : 0))
        };
        int pr = poll(&pf, 1, (int)(deadline - now));
        if (pr < 0) { if (errno == EINTR) continue; return -1; }
        if (pr == 0) { errno = ETIMEDOUT; return -1; }

        if (pf.revents & POLLOUT) { if (tls_flush(t) != 0) return -1; }
        if (pf.revents & (POLLIN | POLLHUP | POLLERR)) {
            if (tls_pump_in(t) < 0) return -1;
        }
    }
}

static int tls_send_frame(tls_conn_t *t, const uint8_t *buf, size_t len) {
    if (tls_queue(t, buf, len) != 0) return -1;
    if (tls_flush(t) != 0) return -1;
    /* tls_flush may leave bytes queued if the socket is full; that is fine,
     * the next tls_recv_frame() will push them. */
    return 0;
}

/* ------------------------------------------------------------- the flow */

int handshake_run(const svx_config *cfg, handshake_result *out,
                  volatile sig_atomic_t *abort_flag) {
    uint8_t *buf = NULL;

    memset(out, 0, sizeof(*out));
    out->tcp_fd  = -1;
    out->udp_fd  = -1;
    out->tls.fd  = -1;   /* NOT 0: tls_close() would close stdin */
    crypto_init(&out->crypto);

    buf = malloc(HS_BUF);
    if (!buf) { snprintf(out->err, sizeof(out->err), "out of memory"); return -1; }

    /* ---- 1. where are we going ---- */
    snprintf(out->host, sizeof(out->host), "%s", cfg->reflector);
    out->port = (uint16_t)cfg->port;

    svx_srv srv[SVX_MAX_SRV];
    int n_srv = net_srv_resolve(cfg->reflector, srv, SVX_MAX_SRV);
    if (n_srv > 0) {
        snprintf(out->host, sizeof(out->host), "%s", srv[0].host);
        out->port = srv[0].port;
        log_info("SRV %s -> %s:%u", cfg->reflector, out->host, out->port);
    }

    /* ---- 2. certificate material must exist before we bother connecting ---- */
    char ca_path[1024], key_path[1024], cert_path[1024];
    snprintf(ca_path, sizeof(ca_path), "%s/ca-bundle.crt", cfg->pki_dir);
    pki_build_path(key_path,  sizeof(key_path),  cfg->pki_dir, cfg->callsign, "key");
    pki_build_path(cert_path, sizeof(cert_path), cfg->pki_dir, cfg->callsign, "crt");

    if (!pki_file_exists(key_path) || !pki_file_exists(cert_path)) {
        FAIL(out, "no certificate for %s in %s — run 'svxconnect --enroll'",
             cfg->callsign, cfg->pki_dir);
    }
    if (pki_check_pair(cert_path, key_path) != 0) {
        FAIL(out, "the certificate and key in %s do not match", cfg->pki_dir);
    }

    /* ---- 3. TCP ---- */
    out->tcp_fd = net_tcp_connect(out->host, out->port, HS_CONNECT_MS, NULL);
    if (out->tcp_fd < 0) FAIL(out, "cannot reach %s:%u", out->host, out->port);
    log_info("connected to %s:%u", out->host, out->port);

    /* ---- 4. announce the protocol version, in the clear ---- */
    size_t blen;
    if (proto_build_proto_ver(buf, HS_BUF, &blen) != 0) FAIL(out, "internal: ProtoVer");
    if (raw_send_all(out->tcp_fd, buf, blen) != 0) FAIL(out, "connection lost sending ProtoVer");

    /* ---- 5. pre-TLS: fetch the CA bundle, then ask to start encryption ----
     * The server drives this. We answer heartbeats, request the bundle when it
     * advertises one, save it, and then ask for TLS. */
    int started_tls = 0;
    while (!started_tls) {
        if (abort_flag && *abort_flag) FAIL(out, "cancelled");

        ssize_t L = raw_recv_frame(out->tcp_fd, buf, HS_BUF, HS_STEP_MS, abort_flag);
        if (L < 0) FAIL(out, "no response from %s (%s)", out->host, strerror(errno));
        if (L < 2) continue;

        uint16_t type = be_get_u16(buf);
        switch (type) {
        case MSG_HEARTBEAT:
            if (proto_build_heartbeat(buf, HS_BUF, &blen) != 0) FAIL(out, "internal: Heartbeat");
            if (raw_send_all(out->tcp_fd, buf, blen) != 0) FAIL(out, "connection lost");
            break;

        case MSG_CA_INFO:
            if (proto_build_ca_bundle_req(buf, HS_BUF, &blen) != 0) FAIL(out, "internal: CABundleReq");
            if (raw_send_all(out->tcp_fd, buf, blen) != 0) FAIL(out, "connection lost");
            break;

        case MSG_CA_BUNDLE_RESPONSE: {
            char *pem = malloc(HS_BUF);
            if (pem) {
                if (proto_parse_pem_blob(buf, (size_t)L, pem, HS_BUF) == 0) {
                    if (write_file_atomic(ca_path, pem, strlen(pem), 0644) == 0)
                        log_dbg("stored CA bundle in %s", ca_path);
                }
                free(pem);
            }
            if (proto_build_start_enc_req(buf, HS_BUF, &blen) != 0) FAIL(out, "internal: StartEncReq");
            if (raw_send_all(out->tcp_fd, buf, blen) != 0) FAIL(out, "connection lost");
            break;
        }

        case MSG_START_ENCRYPTION:
            out->ssl_ctx = tls_make_ctx(ca_path, cert_path, key_path);
            if (!out->ssl_ctx) FAIL(out, "cannot load the certificate for %s", cfg->callsign);
            if (tls_start(&out->tls, out->ssl_ctx, out->tcp_fd) != 0)
                FAIL(out, "TLS handshake with %s failed", out->host);
            started_tls = 1;
            break;

        case MSG_PROTO_VER_DOWNGRADE: {
            uint16_t maj = 0, min = 0;
            proto_parse_proto_ver_downgrade(buf, (size_t)L, &maj, &min);
            FAIL(out, "%s speaks protocol %u.%u, this client needs %u.%u",
                 out->host, maj, min, PROTO_MAJOR, PROTO_MINOR);
        }

        case MSG_ERROR: {
            char e[512];
            if (proto_parse_error(buf, (size_t)L, e, sizeof(e)) == 0)
                FAIL(out, "%s", e);
            FAIL(out, "the reflector rejected the connection");
        }

        default:
            log_dbg("pre-TLS: ignoring %s (%u)", proto_msg_name(type), type);
            break;
        }
    }

    /* ---- 6. over TLS: authenticate, learn our client id, set up UDP ---- */
    int got_server_info = 0, got_udp = 0;
    while (!(got_server_info && got_udp)) {
        if (abort_flag && *abort_flag) FAIL(out, "cancelled");

        ssize_t L = tls_recv_frame(&out->tls, buf, HS_BUF, HS_STEP_MS, abort_flag);
        if (L < 0) FAIL(out, "login failed (%s)", strerror(errno));
        if (L < 2) continue;

        uint16_t type = be_get_u16(buf);
        switch (type) {
        case MSG_HEARTBEAT:
            if (proto_build_heartbeat(buf, HS_BUF, &blen) != 0) FAIL(out, "internal: Heartbeat");
            if (tls_send_frame(&out->tls, buf, blen) != 0) FAIL(out, "connection lost");
            break;

        case MSG_AUTH_CHALLENGE: {
            /* The digest is twenty zero bytes: the mutual TLS certificate is
             * the real authentication, and this message is vestigial. */
            uint8_t digest[20];
            memset(digest, 0, sizeof(digest));
            if (proto_build_auth_response(buf, HS_BUF, &blen, cfg->callsign, digest) != 0)
                FAIL(out, "internal: AuthResponse");
            if (tls_send_frame(&out->tls, buf, blen) != 0) FAIL(out, "connection lost");
            break;
        }

        case MSG_AUTH_OK:
            log_info("authenticated as %s", cfg->callsign);
            break;

        case MSG_SERVER_INFO: {
            uint16_t cid = 0;
            int nodes = 0, opus = 0;
            if (proto_parse_server_info(buf, (size_t)L, &cid, &nodes, &opus) != 0)
                FAIL(out, "malformed ServerInfo");
            out->client_id  = cid;
            out->node_count = nodes;
            out->have_opus  = opus;
            log_info("logged in, client id %u, %d node%s online",
                     cid, nodes, nodes == 1 ? "" : "s");

            /* Our UDP key is generated now and handed to the server inside
             * MsgNodeInfo — it is bound to the client id, so it cannot be
             * generated any earlier than this. */
            crypto_gen_tx_params(&out->crypto, cid);

            char json[2048];
            size_t jlen = nodeinfo_build_json(json, sizeof(json), cfg);
            if (proto_build_node_info(buf, HS_BUF, &blen,
                                      out->crypto.tx_iv_rand, sizeof(out->crypto.tx_iv_rand),
                                      out->crypto.tx_key,     sizeof(out->crypto.tx_key),
                                      json, jlen) != 0)
                FAIL(out, "internal: NodeInfo");
            if (tls_send_frame(&out->tls, buf, blen) != 0) FAIL(out, "connection lost");
            got_server_info = 1;
            break;
        }

        case MSG_START_UDP_ENCRYPTION: {
            uint8_t iv4[4], k16[16];
            int rc = proto_parse_start_udp_encryption(buf, (size_t)L, iv4, k16);
            if (rc == 0) {
                crypto_set_rx(&out->crypto, iv4, k16);
                log_dbg("UDP: server supplied its own receive key");
            } else if (rc == 1) {
                crypto_use_tx_for_rx(&out->crypto);
                log_dbg("UDP: server will use our key in both directions");
            } else {
                FAIL(out, "malformed StartUdpEncryption");
            }

            out->udp_fd = net_udp_create(out->host, out->port, &out->udp_remote);
            if (out->udp_fd < 0) FAIL(out, "cannot open a UDP socket");

            /* The first datagram must go out immediately: it opens the NAT
             * pinhole and, through the client id in its AAD, tells the server
             * which login this UDP flow belongs to. Without it the reflector
             * has somewhere to send audio but no idea where we are. */
            uint8_t pt[64], wire[128];
            size_t  ptlen;
            if (proto_build_udp_plaintext(pt, sizeof(pt), &ptlen,
                                          UDP_MSG_HEARTBEAT, NULL, 0) != 0)
                FAIL(out, "internal: UDP heartbeat");
            ssize_t wn = crypto_encrypt_wire(&out->crypto, pt, ptlen, wire, sizeof(wire));
            if (wn < 0) FAIL(out, "internal: UDP encrypt");
            if (sendto(out->udp_fd, wire, (size_t)wn, 0,
                       (struct sockaddr *)&out->udp_remote, sizeof(out->udp_remote)) < 0)
                FAIL(out, "cannot send UDP to %s:%u (%s)", out->host, out->port, strerror(errno));

            got_udp = 1;
            break;
        }

        case MSG_ERROR: {
            char e[512];
            if (proto_parse_error(buf, (size_t)L, e, sizeof(e)) == 0)
                FAIL(out, "%s", e);
            FAIL(out, "the reflector rejected the login");
        }

        default:
            log_dbg("login: ignoring %s (%u)", proto_msg_name(type), type);
            break;
        }
    }

    free(buf);
    return 0;

fail:
    free(buf);
    handshake_release(out);
    return -1;
}

void handshake_release(handshake_result *r) {
    if (!r) return;

    /* tls_close() closes the fd it owns. Only close tcp_fd directly when TLS
     * never took it over — otherwise this is a double close, which on a busy
     * process can close somebody else's freshly-opened socket. */
    int tls_owned_fd = (r->tls.ssl != NULL) || r->tls.handshake_done;
    tls_close(&r->tls);
    if (!tls_owned_fd && r->tcp_fd >= 0) close(r->tcp_fd);
    r->tcp_fd = -1;

    if (r->ssl_ctx) { SSL_CTX_free(r->ssl_ctx); r->ssl_ctx = NULL; }
    if (r->udp_fd >= 0) { close(r->udp_fd); r->udp_fd = -1; }
}
