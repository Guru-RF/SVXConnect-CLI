/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "handshake.h"
#include "cert.h"
#include "nodeinfo.h"
#include "frameio.h"

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
#include <time.h>
#include <poll.h>
#include <sys/socket.h>

#define HS_BUF        (256 * 1024)   /* must hold a whole CA bundle frame */
#define HS_CONNECT_MS  10000
#define HS_STEP_MS     15000         /* per-message patience once connected */

#define FAIL(r, ...) do { snprintf((r)->err, sizeof((r)->err), __VA_ARGS__); goto fail; } while (0)

/* ------------------------------------------------------------- the flow */

#define ABORTED(f) ((f) && atomic_load(f))

int handshake_run(const svx_config *cfg, handshake_result *out,
                  const atomic_int *abort_flag) {
    return handshake_run_ex(cfg, out, abort_flag, NULL);
}

int handshake_run_ex(const svx_config *cfg, handshake_result *out,
                     const atomic_int *abort_flag, const char *rejected_fp) {
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

    /* ---- 2. certificate material must exist before we bother connecting ----
     * An expired certificate is not presented at all: the reflector would
     * refuse it in the TLS handshake. Connecting without one makes it ask for
     * a CSR instead, which is how an expired certificate gets replaced. */
    char ca_path[1024];
    snprintf(ca_path, sizeof(ca_path), "%s/ca-bundle.crt", cfg->pki_dir);

    cert_state cs;
    cert_assess(cfg, time(NULL), &cs, 1);

    if (!pki_file_exists(cs.key_path) || cs.status == PKI_CERT_MISSING) {
        FAIL(out, "no certificate for %s in %s — run 'svxconnect --enroll'",
             cfg->callsign, cfg->pki_dir);
    }
    if (cs.status == PKI_CERT_INVALID) {
        FAIL(out, "%s is not a readable certificate — move it aside and run "
             "'svxconnect --enroll'", cs.cert_path);
    }
    if (pki_check_pair(cs.cert_path, cs.key_path) != 0) {
        FAIL(out, "the certificate and key in %s do not match", cfg->pki_dir);
    }
    /* A certificate the reflector refused in an earlier TLS handshake is
     * left out just like an expired one, while it is still the one on disk:
     * we cannot tell what is wrong with it from here (revoked or removed on
     * the reflector, or a clock that disagrees), only that it will not do. */
    const int refused = rejected_fp && rejected_fp[0] && cs.info.fingerprint[0] &&
                        strcmp(cs.info.fingerprint, rejected_fp) == 0;
    const int present_cert = (cs.status != PKI_CERT_EXPIRED) && !refused;
    int       sent_csr     = 0;
    if (refused)
        log_info("not presenting the certificate the reflector refused; "
                 "asking it for a new one with the same key");

    /* What the new certificate is for, in the failure the user sees while
     * the request waits for the sysop. */
    char need[96];
    if (refused) {
        snprintf(need, sizeof(need), "the reflector refused our certificate");
    } else {
        char na[32];
        pki_format_time(cs.info.not_after, na, sizeof(na));
        snprintf(need, sizeof(need), "certificate expired on %s", na);
    }

    /* ---- 3. TCP ---- */
    if (ABORTED(abort_flag)) FAIL(out, "cancelled");
    out->tcp_fd = net_tcp_connect_ex(out->host, out->port, HS_CONNECT_MS, NULL, abort_flag);
    if (out->tcp_fd < 0) {
        if (errno == ECANCELED) FAIL(out, "cancelled");
        FAIL(out, "cannot reach %s:%u (%s)", out->host, out->port, strerror(errno));
    }
    log_info("connected to %s:%u", out->host, out->port);

    /* ---- 4. announce the protocol version, in the clear ---- */
    size_t blen;
    if (proto_build_proto_ver(buf, HS_BUF, &blen) != 0) FAIL(out, "internal: ProtoVer");
    if (fio_raw_send(out->tcp_fd, buf, blen) != 0) FAIL(out, "connection lost sending ProtoVer");

    /* ---- 5. pre-TLS: fetch the CA bundle, then ask to start encryption ----
     * The server drives this. We answer heartbeats, request the bundle when it
     * advertises one, save it, and then ask for TLS. */
    int started_tls = 0;
    while (!started_tls) {
        if (ABORTED(abort_flag)) FAIL(out, "cancelled");

        ssize_t L = fio_raw_recv_frame(out->tcp_fd, buf, HS_BUF, HS_STEP_MS, abort_flag);
        if (L < 0 && errno == ECANCELED) FAIL(out, "cancelled");
        if (L < 0) FAIL(out, "no response from %s (%s)", out->host, strerror(errno));
        if (L < 2) continue;

        uint16_t type = be_get_u16(buf);
        switch (type) {
        case MSG_HEARTBEAT:
            if (proto_build_heartbeat(buf, HS_BUF, &blen) != 0) FAIL(out, "internal: Heartbeat");
            if (fio_raw_send(out->tcp_fd, buf, blen) != 0) FAIL(out, "connection lost");
            break;

        case MSG_CA_INFO:
            if (proto_build_ca_bundle_req(buf, HS_BUF, &blen) != 0) FAIL(out, "internal: CABundleReq");
            if (fio_raw_send(out->tcp_fd, buf, blen) != 0) FAIL(out, "connection lost");
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
            if (fio_raw_send(out->tcp_fd, buf, blen) != 0) FAIL(out, "connection lost");
            break;
        }

        case MSG_START_ENCRYPTION:
            out->ssl_ctx = tls_make_ctx(ca_path,
                                        present_cert ? cs.cert_path : NULL,
                                        present_cert ? cs.key_path  : NULL);
            if (!out->ssl_ctx) FAIL(out, "cannot load the certificate for %s", cfg->callsign);
            if (tls_start_ex(&out->tls, out->ssl_ctx, out->tcp_fd, HS_STEP_MS, abort_flag) != 0) {
                if (errno == ECANCELED) FAIL(out, "cancelled");
                if (errno == ETIMEDOUT)
                    FAIL(out, "TLS handshake with %s timed out", out->host);
                char why[200];
                tls_close_describe(&out->tls, why, sizeof(why));
                if (present_cert && tls_cert_rejected(&out->tls)) {
                    /* It looks valid here, yet the reflector will not have
                     * it. Retrying with it can only fail the same way, so
                     * the next attempt asks for a new one instead. */
                    char na[32];
                    pki_format_time(cs.info.not_after, na, sizeof(na));
                    log_warn("the reflector refused our certificate in the TLS handshake (%s), "
                             "although it is valid here until %s. It may have been revoked or "
                             "removed on the reflector, or one of the two clocks is wrong. "
                             "Asking the reflector for a new certificate with the same key.",
                             why, na);
                    snprintf(out->cert_rejected, sizeof(out->cert_rejected), "%s",
                             cs.info.fingerprint);
                    FAIL(out, "the reflector refused our certificate (%s) — requesting a new one",
                         why);
                }
                FAIL(out, "TLS handshake with %s failed (%s)", out->host, why);
            }
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
        if (ABORTED(abort_flag)) FAIL(out, "cancelled");

        ssize_t L = fio_tls_recv_frame(&out->tls, buf, HS_BUF, HS_STEP_MS, abort_flag);
        if (L < 0) {
            if (errno == ECANCELED) FAIL(out, "cancelled");
            if (sent_csr) {
                /* The reflector hangs up after taking a request it cannot sign
                 * by itself. That is the normal answer until the sysop has
                 * signed. */
                FAIL(out, "%s; new one requested — waiting for "
                     "the reflector sysop to sign it", need);
            }
            if (tls_failed(&out->tls)) {
                char why[200];
                FAIL(out, "login failed (%s)", tls_close_describe(&out->tls, why, sizeof(why)));
            }
            FAIL(out, "login failed (%s)", strerror(errno));
        }
        if (L < 2) continue;

        uint16_t type = be_get_u16(buf);
        switch (type) {
        case MSG_HEARTBEAT:
            if (proto_build_heartbeat(buf, HS_BUF, &blen) != 0) FAIL(out, "internal: Heartbeat");
            if (fio_tls_send(&out->tls, buf, blen) != 0) FAIL(out, "connection lost");
            break;

        case MSG_AUTH_CHALLENGE: {
            /* The digest is twenty zero bytes: the mutual TLS certificate is
             * the real authentication, and this message is vestigial. */
            uint8_t digest[20];
            memset(digest, 0, sizeof(digest));
            if (proto_build_auth_response(buf, HS_BUF, &blen, cfg->callsign, digest) != 0)
                FAIL(out, "internal: AuthResponse");
            if (fio_tls_send(&out->tls, buf, blen) != 0) FAIL(out, "connection lost");
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
            if (fio_tls_send(&out->tls, buf, blen) != 0) FAIL(out, "connection lost");
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
                if (crypto_use_tx_for_rx(&out->crypto) != 0)
                    FAIL(out, "the reflector assigned client id 0 with a shared UDP key, "
                              "which would reuse AES-GCM nonces — refusing");
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

        case MSG_CLIENT_CSR_REQUEST: {
            /* Asked for when we connected without a certificate. Always from
             * the key we already have: the reflector treats a new key for a
             * known callsign as a hijack attempt. */
            if (pki_ensure_csr(cs.key_path, cs.csr_path, cfg->callsign, cfg->email) != 0)
                FAIL(out, "cannot prepare a certificate request in %s", cfg->pki_dir);
            size_t csr_len = 0;
            char  *csr_pem = read_file(cs.csr_path, &csr_len);
            if (!csr_pem) FAIL(out, "cannot read %s", cs.csr_path);
            int built = proto_build_client_csr(buf, HS_BUF, &blen, csr_pem, csr_len);
            free(csr_pem);
            if (built != 0) FAIL(out, "internal: ClientCsr");
            if (fio_tls_send(&out->tls, buf, blen) != 0) FAIL(out, "connection lost");
            sent_csr = 1;
            log_info("certificate request for %s sent to the reflector", cfg->callsign);
            break;
        }

        case MSG_CLIENT_CERT: {
            /* Either the answer to our request or a renewal pushed at login.
             * Both ways the reflector ignores the rest of this session, so the
             * login ends here and the next one uses whatever is on disk. */
            pki_push_result r = cert_handle_push(cfg, buf, (size_t)L, time(NULL));
            if (r == PKI_PUSH_STORED) {
                out->cert_renewed = 1;
                FAIL(out, "new certificate stored — reconnecting to use it");
            }
            if (r == PKI_PUSH_EMPTY && sent_csr) {
                FAIL(out, "%s; new one requested — waiting "
                     "for the reflector sysop to sign it", need);
            }
            if (r == PKI_PUSH_SAME && refused) {
                /* It refused this certificate and then hands it back as
                 * current. Try it once more, as SvxLink-Broadcast does: a
                 * reflector that reloaded its CA may take it now. */
                out->cert_retry = 1;
                FAIL(out, "the reflector refused our certificate but sends the same one back — "
                     "check the clock here and on the reflector, or ask its sysop to remove "
                     "and re-sign the certificate for %s", cfg->callsign);
            }
            FAIL(out, "the reflector sent an unusable certificate — see the log");
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
