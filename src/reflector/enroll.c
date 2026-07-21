/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "enroll.h"
#include "frameio.h"

#include "common/log.h"
#include "common/net.h"
#include "common/pki.h"
#include "common/proto.h"
#include "common/tls.h"
#include "common/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

#define EN_BUF       (256 * 1024)
#define EN_CONNECT_MS 10000
#define EN_STEP_MS    20000

static volatile sig_atomic_t g_stop;

static void on_signal(int sig) { (void)sig; g_stop = 1; }

/* One connect-and-ask cycle.
 * Returns 0 when the certificate arrived, 1 to try again later, -1 fatal. */
static int attempt(const svx_config *cfg, int *out_sent_csr) {
    int         rc      = 1;
    int         fd      = -1;
    SSL_CTX    *ssl_ctx = NULL;
    uint8_t    *buf     = NULL;
    tls_conn_t  tls;

    memset(&tls, 0, sizeof(tls));
    tls.fd = -1;                    /* NOT 0 — tls_close() would close stdin */

    buf = malloc(EN_BUF);
    if (!buf) { log_err("out of memory"); return -1; }

    char host[256];
    uint16_t port = (uint16_t)cfg->port;
    snprintf(host, sizeof(host), "%s", cfg->reflector);

    svx_srv srv[SVX_MAX_SRV];
    if (net_srv_resolve(cfg->reflector, srv, SVX_MAX_SRV) > 0) {
        snprintf(host, sizeof(host), "%s", srv[0].host);
        port = srv[0].port;
        log_dbg("SRV %s -> %s:%u", cfg->reflector, host, port);
    }

    char ca_path[1024], key_path[1024], csr_path[1024], cert_path[1024];
    snprintf(ca_path, sizeof(ca_path), "%s/ca-bundle.crt", cfg->pki_dir);
    pki_build_path(key_path,  sizeof(key_path),  cfg->pki_dir, cfg->callsign, "key");
    pki_build_path(csr_path,  sizeof(csr_path),  cfg->pki_dir, cfg->callsign, "csr");
    pki_build_path(cert_path, sizeof(cert_path), cfg->pki_dir, cfg->callsign, "crt");

    fd = net_tcp_connect(host, port, EN_CONNECT_MS, NULL);
    if (fd < 0) goto done;

    size_t blen;
    if (proto_build_proto_ver(buf, EN_BUF, &blen) != 0) { rc = -1; goto done; }
    if (fio_raw_send(fd, buf, blen) != 0) goto done;

    while (!g_stop) {
        ssize_t L = fio_recv_frame(&tls, fd, buf, EN_BUF, EN_STEP_MS, &g_stop);
        if (L < 0) {
            if (errno == ETIMEDOUT) log_dbg("no reply within %d s", EN_STEP_MS / 1000);
            else                    log_dbg("connection closed (%s)", strerror(errno));
            goto done;
        }
        if (L < 2) continue;

        uint16_t type = be_get_u16(buf);
        log_dbg("<- %s (%u), %zd bytes", proto_msg_name(type), type, L);

        switch (type) {
        case MSG_HEARTBEAT:
            if (proto_build_heartbeat(buf, EN_BUF, &blen) == 0)
                fio_send(&tls, fd, buf, blen);
            break;

        case MSG_CA_INFO:
            if (proto_build_ca_bundle_req(buf, EN_BUF, &blen) != 0) { rc = -1; goto done; }
            if (fio_send(&tls, fd, buf, blen) != 0) goto done;
            break;

        case MSG_CA_BUNDLE_RESPONSE: {
            char *pem = malloc(EN_BUF);
            if (!pem) { rc = -1; goto done; }
            if (proto_parse_pem_blob(buf, (size_t)L, pem, EN_BUF) != 0) {
                free(pem);
                log_err("the reflector sent a CA bundle that is not PEM");
                rc = -1;
                goto done;
            }
            mkdir_p(cfg->pki_dir, 0700);
            if (write_file_atomic(ca_path, pem, strlen(pem), 0644) != 0) {
                free(pem);
                log_err("cannot write %s", ca_path);
                rc = -1;
                goto done;
            }
            free(pem);
            log_info("CA bundle stored in %s", ca_path);

            if (proto_build_start_enc_req(buf, EN_BUF, &blen) != 0) { rc = -1; goto done; }
            if (fio_send(&tls, fd, buf, blen) != 0) goto done;
            break;
        }

        case MSG_START_ENCRYPTION: {
            /* Present our certificate if we already have one — a re-run after
             * the sysop has signed needs it to authenticate. On the very first
             * run there is nothing to present and the server does not expect
             * one, which is exactly why it will ask for a CSR next. */
            int have_cert = pki_file_exists(key_path) && pki_file_exists(cert_path);
            ssl_ctx = tls_make_ctx(ca_path,
                                   have_cert ? cert_path : NULL,
                                   have_cert ? key_path  : NULL);
            if (!ssl_ctx) { rc = -1; goto done; }
            if (tls_start(&tls, ssl_ctx, fd) != 0) goto done;
            log_dbg("TLS established");
            break;
        }

        case MSG_CLIENT_CSR_REQUEST: {
            if (!pki_file_exists(key_path) || !pki_file_exists(csr_path)) {
                log_info("generating a key and certificate request for %s", cfg->callsign);
                if (pki_generate_csr(key_path, csr_path, cfg->callsign, cfg->email) != 0) {
                    rc = -1;
                    goto done;
                }
            } else {
                /* Never regenerate. The sysop may be looking at the earlier
                 * request right now; replacing it would invalidate whatever
                 * they are about to sign. */
                log_dbg("reusing the existing request %s", csr_path);
            }

            size_t csr_len = 0;
            char  *csr_pem = read_file(csr_path, &csr_len);
            if (!csr_pem) { log_err("cannot read %s", csr_path); rc = -1; goto done; }

            int ok = (proto_build_client_csr(buf, EN_BUF, &blen, csr_pem, csr_len) == 0);
            free(csr_pem);
            if (!ok) { rc = -1; goto done; }
            if (fio_send(&tls, fd, buf, blen) != 0) goto done;

            *out_sent_csr = 1;
            log_info("request sent for %s <%s>", cfg->callsign, cfg->email);
            break;
        }

        case MSG_CLIENT_CERT: {
            char *pem = malloc(EN_BUF);
            if (!pem) { rc = -1; goto done; }
            if (proto_parse_pem_blob(buf, (size_t)L, pem, EN_BUF) != 0) {
                free(pem);
                log_err("the reflector sent a certificate that is not PEM");
                rc = -1;
                goto done;
            }
            if (write_file_atomic(cert_path, pem, strlen(pem), 0644) != 0) {
                free(pem);
                log_err("cannot write %s", cert_path);
                rc = -1;
                goto done;
            }
            free(pem);
            log_info("certificate stored in %s", cert_path);
            rc = 0;
            goto done;
        }

        case MSG_AUTH_CHALLENGE:
            /* The server is trying to authenticate the session. Reaching this
             * during enrolment means our certificate is not signed yet — it is
             * NOT success, and treating it as such is the classic bug here.
             * Answer so we are not dropped, then let the loop time out and
             * retry later. */
            if (*out_sent_csr) {
                log_info("request delivered, waiting for the sysop to sign it");
            }
            {
                uint8_t digest[20];
                memset(digest, 0, sizeof(digest));
                if (proto_build_auth_response(buf, EN_BUF, &blen, cfg->callsign, digest) == 0)
                    fio_send(&tls, fd, buf, blen);
            }
            break;

        case MSG_AUTH_OK:
            /* We authenticated, so a valid signed certificate is already on
             * disk and being used. Nothing left to enrol. */
            if (pki_file_exists(cert_path)) {
                log_info("%s already has a valid certificate in %s",
                         cfg->callsign, cfg->pki_dir);
                rc = 0;
                goto done;
            }
            break;

        case MSG_ERROR: {
            char e[512];
            if (proto_parse_error(buf, (size_t)L, e, sizeof(e)) == 0)
                log_err("reflector: %s", e);
            goto done;
        }

        default:
            log_dbg("ignoring %s (%u)", proto_msg_name(type), type);
            break;
        }
    }

done:
    if (tls.ssl)      tls_close(&tls);
    else if (fd >= 0) close(fd);
    if (ssl_ctx)      SSL_CTX_free(ssl_ctx);
    free(buf);
    return rc;
}

int enroll_run(const svx_config *cfg, int retry_seconds) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (mkdir_p(cfg->pki_dir, 0700) != 0) {
        log_err("cannot create %s: %s", cfg->pki_dir, strerror(errno));
        return -1;
    }

    char cert_path[1024], key_path[1024];
    pki_build_path(cert_path, sizeof(cert_path), cfg->pki_dir, cfg->callsign, "crt");
    pki_build_path(key_path,  sizeof(key_path),  cfg->pki_dir, cfg->callsign, "key");

    if (pki_file_exists(cert_path) && pki_file_exists(key_path) &&
        pki_check_pair(cert_path, key_path) == 0) {
        char cn[64] = "", exp[32] = "";
        int  days = 0;
        pki_cert_info(cert_path, cn, sizeof(cn), exp, sizeof(exp), &days);
        log_info("%s already has a certificate, valid until %s (%d days)",
                 cn[0] ? cn : cfg->callsign, exp, days);
        log_info("delete %s to enrol again", cert_path);
        return 0;
    }

    log_info("enrolling %s with %s", cfg->callsign, cfg->reflector);
    log_info("the reflector sysop has to approve this by hand — it can take "
             "minutes or days.");
    log_info("it is safe to stop with Ctrl-C and run --enroll again later.");

    int sent_csr = 0;
    int tries    = 0;

    while (!g_stop) {
        tries++;
        int rc = attempt(cfg, &sent_csr);
        if (rc == 0) {
            char cn[64] = "", exp[32] = "";
            int  days = 0;
            pki_cert_info(cert_path, cn, sizeof(cn), exp, sizeof(exp), &days);
            log_info("enrolled. %s is valid until %s (%d days).",
                     cn[0] ? cn : cfg->callsign, exp, days);
            log_info("you can now run: svxconnect");
            return 0;
        }
        if (rc < 0) return -1;
        if (g_stop) break;

        log_info("attempt %d — not signed yet, retrying in %d s", tries, retry_seconds);

        /* Sleep in short slices so Ctrl-C is responsive. */
        for (int i = 0; i < retry_seconds * 10 && !g_stop; i++) msleep(100);
    }

    log_info("stopped. The key and request are kept in %s — run --enroll again "
             "to carry on where this left off.", cfg->pki_dir);
    return 1;
}
