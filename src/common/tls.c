/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "tls.h"
#include "net.h"
#include "log.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define TLS_IN_INITIAL   (64 * 1024)
#define TLS_IN_MAX       (1024 * 1024)   /* a CA bundle is the largest frame */
#define TLS_OUT_INITIAL  (16 * 1024)
#define TLS_OUT_MAX      (1024 * 1024)
#define TLS_HANDSHAKE_MS 15000
#define TLS_SLICE_MS     100             /* how often a waiting handshake looks at the abort flag */

void tls_global_init(void) {
    static int done = 0;
    if (done) return;
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    done = 1;
}

const char *tls_last_error(void) {
    /* Per thread: the connect worker and the main thread both format errors. */
    static _Thread_local char buf[256];
    unsigned long e = ERR_get_error();
    if (!e) return "no OpenSSL error";
    ERR_error_string_n(e, buf, sizeof(buf));
    return buf;
}

SSL_CTX *tls_make_ctx(const char *ca_bundle_path,
                      const char *cert_path,
                      const char *key_path) {
    tls_global_init();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        log_err("SSL_CTX_new failed: %s", tls_last_error());
        return NULL;
    }

    /* The reflector pins TLS 1.2. Offering 1.3 makes some servers drop the
     * connection during the handshake, so min and max are both 1.2. */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

    /* The reflector uses its own CA, and the CA bundle is fetched over the
     * very connection we are securing, so certificate verification cannot be
     * the trust anchor here. The anchor is our client certificate: the server
     * verifies us, and only a server holding the matching CA key can complete
     * the exchange. We record the peer for logging but do not refuse it. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    if (ca_bundle_path && *ca_bundle_path) {
        if (SSL_CTX_load_verify_locations(ctx, ca_bundle_path, NULL) != 1) {
            log_dbg("could not load CA bundle %s: %s (continuing)",
                    ca_bundle_path, tls_last_error());
        }
    }

    if (cert_path && key_path) {
        if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) != 1) {
            log_err("cannot load client certificate %s: %s", cert_path, tls_last_error());
            SSL_CTX_free(ctx);
            return NULL;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) != 1) {
            log_err("cannot load private key %s: %s", key_path, tls_last_error());
            SSL_CTX_free(ctx);
            return NULL;
        }
        if (SSL_CTX_check_private_key(ctx) != 1) {
            log_err("client certificate and key do not match");
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE
                        | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    return ctx;
}

/* Record why the connection ended. Only the first reason sticks: a failed
 * read followed by a failed write describes one event, and the read saw it. */
static void set_closed(tls_conn_t *t, tls_close_kind k, const char *detail) {
    if (!t->failed) {
        t->close_kind = k;
        snprintf(t->close_detail, sizeof(t->close_detail), "%s", detail ? detail : "");
    }
    t->failed = 1;
}

/* Classify a failed SSL_read/SSL_write/SSL_connect. `sys_errno` is errno as
 * it was straight after the call — SSL_get_error() may clobber it. */
static void classify_failure(tls_conn_t *t, int ssl_err, int sys_errno, const char *op) {
    unsigned long e = ERR_peek_last_error();
    const char *reason = e ? ERR_reason_error_string(e) : NULL;

    if (ssl_err == SSL_ERROR_ZERO_RETURN) {
        log_dbg("TLS closed by peer (close_notify) while %s", op);
        set_closed(t, TLS_CLOSE_NOTIFY, NULL);
    } else if (ssl_err == SSL_ERROR_SYSCALL && sys_errno == 0 && !e) {
        log_dbg("TLS connection dropped (EOF) while %s", op);
        set_closed(t, TLS_CLOSE_EOF, NULL);
#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
    } else if (ssl_err == SSL_ERROR_SSL && e &&
               ERR_GET_REASON(e) == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
        /* OpenSSL 3 reports a bare FIN this way rather than as SYSCALL/0. */
        log_dbg("TLS connection dropped (EOF) while %s", op);
        set_closed(t, TLS_CLOSE_EOF, NULL);
#endif
    } else if (ssl_err == SSL_ERROR_SYSCALL && sys_errno == ECONNRESET) {
        log_dbg("TLS connection reset while %s", op);
        set_closed(t, TLS_CLOSE_RESET, NULL);
    } else if (ssl_err == SSL_ERROR_SYSCALL && sys_errno != 0) {
        log_dbg("TLS socket error while %s: %s", op, strerror(sys_errno));
        set_closed(t, TLS_CLOSE_NETWORK, strerror(sys_errno));
    } else {
        log_dbg("TLS error while %s: %s", op, tls_last_error());
        set_closed(t, TLS_CLOSE_ALERT, reason ? reason : "protocol error");
    }
    ERR_clear_error();
}

int tls_failed(const tls_conn_t *t) { return t->failed; }

const char *tls_close_describe(const tls_conn_t *t, char *buf, size_t cap) {
    const char *d = t->close_detail[0] ? t->close_detail : "unknown";
    switch (t->close_kind) {
    case TLS_CLOSE_NONE:    snprintf(buf, cap, "open"); break;
    case TLS_CLOSE_NOTIFY:  snprintf(buf, cap, "TLS close_notify"); break;
    case TLS_CLOSE_EOF:     snprintf(buf, cap, "TCP close, no TLS close_notify"); break;
    case TLS_CLOSE_RESET:   snprintf(buf, cap, "ECONNRESET"); break;
    case TLS_CLOSE_NETWORK: snprintf(buf, cap, "network error: %s", d); break;
    case TLS_CLOSE_ALERT:   snprintf(buf, cap, "TLS error: %s", d); break;
    case TLS_CLOSE_LOCAL:   snprintf(buf, cap, "local error: %s", d); break;
    default:                snprintf(buf, cap, "?"); break;
    }
    return buf;
}

int tls_start(tls_conn_t *t, SSL_CTX *ctx, int fd) {
    return tls_start_ex(t, ctx, fd, TLS_HANDSHAKE_MS, NULL);
}

int tls_start_ex(tls_conn_t *t, SSL_CTX *ctx, int fd, int timeout_ms,
                 const atomic_int *abort_flag) {
    memset(t, 0, sizeof(*t));
    t->ctx = ctx;
    t->fd  = fd;
    int err_out = EPROTO;

    t->in = malloc(TLS_IN_INITIAL);
    if (!t->in) return -1;
    t->in_cap = TLS_IN_INITIAL;

    t->out = malloc(TLS_OUT_INITIAL);
    if (!t->out) { free(t->in); t->in = NULL; return -1; }
    t->out_cap = TLS_OUT_INITIAL;

    t->ssl = SSL_new(ctx);
    if (!t->ssl) { log_err("SSL_new failed: %s", tls_last_error()); goto fail; }
    if (SSL_set_fd(t->ssl, fd) != 1) {
        log_err("SSL_set_fd failed: %s", tls_last_error());
        goto fail;
    }

    /* Drive SSL_connect() from poll() on a non-blocking socket. A blocking
     * SSL_connect has no timeout at all: against a server that goes quiet
     * mid-handshake it waited for the kernel to give up on the TCP connection
     * (hours), and nothing could interrupt it. The slices keep the abort flag
     * honoured within TLS_SLICE_MS. */
    if (net_set_nonblock(fd) != 0) {
        log_err("cannot set the TLS socket non-blocking: %s", strerror(errno));
        goto fail;
    }
    uint64_t deadline = now_ms() + (uint64_t)(timeout_ms > 0 ? timeout_ms : TLS_HANDSHAKE_MS);
    for (;;) {
        ERR_clear_error();
        int r = SSL_connect(t->ssl);
        if (r == 1) break;

        int sys_errno = errno;
        int e = SSL_get_error(t->ssl, r);
        short ev;
        if      (e == SSL_ERROR_WANT_READ)  ev = POLLIN;
        else if (e == SSL_ERROR_WANT_WRITE) ev = POLLOUT;
        else {
            char why[200];
            classify_failure(t, e, sys_errno, "handshaking");
            log_err("TLS handshake failed: %s", tls_close_describe(t, why, sizeof(why)));
            goto fail;
        }

        for (;;) {
            if (abort_flag && atomic_load(abort_flag)) { err_out = ECANCELED; goto fail; }
            uint64_t now = now_ms();
            if (now >= deadline) {
                log_err("TLS handshake timed out after %d s", timeout_ms / 1000);
                err_out = ETIMEDOUT;
                goto fail;
            }
            uint64_t left = deadline - now;
            struct pollfd pf = { .fd = fd, .events = ev };
            int pr = poll(&pf, 1, (int)(left < TLS_SLICE_MS ? left : TLS_SLICE_MS));
            if (pr < 0 && errno != EINTR) { err_out = errno; goto fail; }
            if (pr > 0) break;
        }
    }
    t->handshake_done = 1;
    log_dbg("TLS established, cipher %s", SSL_get_cipher(t->ssl));
    return 0;

fail:
    if (t->ssl) { SSL_free(t->ssl); t->ssl = NULL; }
    free(t->in);  t->in  = NULL; t->in_cap  = 0;
    free(t->out); t->out = NULL; t->out_cap = 0;
    /* Clear handshake_done too, not just fd.
     *
     * handshake_release() decides who owns the socket from BOTH ssl != NULL and
     * handshake_done. If SSL_connect() succeeded (setting handshake_done) but a
     * later step here failed, leaving handshake_done set would make the caller
     * believe TLS owns the fd while we have disowned it, and nobody closes it:
     * a leaked TCP socket. Reset both so the caller's own tcp_fd cleanup runs. */
    t->handshake_done = 0;
    t->fd = -1;
    errno = err_out;
    return -1;
}

/* ------------------------------------------------------------- outbound */

static int out_reserve(tls_conn_t *t, size_t extra) {
    if (t->out_len + extra <= t->out_cap) return 0;
    size_t want = t->out_cap ? t->out_cap : TLS_OUT_INITIAL;
    while (want < t->out_len + extra) want *= 2;
    if (want > TLS_OUT_MAX) {
        log_err("TLS output queue overflow (%zu bytes)", t->out_len + extra);
        return -1;
    }
    uint8_t *p = realloc(t->out, want);
    if (!p) return -1;
    t->out     = p;
    t->out_cap = want;
    return 0;
}

int tls_queue(tls_conn_t *t, const void *buf, size_t len) {
    if (t->failed || len == 0) return t->failed ? -1 : 0;
    if (out_reserve(t, len) != 0) {
        set_closed(t, TLS_CLOSE_LOCAL, "TLS output queue overflow");
        return -1;
    }
    memcpy(t->out + t->out_len, buf, len);
    t->out_len += len;
    return 0;
}

int tls_want_write(const tls_conn_t *t) {
    return t->out_len > 0 || t->want_write;
}

int tls_flush(tls_conn_t *t) {
    if (t->failed) return -1;
    if (!t->ssl)   return -1;

    while (t->out_len > 0) {
        ERR_clear_error();
        int n = SSL_write(t->ssl, t->out, (int)t->out_len);
        int sys_errno = errno;
        if (n > 0) {
            memmove(t->out, t->out + n, t->out_len - (size_t)n);
            t->out_len -= (size_t)n;
            t->want_write = 0;
            continue;
        }
        int e = SSL_get_error(t->ssl, n);
        if (e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ) {
            /* Retry when poll() says so. SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
             * is set, so compacting the queue above is safe. */
            t->want_write = 1;
            return 0;
        }
        classify_failure(t, e, sys_errno, "writing");
        return -1;
    }
    t->want_write = 0;
    return 0;
}

/* -------------------------------------------------------------- inbound */

static int in_reserve(tls_conn_t *t, size_t extra) {
    if (t->in_len + extra <= t->in_cap) return 0;
    size_t want = t->in_cap ? t->in_cap : TLS_IN_INITIAL;
    while (want < t->in_len + extra) want *= 2;
    if (want > TLS_IN_MAX) {
        log_err("TLS input buffer overflow (%zu bytes) — dropping the connection",
                t->in_len + extra);
        return -1;
    }
    uint8_t *p = realloc(t->in, want);
    if (!p) return -1;
    t->in     = p;
    t->in_cap = want;
    return 0;
}

int tls_pump_in(tls_conn_t *t) {
    if (t->failed || !t->ssl) return -1;

    int got_any = 0;
    for (;;) {
        if (in_reserve(t, 16 * 1024) != 0) {
            set_closed(t, TLS_CLOSE_LOCAL, "TLS input buffer overflow");
            return got_any ? 1 : -1;
        }

        ERR_clear_error();
        int n = SSL_read(t->ssl, t->in + t->in_len, (int)(t->in_cap - t->in_len));
        int sys_errno = errno;
        if (n > 0) {
            t->in_len += (size_t)n;
            got_any = 1;
            /* Keep going: SSL_read returns one record at a time, and there may
             * be more already buffered inside OpenSSL that poll() cannot see. */
            continue;
        }

        int e = SSL_get_error(t->ssl, n);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            if (e == SSL_ERROR_WANT_WRITE) t->want_write = 1;
            return got_any;
        }
        classify_failure(t, e, sys_errno, "reading");
        /* Hand over what arrived before the close: it is typically the
         * reflector's MsgError saying why it is hanging up. The failure is
         * recorded and the next call reports it. */
        return got_any ? 1 : -1;
    }
}

size_t tls_pending(const tls_conn_t *t) { return t->in_len; }

const uint8_t *tls_peek(const tls_conn_t *t, size_t *len) {
    if (len) *len = t->in_len;
    return t->in;
}

void tls_consume(tls_conn_t *t, size_t n) {
    if (n >= t->in_len) { t->in_len = 0; return; }
    memmove(t->in, t->in + n, t->in_len - n);
    t->in_len -= n;
}

/* ---------------------------------------------------------------- close */

void tls_close(tls_conn_t *t) {
    if (!t) return;
    if (t->ssl) {
        /* No SSL_shutdown — see tls.h. */
        SSL_free(t->ssl);
        t->ssl = NULL;
    }
    if (t->fd >= 0) { close(t->fd); t->fd = -1; }
    free(t->in);  t->in  = NULL; t->in_len  = t->in_cap  = 0;
    free(t->out); t->out = NULL; t->out_len = t->out_cap = 0;
    t->handshake_done = 0;
    t->want_write     = 0;
    t->failed         = 0;
    t->close_kind     = TLS_CLOSE_NONE;
    t->close_detail[0] = '\0';
    t->ctx            = NULL;   /* not ours to free */
}
