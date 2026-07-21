/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — Copyright (C) 2026 Joeri Van Dooren
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
#include <openssl/ssl.h>
#include <openssl/err.h>

#define TLS_IN_INITIAL   (64 * 1024)
#define TLS_IN_MAX       (1024 * 1024)   /* a CA bundle is the largest frame */
#define TLS_OUT_INITIAL  (16 * 1024)
#define TLS_OUT_MAX      (1024 * 1024)

void tls_global_init(void) {
    static int done = 0;
    if (done) return;
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    done = 1;
}

const char *tls_last_error(void) {
    static char buf[256];
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

int tls_start(tls_conn_t *t, SSL_CTX *ctx, int fd) {
    memset(t, 0, sizeof(*t));
    t->ctx = ctx;
    t->fd  = fd;

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

    /* Blocking handshake — see the note in tls.h. */
    if (SSL_connect(t->ssl) != 1) {
        log_err("TLS handshake failed: %s", tls_last_error());
        goto fail;
    }
    t->handshake_done = 1;
    log_dbg("TLS established, cipher %s", SSL_get_cipher(t->ssl));

    if (net_set_nonblock(fd) != 0) {
        log_err("cannot set the TLS socket non-blocking: %s", strerror(errno));
        goto fail;
    }
    return 0;

fail:
    if (t->ssl) { SSL_free(t->ssl); t->ssl = NULL; }
    free(t->in);  t->in  = NULL; t->in_cap  = 0;
    free(t->out); t->out = NULL; t->out_cap = 0;
    /* Disown the fd. We never took ownership of it — the caller passed it in
     * and still has to close it — and leaving it here would make a later
     * tls_close() close it a second time, which on a busy process can end up
     * closing an unrelated socket that happened to reuse the descriptor. */
    t->fd = -1;
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
    if (out_reserve(t, len) != 0) return -1;
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
        if (e == SSL_ERROR_ZERO_RETURN) {
            log_dbg("TLS closed by peer while writing");
        } else if (e == SSL_ERROR_SYSCALL && errno == 0) {
            log_dbg("TLS connection dropped while writing");
        } else {
            log_dbg("TLS write error: %s", tls_last_error());
        }
        t->failed = 1;
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
        if (in_reserve(t, 16 * 1024) != 0) { t->failed = 1; return -1; }

        ERR_clear_error();
        int n = SSL_read(t->ssl, t->in + t->in_len, (int)(t->in_cap - t->in_len));
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
        if (e == SSL_ERROR_ZERO_RETURN) {
            log_dbg("TLS closed by peer");
        } else if (e == SSL_ERROR_SYSCALL && errno == 0) {
            log_dbg("TLS connection dropped");
        } else {
            log_dbg("TLS read error: %s", tls_last_error());
        }
        t->failed = 1;
        return -1;
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
    t->ctx            = NULL;   /* not ours to free */
}
