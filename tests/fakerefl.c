/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "fakerefl.h"

#include "common/proto.h"
#include "common/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#define FR_MAX_CONN 16

typedef struct {
    fakerefl *f;
    int       fd;
} fr_conn;

static pthread_t     g_handlers[FR_MAX_CONN];
static int           g_n_handlers;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* ---------------------------------------------------------------- PKI */

int fr_make_pki(const char *dir, const char *callsign) {
    int rc = -1;
    EVP_PKEY     *pkey = NULL;
    X509         *x    = NULL;
    EVP_PKEY_CTX *kc   = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!kc || EVP_PKEY_keygen_init(kc) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(kc, 2048) <= 0 ||
        EVP_PKEY_keygen(kc, &pkey) <= 0) goto end;

    x = X509_new();
    if (!x) goto end;
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, pkey);
    X509_NAME *n = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)callsign, -1, -1, 0);
    X509_set_issuer_name(x, n);
    if (!X509_sign(x, pkey, EVP_sha256())) goto end;

    char path[1024];
    snprintf(path, sizeof(path), "%s/%s.key", dir, callsign);
    FILE *fk = fopen(path, "w");
    if (!fk) goto end;
    PEM_write_PrivateKey(fk, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(fk);

    snprintf(path, sizeof(path), "%s/%s.crt", dir, callsign);
    FILE *fc = fopen(path, "w");
    if (!fc) goto end;
    PEM_write_X509(fc, x);
    fclose(fc);
    rc = 0;
end:
    X509_free(x);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kc);
    return rc;
}

/* ------------------------------------------------------------- helpers */

/* Wait for readability, in slices so fr_stop() is honoured. 1 ready, 0 stop. */
static int wait_readable(fakerefl *f, int fd, SSL *ssl) {
    while (!atomic_load(&f->stop)) {
        if (ssl && SSL_pending(ssl) > 0) return 1;
        struct pollfd p = { .fd = fd, .events = POLLIN };
        int pr = poll(&p, 1, 50);
        if (pr > 0) return 1;
        if (pr < 0 && errno != EINTR) return 0;
    }
    return 0;
}

static int raw_read_n(fakerefl *f, int fd, uint8_t *p, size_t n) {
    while (n > 0) {
        if (!wait_readable(f, fd, NULL)) return -1;
        ssize_t r = recv(fd, p, n, 0);
        if (r <= 0) return -1;
        p += r; n -= (size_t)r;
    }
    return 0;
}

static int ssl_send_frame(SSL *ssl, const uint8_t *body, size_t len) {
    uint8_t hdr[4];
    be_put_u32(hdr, (uint32_t)len);
    if (SSL_write(ssl, hdr, 4) != 4) return -1;
    return SSL_write(ssl, body, (int)len) == (int)len ? 0 : -1;
}

/* Read and discard until the client goes away or we are stopped. */
static void drain_until_gone(fakerefl *f, int fd, SSL *ssl) {
    uint8_t buf[4096];
    while (wait_readable(f, fd, ssl)) {
        int r = ssl ? SSL_read(ssl, buf, sizeof(buf)) : (int)recv(fd, buf, sizeof(buf), 0);
        if (r <= 0) {
            if (ssl) {
                int e = SSL_get_error(ssl, r);
                if (e == SSL_ERROR_WANT_READ) continue;
            }
            atomic_store(&f->client_gone_at, now_ms());
            return;
        }
    }
}

/* ------------------------------------------------------------- the part */

static void login_and_act(fakerefl *f, int fd) {
    SSL *ssl = SSL_new(f->ctx);
    SSL_set_fd(ssl, fd);
    if (SSL_accept(ssl) != 1) { SSL_free(ssl); return; }

    /* ServerInfo: type, reserved, client id 42, no nodes, no codecs. */
    uint8_t si[10];
    be_put_u16(si + 0, MSG_SERVER_INFO);
    be_put_u16(si + 2, 0);
    be_put_u16(si + 4, 42);
    be_put_u16(si + 6, 0);
    be_put_u16(si + 8, 0);
    /* An empty StartUdpEncryption: "use your key both ways". */
    uint8_t su[2];
    be_put_u16(su, MSG_START_UDP_ENCRYPTION);
    if (ssl_send_frame(ssl, si, sizeof(si)) != 0 ||
        ssl_send_frame(ssl, su, sizeof(su)) != 0) { SSL_free(ssl); return; }
    atomic_fetch_add(&f->logged_in, 1);

    /* Let the client adopt the connection and settle. */
    uint64_t until = now_ms() + 300;
    uint8_t  junk[4096];
    while (now_ms() < until && !atomic_load(&f->stop)) {
        struct pollfd p = { .fd = fd, .events = POLLIN };
        if (poll(&p, 1, 20) > 0 && SSL_read(ssl, junk, sizeof(junk)) <= 0) break;
    }

    switch (f->after) {
    case FR_HOLD:
        drain_until_gone(f, fd, ssl);
        break;
    case FR_ERROR_NOTIFY:
    case FR_ERROR_EOF: {
        const char *msg = f->error_text ? f->error_text : "TCP heartbeat timeout";
        size_t      ml  = strlen(msg);
        uint8_t     body[300];
        be_put_u16(body, MSG_ERROR);
        be_put_u16(body + 2, (uint16_t)ml);
        memcpy(body + 4, msg, ml);
        ssl_send_frame(ssl, body, 4 + ml);
        if (f->after == FR_ERROR_NOTIFY) SSL_shutdown(ssl);
        break;
    }
    case FR_RESET: {
        struct linger lg = { .l_onoff = 1, .l_linger = 0 };
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
        break;
    }
    }
    SSL_free(ssl);
}

static void *conn_main(void *arg) {
    fr_conn  *c = arg;
    fakerefl *f = c->f;
    int      fd = c->fd;
    free(c);

    uint8_t pv[10];                            /* [len][MsgProtoVer 3.0] */
    if (raw_read_n(f, fd, pv, sizeof(pv)) != 0) {
        atomic_store(&f->client_gone_at, now_ms());
        close(fd);
        return NULL;
    }

    if (f->mode == FR_SILENT) {
        drain_until_gone(f, fd, NULL);
    } else {
        uint8_t se[6];
        be_put_u32(se, 2);
        be_put_u16(se + 4, MSG_START_ENCRYPTION);
        if (send(fd, se, sizeof(se), 0) == (ssize_t)sizeof(se)) {
            if (f->mode == FR_STALL_TLS) drain_until_gone(f, fd, NULL);
            else                         login_and_act(f, fd);
        }
    }
    close(fd);
    return NULL;
}

static void *accept_main(void *arg) {
    fakerefl *f = arg;
    while (!atomic_load(&f->stop)) {
        struct pollfd p = { .fd = f->lfd, .events = POLLIN };
        if (poll(&p, 1, 50) <= 0) continue;
        int fd = accept(f->lfd, NULL, NULL);
        if (fd < 0) continue;
        atomic_fetch_add(&f->accepts, 1);

        fr_conn *c = malloc(sizeof(*c));
        c->f  = f;
        c->fd = fd;
        pthread_mutex_lock(&g_mu);
        if (g_n_handlers < FR_MAX_CONN &&
            pthread_create(&g_handlers[g_n_handlers], NULL, conn_main, c) == 0) {
            g_n_handlers++;
        } else {
            close(fd);
            free(c);
        }
        pthread_mutex_unlock(&g_mu);
    }
    return NULL;
}

int fr_start(fakerefl *f, fr_mode mode, fr_after after, const char *pki_dir,
             const char *callsign) {
    const char *text = f->error_text;
    memset(f, 0, sizeof(*f));
    f->mode       = mode;
    f->after      = after;
    f->error_text = text;

    char crt[1024], key[1024];
    snprintf(crt, sizeof(crt), "%s/%s.crt", pki_dir, callsign);
    snprintf(key, sizeof(key), "%s/%s.key", pki_dir, callsign);
    f->ctx = SSL_CTX_new(TLS_server_method());
    if (!f->ctx ||
        SSL_CTX_use_certificate_file(f->ctx, crt, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(f->ctx, key, SSL_FILETYPE_PEM) != 1) return -1;

    f->lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family      = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t al = sizeof(a);
    if (bind(f->lfd, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        listen(f->lfd, 8) != 0 ||
        getsockname(f->lfd, (struct sockaddr *)&a, &al) != 0) return -1;
    f->port = ntohs(a.sin_port);

    g_n_handlers = 0;
    return pthread_create(&f->th, NULL, accept_main, f) == 0 ? 0 : -1;
}

void fr_stop(fakerefl *f) {
    atomic_store(&f->stop, 1);
    pthread_join(f->th, NULL);
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_n_handlers; i++) pthread_join(g_handlers[i], NULL);
    g_n_handlers = 0;
    pthread_mutex_unlock(&g_mu);
    close(f->lfd);
    SSL_CTX_free(f->ctx);
}
