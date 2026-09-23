/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * Certificate lifecycle fixtures.
 *
 * The reflector renews a client certificate by pushing a new one mid-session,
 * and an expired one can only be replaced by connecting without it and
 * answering the reflector's CSR request with the SAME key. Get either wrong and
 * nothing fails until the day the certificate expires, months after the
 * release — so this is tested against real certificates, made here with a
 * throwaway CA, and against a small in-process reflector that speaks enough of
 * the protocol to log in, ask for a CSR, sign it, and push a renewal.
 *
 * Run with `make test`. CERTTEST_VERBOSE=1 shows the client's log. Each test
 * has a 60 s limit; past it the run stops and names the test.
 * CERTTEST_TIMEOUT=secs overrides the limit.
 */
#include "common/config.h"
#include "common/log.h"
#include "common/pki.h"
#include "common/util.h"
#include "reflector/cert.h"
#include "reflector/client.h"
#include "reflector/enroll.h"
#include "reflector/handshake.h"

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

static int g_fail, g_run;

#define CHECK(cond, ...) do {                               \
    g_run++;                                                \
    if (!(cond)) { g_fail++; printf("  FAIL  " __VA_ARGS__);\
                   printf("\n        at %s:%d\n", __FILE__, __LINE__); } \
} while (0)

#define DAY  86400L
#define CALL "ON0TEST"

/* ------------------------------------------------------ per-test timeout */

/* A plain run of this suite hung once and would not do it again. If it does,
 * it must at least say where: each test runs under an alarm, and the handler
 * names the test that was running and fails the run. Only async-signal-safe
 * calls in the handler — write(), not printf(). */
static const char *volatile g_current = "setup";
static volatile int          g_current_s;
static int                   g_limit_s;      /* CERTTEST_TIMEOUT=secs overrides every limit */

static void put_int(char *p, size_t *n, int v) {
    char d[12];
    int  k = 0;
    do { d[k++] = (char)('0' + v % 10); v /= 10; } while (v > 0 && k < 11);
    while (k > 0) p[(*n)++] = d[--k];
}

static void on_test_timeout(int sig) {
    (void)sig;
    char   msg[512];
    size_t n = 0;
    const char *a = "\n  TIMEOUT  ", *b = " still running after ", *c = " s\n";
    for (const char *s = a; *s; s++) msg[n++] = *s;
    for (const char *s = g_current; *s && n < 400; s++) msg[n++] = *s;
    for (const char *s = b; *s; s++) msg[n++] = *s;
    put_int(msg, &n, g_current_s);
    for (const char *s = c; *s; s++) msg[n++] = *s;
    ssize_t w = write(STDOUT_FILENO, msg, n);
    (void)w;
#ifdef __linux__
    /* And where every thread is stuck, if eu-stack is there to say: the one
     * hang seen so far left nothing but a kernel wait channel. fork, execve
     * and waitpid are all async-signal-safe. */
    char pid[16];
    size_t pn = 0;
    put_int(pid, &pn, (int)getpid());
    pid[pn] = '\0';
    pid_t k = fork();
    if (k == 0) {
        char *argv[] = { "eu-stack", "-p", pid, NULL }, *envp[] = { NULL };
        dup2(STDOUT_FILENO, STDERR_FILENO);
        execve("/usr/bin/eu-stack", argv, envp);
        _exit(127);
    }
    if (k > 0) waitpid(k, NULL, 0);
#endif
    _exit(2);
}

/* Run one test under a `secs` alarm. */
#define RUN(secs, call) do {                                  \
    g_current = #call; g_current_s = g_limit_s ? g_limit_s : (secs); \
    alarm((unsigned)g_current_s);                              \
    call;                                      \
    alarm(0);                                  \
} while (0)

/* ------------------------------------------------------------ log capture */

static pthread_mutex_t g_log_mu = PTHREAD_MUTEX_INITIALIZER;
static char            g_log[64 * 1024];
static int             g_verbose;

static void sink(int level, const char *line, void *user) {
    (void)user;
    pthread_mutex_lock(&g_log_mu);
    size_t have = strlen(g_log);
    if (have + strlen(line) + 2 < sizeof(g_log)) {
        strcat(g_log, line);
        strcat(g_log, "\n");
    }
    pthread_mutex_unlock(&g_log_mu);
    if (g_verbose) fprintf(stderr, "    [%s] %s\n", log_level_name(level), line);
}

static void log_reset(void) {
    pthread_mutex_lock(&g_log_mu);
    g_log[0] = '\0';
    pthread_mutex_unlock(&g_log_mu);
}

static int log_has(const char *needle) {
    pthread_mutex_lock(&g_log_mu);
    int r = strstr(g_log, needle) != NULL;
    pthread_mutex_unlock(&g_log_mu);
    return r;
}

/* ------------------------------------------------------ certificate kit */

static EVP_PKEY *new_key(void) {
    EVP_PKEY     *k   = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx && EVP_PKEY_keygen_init(ctx) > 0 &&
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) > 0)
        EVP_PKEY_keygen(ctx, &k);
    EVP_PKEY_CTX_free(ctx);
    return k;
}

static long g_serial = 1000;

/* A certificate for `key`, valid from now+nb to now+na seconds, signed by
 * `ca`/`ca_key` (self-signed when `ca` is NULL). */
static X509 *make_cert(EVP_PKEY *key, const char *cn, long nb, long na,
                       X509 *ca, EVP_PKEY *ca_key) {
    X509 *x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), g_serial++);
    X509_time_adj_ex(X509_getm_notBefore(x), 0, nb, NULL);
    X509_time_adj_ex(X509_getm_notAfter(x),  0, na, NULL);
    X509_set_pubkey(x, key);
    X509_NAME *n = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
    X509_set_issuer_name(x, ca ? X509_get_subject_name(ca) : n);
    X509_sign(x, ca ? ca_key : key, EVP_sha256());
    return x;
}

static char *pem_of_cert(X509 *x) {
    BIO *b = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(b, x);
    char *data; long n = BIO_get_mem_data(b, &data);
    char *out = malloc((size_t)n + 1);
    memcpy(out, data, (size_t)n); out[n] = '\0';
    BIO_free(b);
    return out;
}

static char *pem_of_key(EVP_PKEY *k) {
    BIO *b = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(b, k, NULL, NULL, 0, NULL, NULL);
    char *data; long n = BIO_get_mem_data(b, &data);
    char *out = malloc((size_t)n + 1);
    memcpy(out, data, (size_t)n); out[n] = '\0';
    BIO_free(b);
    return out;
}

static void put_file(const char *path, const char *s) {
    FILE *f = fopen(path, "w");
    fputs(s, f);
    fclose(f);
}

static char *get_file(const char *path) {
    size_t n = 0;
    return read_file(path, &n);
}

static int same_file(const char *path, const char *want) {
    char *got = get_file(path);
    int   r   = got && strcmp(got, want) == 0;
    free(got);
    return r;
}

/* Into the caller's buffer: the fake reflector's thread takes fingerprints
 * too, while the test's thread does. */
static char *fingerprint_into(X509 *x, char fp[65]) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int  n = 0;
    fp[0] = '\0';
    X509_digest(x, EVP_sha256(), md, &n);
    for (unsigned i = 0; i < n && i < 32; i++) snprintf(fp + i * 2, 3, "%02x", md[i]);
    return fp;
}

static char *fingerprint(X509 *x) {
    static char out[4][65];
    static int  slot;
    return fingerprint_into(x, out[slot++ & 3]);
}

/* Shared material: one CA, the node's key and a stranger's key. */
static EVP_PKEY *g_ca_key, *g_key, *g_other_key;
static X509     *g_ca;
static char     *g_key_pem;

static char g_dir[256];
static char g_crt[512], g_key_path[512], g_csr[512];
static svx_config g_cfg;

static void fresh_dir(void) {
    static int n;
    snprintf(g_dir, sizeof(g_dir), "/tmp/svx-certtest-%d-%d", (int)getpid(), n++);
    mkdir(g_dir, 0700);
    snprintf(g_crt,      sizeof(g_crt),      "%s/%s.crt", g_dir, CALL);
    snprintf(g_key_path, sizeof(g_key_path), "%s/%s.key", g_dir, CALL);
    snprintf(g_csr,      sizeof(g_csr),      "%s/%s.csr", g_dir, CALL);
    put_file(g_key_path, g_key_pem);
    chmod(g_key_path, 0600);
    snprintf(g_cfg.pki_dir, sizeof(g_cfg.pki_dir), "%s", g_dir);
}

static void rm_dir(void) {
    char cmd[400];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) { /* leftover in /tmp; harmless */ }
}

/* Install a certificate for our key, valid from now+nb to now+na. */
static char *install_cert(long nb, long na) {
    X509 *x   = make_cert(g_key, CALL, nb, na, g_ca, g_ca_key);
    char *pem = pem_of_cert(x);
    put_file(g_crt, pem);
    X509_free(x);
    return pem;
}

/* ------------------------------------------------------ status, warnings */

static pki_cert_status_t status_of(long nb, long na) {
    X509 *x = make_cert(g_key, CALL, nb, na, g_ca, g_ca_key);
    char *pem = pem_of_cert(x);
    pki_cert_info_t info;
    pki_cert_status_t st = PKI_CERT_INVALID;
    if (pki_cert_info_pem(pem, strlen(pem), &info) == 0) st = pki_cert_status(&info, time(NULL));
    free(pem);
    X509_free(x);
    return st;
}

static void t_status(void) {
    printf("cert: lifetime classification and the near-expiry threshold\n");

    /* A 90-day certificate, like the reflector issues: renewal from day 60,
     * the warning from 14 days before expiry. */
    CHECK(status_of(-30 * DAY, 60 * DAY) == PKI_CERT_OK,         "90 d cert, 60 d left: ok");
    CHECK(status_of(-62 * DAY, 28 * DAY) == PKI_CERT_RENEW_DUE,  "90 d cert, 28 d left: renewal due, no warning yet");
    CHECK(status_of(-75 * DAY, 15 * DAY) == PKI_CERT_RENEW_DUE,  "90 d cert, 15 d left: still no warning");
    CHECK(status_of(-77 * DAY, 13 * DAY) == PKI_CERT_EXPIRING,   "90 d cert, 13 d left: warn");
    CHECK(status_of(-90 * DAY, -3600)    == PKI_CERT_EXPIRED,    "an hour past notAfter: expired");
    CHECK(status_of(DAY, 91 * DAY)       == PKI_CERT_NOT_YET_VALID, "notBefore tomorrow: not yet valid");

    /* A short-lived one must not warn the moment renewal becomes possible:
     * 30 days, renewal from 10 days left, warning from 5 days left. */
    CHECK(status_of(-21 * DAY, 9 * DAY)  == PKI_CERT_RENEW_DUE,  "30 d cert, 9 d left: renewal due, no warning");
    CHECK(status_of(-26 * DAY, 4 * DAY)  == PKI_CERT_EXPIRING,   "30 d cert, 4 d left: warn");

    time_t now = time(NULL);
    CHECK(pki_days_until(now + 13 * DAY + 5, now) == 13, "13 days and a bit is 13 days");
    CHECK(pki_days_until(now - 3600, now) == -1,         "an hour ago is day -1, never 0");
}

static void t_expired_file_detected(void) {
    printf("cert: an expired certificate on disk is detected, and not usable\n");
    fresh_dir();
    free(install_cert(-90 * DAY, -2 * DAY));

    cert_state cs;
    log_reset();
    cert_assess(&g_cfg, time(NULL), &cs, 1);
    CHECK(cs.status == PKI_CERT_EXPIRED, "status is expired (got %s)", pki_cert_status_str(cs.status));
    CHECK(log_has("EXPIRED"), "the login log says EXPIRED");
    CHECK(enroll_have_usable_cert(&g_cfg, time(NULL)) == 0,
          "an expired certificate that matches the key is still not usable");

    free(install_cert(-10 * DAY, 80 * DAY));
    log_reset();
    cert_assess(&g_cfg, time(NULL), &cs, 1);
    CHECK(enroll_have_usable_cert(&g_cfg, time(NULL)) == 1, "a current one is usable");
    CHECK(log_has("79 days left") || log_has("80 days left"),
          "the login log gives the days left");
    rm_dir();
}

static void t_banner(void) {
    printf("cert: the banner names the date and the action\n");
    fresh_dir();
    char text[240];
    cert_state cs;

    free(install_cert(-80 * DAY, 10 * DAY));
    cert_assess(&g_cfg, time(NULL), &cs, 0);
    CHECK(cert_banner_text(&g_cfg, &cs, time(NULL), text, sizeof(text)) == 1,
          "10 days left raises a banner");
    char date[32];
    pki_format_time(cs.info.not_after, date, sizeof(date));
    CHECK(strstr(text, "EXPIRES") && strstr(text, date) && strstr(text, "(10 days)"),
          "near-expiry banner has the date and days left: %s", text);
    CHECK(strstr(text, "sysop") && strstr(text, CALL), "and says whom to ask: %s", text);

    free(install_cert(-90 * DAY, -DAY));
    cert_assess(&g_cfg, time(NULL), &cs, 0);
    CHECK(cert_banner_text(&g_cfg, &cs, time(NULL), text, sizeof(text)) == 1,
          "an expired certificate raises a banner");
    pki_format_time(cs.info.not_after, date, sizeof(date));
    CHECK(strstr(text, "EXPIRED") && strstr(text, date) && strstr(text, "sign"),
          "expired banner has the date and the action: %s", text);

    free(install_cert(-20 * DAY, 70 * DAY));
    cert_assess(&g_cfg, time(NULL), &cs, 0);
    CHECK(cert_banner_text(&g_cfg, &cs, time(NULL), text, sizeof(text)) == 0,
          "a healthy certificate raises nothing");
    free(install_cert(-65 * DAY, 25 * DAY));
    cert_assess(&g_cfg, time(NULL), &cs, 0);
    CHECK(cert_banner_text(&g_cfg, &cs, time(NULL), text, sizeof(text)) == 0,
          "renewal due is the reflector's job, not a banner");
    rm_dir();
}

/* ------------------------------------------------ a pushed certificate */

static pki_push_result push(const char *pem, time_t now, char *why, size_t cap) {
    return pki_store_pushed_cert(g_crt, g_key_path, CALL, pem, pem ? strlen(pem) : 0,
                                 now, NULL, why, cap);
}

static int tmp_left(void) {
    char tmp[600];
    snprintf(tmp, sizeof(tmp), "%s.tmp", g_crt);
    return access(tmp, F_OK) == 0;
}

static void t_push(void) {
    printf("cert: a pushed renewal is validated before it is written\n");
    fresh_dir();
    char why[320];
    char *cur = install_cert(-62 * DAY, 28 * DAY);

    /* wrong CN */
    X509 *x = make_cert(g_key, "ON0EVIL", 0, 90 * DAY, g_ca, g_ca_key);
    char *pem = pem_of_cert(x); X509_free(x);
    CHECK(push(pem, time(NULL), why, sizeof(why)) == PKI_PUSH_REJECTED, "another callsign is rejected");
    CHECK(strstr(why, "ON0EVIL") != NULL, "and the reason names it: %s", why);
    CHECK(same_file(g_crt, cur), "the certificate on disk is untouched");
    free(pem);

    /* wrong key */
    x = make_cert(g_other_key, CALL, 0, 90 * DAY, g_ca, g_ca_key);
    pem = pem_of_cert(x); X509_free(x);
    CHECK(push(pem, time(NULL), why, sizeof(why)) == PKI_PUSH_REJECTED, "another key is rejected");
    CHECK(strstr(why, "private key") != NULL, "and the reason says so: %s", why);
    CHECK(same_file(g_crt, cur), "the certificate on disk is untouched");
    free(pem);

    /* already expired */
    x = make_cert(g_key, CALL, -100 * DAY, -DAY, g_ca, g_ca_key);
    pem = pem_of_cert(x); X509_free(x);
    CHECK(push(pem, time(NULL), why, sizeof(why)) == PKI_PUSH_REJECTED, "an expired one is rejected");
    CHECK(same_file(g_crt, cur), "the certificate on disk is untouched");
    free(pem);

    /* expires before the one we have */
    x = make_cert(g_key, CALL, -DAY, 20 * DAY, g_ca, g_ca_key);
    pem = pem_of_cert(x); X509_free(x);
    CHECK(push(pem, time(NULL), why, sizeof(why)) == PKI_PUSH_REJECTED, "an older one is rejected");
    CHECK(same_file(g_crt, cur), "the certificate on disk is untouched");
    free(pem);

    /* garbage and empty */
    CHECK(push("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n",
               time(NULL), why, sizeof(why)) == PKI_PUSH_REJECTED, "garbage is rejected");
    CHECK(push(NULL, time(NULL), why, sizeof(why)) == PKI_PUSH_EMPTY, "an empty message is 'nothing yet'");
    CHECK(same_file(g_crt, cur), "the certificate on disk is untouched");

    /* the same one again */
    CHECK(push(cur, time(NULL), why, sizeof(why)) == PKI_PUSH_SAME, "the same certificate is recognised");

    /* a genuine renewal */
    x = make_cert(g_key, CALL, 0, 90 * DAY, g_ca, g_ca_key);
    pem = pem_of_cert(x); X509_free(x);
    CHECK(push(pem, time(NULL), why, sizeof(why)) == PKI_PUSH_STORED, "a renewal is stored (%s)", why);
    CHECK(same_file(g_crt, pem), "the file now holds the renewal");
    CHECK(!tmp_left(), "no temporary file is left behind");
    CHECK(same_file(g_key_path, g_key_pem), "the key is untouched");
    CHECK(pki_check_pair(g_crt, g_key_path) == 0, "and the pair still matches");
    struct stat st;
    CHECK(stat(g_crt, &st) == 0 && (st.st_mode & 0777) == 0644, "written 0644");
    free(pem);
    free(cur);
    rm_dir();
}

/* ------------------------------------------------------ key and CSR */

static int csr_pubkey_is_ours(void) {
    FILE *f = fopen(g_csr, "r");
    if (!f) return 0;
    X509_REQ *r = PEM_read_X509_REQ(f, NULL, NULL, NULL);
    fclose(f);
    if (!r) return 0;
    int ok = X509_REQ_check_private_key(r, g_key) == 1;
    X509_REQ_free(r);
    return ok;
}

static void t_csr_keeps_key(void) {
    printf("cert: a lost or stale CSR is rebuilt from the key we have\n");
    fresh_dir();

    CHECK(pki_ensure_csr(g_key_path, g_csr, CALL, "a@b.c") == 0, "CSR made with the key missing its .csr");
    CHECK(same_file(g_key_path, g_key_pem), "the key is byte-for-byte unchanged");
    CHECK(csr_pubkey_is_ours(), "the CSR carries our public key");

    char *first = get_file(g_csr);
    CHECK(pki_ensure_csr(g_key_path, g_csr, CALL, "a@b.c") == 0 && same_file(g_csr, first),
          "a matching CSR is reused as it is");
    free(first);

    /* A CSR from someone else's key is replaced; the key still is not. */
    char *other = pem_of_key(g_other_key);
    char other_key[600];
    snprintf(other_key, sizeof(other_key), "%s/other.key", g_dir);
    put_file(other_key, other);
    free(other);
    CHECK(pki_ensure_csr(other_key, g_csr, CALL, "") == 0, "CSR for the other key");
    CHECK(pki_ensure_csr(g_key_path, g_csr, CALL, "") == 0, "then ours again");
    CHECK(csr_pubkey_is_ours() && same_file(g_key_path, g_key_pem),
          "the stale CSR was rebuilt from our unchanged key");

    /* An unreadable key is refused, never replaced. */
    put_file(g_key_path, "not a key\n");
    unlink(g_csr);
    CHECK(pki_ensure_csr(g_key_path, g_csr, CALL, "") != 0, "an unreadable key is an error");
    CHECK(same_file(g_key_path, "not a key\n"), "and it is left where it is");
    rm_dir();
}

/* --------------------------------------------------- a fake reflector */

typedef struct {
    int         lfd;
    uint16_t    port;
    pthread_t   th;
    _Atomic int stop;
    SSL_CTX    *ctx;

    /* behaviour */
    int         sign_csr;      /* sign a CSR and send it back */
    EVP_PKEY   *sign_pub_key;  /* ...but certify this key instead of the CSR's */
    char       *push_pem;      /* push this once, after a login with a certificate */
    char        refuse_fp[65]; /* turn this certificate away in the TLS handshake,
                                  with a certificate_revoked alert */

    /* what it saw; read by the test after fr_stop() or under mu */
    pthread_mutex_t mu;
    int         sessions, logins;
    char        presented[8][65];   /* fingerprint per session, "" for none */
    char        csr[8192];
    int         got_csr, pushed;
    int         refused;            /* handshakes turned away over refuse_fp */
    int         cur;                /* the session being served            */
} fakerefl;

static int rd_exact(SSL *ssl, int fd, uint8_t *p, size_t n, int timeout_ms, _Atomic int *stop) {
    size_t got = 0;
    while (got < n) {
        if (stop && *stop) return -1;
        if (!ssl || SSL_pending(ssl) == 0) {
            struct pollfd pf = { .fd = fd, .events = POLLIN };
            int pr = poll(&pf, 1, timeout_ms);
            if (pr == 0) { if (stop) continue; return -1; }
            if (pr < 0) return -1;
        }
        ssize_t r = ssl ? SSL_read(ssl, p + got, (int)(n - got)) : recv(fd, p + got, n - got, 0);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

/* Read one frame; returns its type, -1 on EOF/timeout. */
static int rd_frame(SSL *ssl, int fd, uint8_t *body, size_t cap, size_t *len, _Atomic int *stop) {
    uint8_t h[4];
    if (rd_exact(ssl, fd, h, 4, stop ? 100 : 5000, stop) != 0) return -1;
    uint32_t L = (uint32_t)h[0] << 24 | (uint32_t)h[1] << 16 | (uint32_t)h[2] << 8 | h[3];
    if (L > cap || L < 2) return -1;
    if (rd_exact(ssl, fd, body, L, 5000, stop) != 0) return -1;
    *len = L;
    return body[0] << 8 | body[1];
}

static void wr_frame(SSL *ssl, int fd, uint16_t type, const char *str) {
    size_t  sl = str ? strlen(str) : 0;
    uint8_t *b = malloc(8 + sl);
    size_t  L  = 2 + (str ? 2 + sl : 0);
    b[0] = (uint8_t)(L >> 24); b[1] = (uint8_t)(L >> 16); b[2] = (uint8_t)(L >> 8); b[3] = (uint8_t)L;
    b[4] = (uint8_t)(type >> 8); b[5] = (uint8_t)type;
    if (str) { b[6] = (uint8_t)(sl >> 8); b[7] = (uint8_t)sl; memcpy(b + 8, str, sl); }
    if (ssl) SSL_write(ssl, b, (int)(4 + L));
    else     { ssize_t w = send(fd, b, 4 + L, 0); (void)w; }
    free(b);
}

static void wr_server_info(SSL *ssl) {
    /* type, reserved, client id 42, no nodes, one codec: OPUS */
    uint8_t b[] = { 0, 0, 0, 16, 0, 100, 0, 0, 0, 42, 0, 0, 0, 1, 0, 4, 'O', 'P', 'U', 'S' };
    SSL_write(ssl, b, sizeof(b));
}

static char *sign_csr_pem(const char *csr_pem, EVP_PKEY *instead) {
    BIO *b = BIO_new_mem_buf(csr_pem, -1);
    X509_REQ *r = PEM_read_bio_X509_REQ(b, NULL, NULL, NULL);
    BIO_free(b);
    if (!r) return NULL;
    EVP_PKEY *pk = X509_REQ_get_pubkey(r);
    X509 *x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), g_serial++);
    X509_time_adj_ex(X509_getm_notBefore(x), 0, 0, NULL);
    X509_time_adj_ex(X509_getm_notAfter(x),  90, 0, NULL);
    X509_set_pubkey(x, instead ? instead : pk);
    X509_set_subject_name(x, X509_REQ_get_subject_name(r));
    X509_set_issuer_name(x, X509_get_subject_name(g_ca));
    X509_sign(x, g_ca_key, EVP_sha256());
    char *pem = pem_of_cert(x);
    X509_free(x);
    EVP_PKEY_free(pk);
    X509_REQ_free(r);
    return pem;
}

/* Take whatever certificate comes — the test wants to see what the client
 * presents, expired or not — except the one named in refuse_fp, which is
 * refused the way svxreflector refuses a revoked or removed certificate. */
static int accept_any(int ok, X509_STORE_CTX *c) {
    (void)ok;
    if (X509_STORE_CTX_get_error_depth(c) != 0) return 1;
    SSL      *ssl = X509_STORE_CTX_get_ex_data(c, SSL_get_ex_data_X509_STORE_CTX_idx());
    fakerefl *f   = ssl ? SSL_get_app_data(ssl) : NULL;
    X509     *x   = X509_STORE_CTX_get_current_cert(c);
    if (!f || !x) return 1;
    char fp[65];
    fingerprint_into(x, fp);
    int refuse = 0;
    pthread_mutex_lock(&f->mu);
    snprintf(f->presented[f->cur], 65, "%s", fp);
    if (f->refuse_fp[0] && strcmp(fp, f->refuse_fp) == 0) { refuse = 1; f->refused++; }
    pthread_mutex_unlock(&f->mu);
    if (!refuse) return 1;
    X509_STORE_CTX_set_error(c, X509_V_ERR_CERT_REVOKED);
    return 0;
}

static void serve(fakerefl *f, int fd) {
    uint8_t *buf = malloc(64 * 1024);
    size_t   L;
    SSL     *ssl = NULL;
    int      idx;

    pthread_mutex_lock(&f->mu);
    idx = f->sessions < 8 ? f->sessions : 7;
    f->cur = idx;
    f->sessions++;
    pthread_mutex_unlock(&f->mu);

    if (rd_frame(NULL, fd, buf, 65536, &L, NULL) != 5) goto out;          /* ProtoVer */
    wr_frame(NULL, fd, 19, NULL);                                          /* CAInfo */
    if (rd_frame(NULL, fd, buf, 65536, &L, NULL) != 20) goto out;         /* CABundleReq */
    char *ca_pem = pem_of_cert(g_ca);
    wr_frame(NULL, fd, 21, ca_pem);
    free(ca_pem);
    if (rd_frame(NULL, fd, buf, 65536, &L, NULL) != 14) goto out;         /* StartEncReq */
    wr_frame(NULL, fd, 15, NULL);

    ssl = SSL_new(f->ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_app_data(ssl, f);
    if (SSL_accept(ssl) != 1) goto out;

    X509 *peer = SSL_get_peer_certificate(ssl);
    char  pfp[65] = "";
    if (peer) fingerprint_into(peer, pfp);
    pthread_mutex_lock(&f->mu);
    snprintf(f->presented[idx], 65, "%s", pfp);
    pthread_mutex_unlock(&f->mu);

    if (!peer) {
        /* No certificate: ask for a request, as svxreflector does. */
        wr_frame(ssl, fd, 16, NULL);
        int t;
        while ((t = rd_frame(ssl, fd, buf, 65536, &L, NULL)) >= 0 && t != 17) { }
        if (t != 17) goto out;
        size_t sl = (size_t)(buf[2] << 8 | buf[3]);
        pthread_mutex_lock(&f->mu);
        memcpy(f->csr, buf + 4, sl < sizeof(f->csr) - 1 ? sl : sizeof(f->csr) - 1);
        f->csr[sl < sizeof(f->csr) - 1 ? sl : sizeof(f->csr) - 1] = '\0';
        f->got_csr++;
        pthread_mutex_unlock(&f->mu);
        if (f->sign_csr) {
            char *pem = sign_csr_pem(f->csr, f->sign_pub_key);
            wr_frame(ssl, fd, 18, pem);
            free(pem);
            /* ...and then ignore the session, like the reflector. */
            while (rd_frame(ssl, fd, buf, 65536, &L, &f->stop) >= 0) { }
        }
        goto out;
    }
    X509_free(peer);

    wr_frame(ssl, fd, 12, NULL);                                           /* AuthOk */
    wr_server_info(ssl);
    int t;
    while ((t = rd_frame(ssl, fd, buf, 65536, &L, NULL)) >= 0 && t != 111) { }
    if (t != 111) goto out;
    wr_frame(ssl, fd, 114, NULL);                                          /* StartUdpEncryption */
    pthread_mutex_lock(&f->mu);
    f->logins++;
    int do_push = f->push_pem && !f->pushed;
    if (do_push) f->pushed = 1;
    pthread_mutex_unlock(&f->mu);

    if (do_push) {
        usleep(300 * 1000);
        wr_frame(ssl, fd, 18, f->push_pem);
    }
    while (rd_frame(ssl, fd, buf, 65536, &L, &f->stop) >= 0) { }

out:
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    close(fd);
    free(buf);
}

static void *fr_main(void *arg) {
    fakerefl *f = arg;
    while (!f->stop) {
        struct pollfd pf = { .fd = f->lfd, .events = POLLIN };
        if (poll(&pf, 1, 100) <= 0) continue;
        int fd = accept(f->lfd, NULL, NULL);
        if (fd >= 0) serve(f, fd);
    }
    return NULL;
}

static void fr_start(fakerefl *f) {
    memset(f, 0, sizeof(*f));
    pthread_mutex_init(&f->mu, NULL);

    f->ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_max_proto_version(f->ctx, TLS1_2_VERSION);
    EVP_PKEY *sk = g_other_key;
    X509 *sc = make_cert(sk, "reflector.test", -DAY, 365 * DAY, g_ca, g_ca_key);
    SSL_CTX_use_certificate(f->ctx, sc);
    SSL_CTX_use_PrivateKey(f->ctx, sk);
    X509_free(sc);
    /* Ask for a client certificate; accept_any decides what to do with it. */
    SSL_CTX_set_verify(f->ctx, SSL_VERIFY_PEER, accept_any);

    f->lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(f->lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    bind(f->lfd, (struct sockaddr *)&a, sizeof(a));
    listen(f->lfd, 4);
    socklen_t al = sizeof(a);
    getsockname(f->lfd, (struct sockaddr *)&a, &al);
    f->port = ntohs(a.sin_port);
    g_cfg.port = f->port;
}

static void fr_run(fakerefl *f) { pthread_create(&f->th, NULL, fr_main, f); }

static void fr_stop(fakerefl *f) {
    f->stop = 1;
    pthread_join(f->th, NULL);
    close(f->lfd);
    SSL_CTX_free(f->ctx);
    pthread_mutex_destroy(&f->mu);
}

/* ---------------------------------------------- expired: new request */

static void t_expired_login_requests_new_cert(void) {
    printf("cert: an expired certificate logs in without it and sends the SAME key's CSR\n");
    fresh_dir();
    char *old = install_cert(-91 * DAY, -DAY);
    CHECK(pki_ensure_csr(g_key_path, g_csr, CALL, "") == 0, "an existing request on disk");
    char *csr_before = get_file(g_csr);

    fakerefl f;
    fr_start(&f);
    f.sign_csr = 1;
    fr_run(&f);

    handshake_result r;
    log_reset();
    int rc = handshake_run(&g_cfg, &r, NULL);
    CHECK(rc != 0 && r.cert_renewed, "the login ends because a new certificate was stored (%s)", r.err);
    CHECK(log_has("EXPIRED"), "the log says the certificate EXPIRED");

    pthread_mutex_lock(&f.mu);
    CHECK(f.presented[0][0] == '\0', "no client certificate was presented");
    CHECK(f.got_csr == 1 && csr_before && strcmp(f.csr, csr_before) == 0,
          "the reflector received the existing CSR, byte for byte");
    pthread_mutex_unlock(&f.mu);

    CHECK(!same_file(g_crt, old), "the certificate on disk was replaced");
    CHECK(same_file(g_key_path, g_key_pem), "the key was not");
    cert_state cs;
    cert_assess(&g_cfg, time(NULL), &cs, 0);
    CHECK(cs.status == PKI_CERT_OK, "and the new certificate is current");

    /* The next login presents the new certificate and completes. */
    X509 *nx = NULL;
    { FILE *fp = fopen(g_crt, "r"); nx = PEM_read_X509(fp, NULL, NULL, NULL); fclose(fp); }
    char want[65];
    snprintf(want, sizeof(want), "%s", fingerprint(nx));
    X509_free(nx);

    rc = handshake_run(&g_cfg, &r, NULL);
    CHECK(rc == 0, "the next login succeeds (%s)", rc ? r.err : "");
    if (rc == 0) handshake_release(&r);

    fr_stop(&f);
    CHECK(strcmp(f.presented[1], want) == 0, "presenting the new certificate");
    free(old);
    free(csr_before);
    rm_dir();
}

static void t_expired_login_unsigned(void) {
    printf("cert: with nothing signed yet, the failure says so\n");
    fresh_dir();
    free(install_cert(-91 * DAY, -DAY));

    fakerefl f;
    fr_start(&f);
    f.sign_csr = 0;
    fr_run(&f);

    handshake_result r;
    int rc = handshake_run(&g_cfg, &r, NULL);
    fr_stop(&f);

    CHECK(rc != 0 && !r.cert_renewed, "the login fails");
    CHECK(strstr(r.err, "expired") && strstr(r.err, "sysop"), "and the reason is actionable: %s", r.err);
    CHECK(f.got_csr == 1, "after the request was sent");
    CHECK(access(g_csr, F_OK) == 0 && csr_pubkey_is_ours(),
          "a missing .csr was rebuilt from the existing key");
    CHECK(same_file(g_key_path, g_key_pem), "which was not replaced");
    rm_dir();
}

/* ------------------------------------------- renewal pushed mid-session */


typedef struct { int connected; int closed_msgs; } rc_obs;

static void obs_state(void *u, rc_state st, const char *detail) {
    rc_obs *o = u;
    if (st == RC_CONNECTED) o->connected++;
    if (detail && strstr(detail, "closed the connection")) o->closed_msgs++;
}

static void t_midsession_push(int good) {
    printf(good ? "cert: a renewal pushed mid-session is stored and used on a fresh login\n"
                : "cert: a mid-session certificate for another key is refused\n");
    fresh_dir();
    char *old = install_cert(-62 * DAY, 28 * DAY);      /* renewal due */

    X509 *nx = make_cert(good ? g_key : g_other_key, CALL, 0, 90 * DAY, g_ca, g_ca_key);
    char want[65];
    snprintf(want, sizeof(want), "%s", fingerprint(nx));

    fakerefl f;
    fr_start(&f);
    f.push_pem = pem_of_cert(nx);
    X509_free(nx);
    fr_run(&f);

    rc_obs obs = { 0 };
    rc_callbacks cb = { .user = &obs, .on_state = obs_state };
    rc_client *rc = rc_new(&g_cfg, &cb);
    rc_start(rc);

    uint64_t until = now_ms() + (good ? 8000 : 4000);
    while (now_ms() < until) {
        struct pollfd p[8];
        int n = rc_poll_fds(rc, p, 8);
        poll(p, (nfds_t)n, 50);
        rc_service(rc, now_ms());
        if (good && obs.connected >= 2) break;
    }
    rc_stop(rc, "test over");
    rc_free(rc);
    fr_stop(&f);

    if (good) {
        CHECK(!same_file(g_crt, old), "the certificate file was replaced");
        CHECK(same_file(g_crt, f.push_pem ? f.push_pem : ""), "with the pushed one");
        CHECK(!tmp_left(), "no temporary file is left behind");
        CHECK(obs.connected >= 2, "the client logged in again (%d logins)", obs.connected);
        CHECK(f.sessions >= 2 && strcmp(f.presented[1], want) == 0,
              "the second login presented the renewed certificate");
        CHECK(obs.closed_msgs == 0, "without being kicked first");
    } else {
        CHECK(same_file(g_crt, old), "the certificate on disk is untouched");
        CHECK(f.pushed == 1, "(the push did happen)");
    }
    free(f.push_pem);
    free(old);
    rm_dir();
}

/* ------------------------------------ refused in the TLS handshake */

/* A certificate that is valid by our clock, but the reflector will not have
 * it: revoked or removed there, or its clock disagrees. It says so with a
 * certificate alert in the TLS handshake. The login must recognise that, say
 * it plainly, and go the way of an expired certificate: no certificate, and a
 * request from the same key. */
static void t_refused_login_requests_new_cert(int signed_) {
    printf(signed_ ? "cert: a certificate the reflector refuses in TLS is replaced through a request\n"
                   : "cert: a refused certificate with nothing signed yet says so\n");
    fresh_dir();
    char *old = install_cert(-10 * DAY, 80 * DAY);       /* healthy, by our clock */
    X509 *ox  = NULL;
    { FILE *fp = fopen(g_crt, "r"); ox = PEM_read_X509(fp, NULL, NULL, NULL); fclose(fp); }
    char old_fp[65];
    fingerprint_into(ox, old_fp);
    X509_free(ox);

    fakerefl f;
    fr_start(&f);
    f.sign_csr = signed_;
    snprintf(f.refuse_fp, sizeof(f.refuse_fp), "%s", old_fp);
    fr_run(&f);

    handshake_result r;
    log_reset();
    int rc = handshake_run(&g_cfg, &r, NULL);
    CHECK(rc != 0 && strcmp(r.cert_rejected, old_fp) == 0,
          "the login fails and names the refused certificate (%s)", r.err);
    CHECK(strstr(r.err, "refused our certificate") && strstr(r.err, "revoked"),
          "the reason says the reflector refused it, and how: %s", r.err);
    CHECK(log_has("refused our certificate in the TLS handshake") && log_has("same key"),
          "the log explains it and says what happens next");

    /* The next attempt, told what was refused, goes without it. */
    handshake_result r2;
    log_reset();
    rc = handshake_run_ex(&g_cfg, &r2, NULL, r.cert_rejected);
    CHECK(rc != 0, "the second login ends too (%s)", r2.err);
    CHECK(log_has("not presenting the certificate the reflector refused"), "and says why");

    fr_stop(&f);
    CHECK(f.refused == 1 && f.sessions == 2, "one refusal in two sessions (%d, %d)",
          f.refused, f.sessions);
    CHECK(strcmp(f.presented[0], old_fp) == 0, "the first presented the certificate");
    CHECK(f.presented[1][0] == '\0', "the second presented none");
    CHECK(f.got_csr == 1 && csr_pubkey_is_ours(), "and sent a request from our key");
    CHECK(same_file(g_key_path, g_key_pem), "the key was not replaced");
    if (signed_) {
        CHECK(r2.cert_renewed, "the signed certificate was stored");
        CHECK(!same_file(g_crt, old), "the refused certificate on disk was replaced");
    } else {
        CHECK(!r2.cert_renewed && strstr(r2.err, "refused our certificate") &&
              strstr(r2.err, "sysop"), "the wait for the sysop is explained: %s", r2.err);
        CHECK(same_file(g_crt, old), "the certificate on disk is kept");
    }
    free(old);
    rm_dir();
}

/* The same through the client, which owns the state between attempts: it
 * must remember the refusal across connects, and forget it once a new
 * certificate is in. */
static void t_refused_across_attempts(void) {
    printf("cert: the client remembers a refused certificate across attempts, until it is replaced\n");
    fresh_dir();
    char *old = install_cert(-10 * DAY, 80 * DAY);
    X509 *ox  = NULL;
    { FILE *fp = fopen(g_crt, "r"); ox = PEM_read_X509(fp, NULL, NULL, NULL); fclose(fp); }
    char old_fp[65];
    fingerprint_into(ox, old_fp);
    X509_free(ox);

    fakerefl f;
    fr_start(&f);
    f.sign_csr = 1;
    snprintf(f.refuse_fp, sizeof(f.refuse_fp), "%s", old_fp);
    fr_run(&f);

    rc_obs obs = { 0 };
    rc_callbacks cb = { .user = &obs, .on_state = obs_state };
    rc_client *rc = rc_new(&g_cfg, &cb);
    rc_start(rc);
    uint64_t until = now_ms() + 12000;
    while (now_ms() < until && obs.connected < 1) {
        struct pollfd p[8];
        int n = rc_poll_fds(rc, p, 8);
        poll(p, (nfds_t)n, 50);
        rc_service(rc, now_ms());
    }
    rc_stop(rc, "test over");
    rc_free(rc);
    fr_stop(&f);

    char new_fp[65] = "";
    X509 *nx = NULL;
    { FILE *fp = fopen(g_crt, "r"); nx = PEM_read_X509(fp, NULL, NULL, NULL); fclose(fp); }
    if (nx) { fingerprint_into(nx, new_fp); X509_free(nx); }

    CHECK(obs.connected == 1, "the client logged in in the end (%d)", obs.connected);
    CHECK(f.sessions == 3, "in three sessions: refused, request, login (%d)", f.sessions);
    CHECK(f.refused == 1, "the refused certificate was offered once only (%d)", f.refused);
    CHECK(f.presented[1][0] == '\0', "the attempt after the refusal presented none");
    CHECK(strcmp(new_fp, old_fp) != 0 && strcmp(f.presented[2], new_fp) == 0,
          "the login after the renewal presented the new certificate");
    CHECK(same_file(g_key_path, g_key_pem), "with the same key");
    free(old);
    rm_dir();
}

/* ------------------------------------------------ --enroll, expired */

static void t_enroll_expired(void) {
    printf("cert: --enroll replaces an expired certificate instead of reporting success\n");
    fresh_dir();
    char *old = install_cert(-91 * DAY, -DAY);

    fakerefl f;
    fr_start(&f);
    f.sign_csr = 1;
    fr_run(&f);

    log_reset();
    int rc = enroll_run(&g_cfg, 1);
    fr_stop(&f);

    CHECK(rc == 0, "enrolment succeeds");
    CHECK(f.sessions >= 1 && f.got_csr == 1, "after actually asking the reflector");
    CHECK(f.presented[0][0] == '\0', "without presenting the expired certificate");
    CHECK(!same_file(g_crt, old), "the certificate was replaced");
    CHECK(same_file(g_key_path, g_key_pem), "the key was kept");
    CHECK(enroll_have_usable_cert(&g_cfg, time(NULL)) == 1, "and it is usable now");
    CHECK(log_has("EXPIRED"), "the log says why");
    free(old);
    rm_dir();
}

static void t_enroll_wrong_cert(void) {
    printf("cert: --enroll does not store a certificate for another key\n");
    fresh_dir();
    free(install_cert(-91 * DAY, -DAY));
    char *old = get_file(g_crt);

    fakerefl f;
    fr_start(&f);
    f.sign_csr     = 1;
    f.sign_pub_key = g_other_key;     /* hand back somebody else's certificate */
    fr_run(&f);

    log_reset();
    int rc = enroll_run(&g_cfg, 1);
    fr_stop(&f);

    CHECK(rc < 0, "enrolment reports an error (rc %d)", rc);
    CHECK(f.got_csr == 1, "(the reflector did answer the request)");
    CHECK(same_file(g_crt, old), "the certificate on disk is unchanged");
    CHECK(log_has("private key"), "and the log says why");
    free(old);
    rm_dir();
}

/* ------------------------------------------------------------------ main */

int main(void) {
    g_verbose = getenv("CERTTEST_VERBOSE") != NULL;
    signal(SIGALRM, on_test_timeout);
#ifdef __linux__
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);        /* for eu-stack, above */
#endif
    g_limit_s   = getenv("CERTTEST_TIMEOUT") ? atoi(getenv("CERTTEST_TIMEOUT")) : 0;
    g_current_s = g_limit_s ? g_limit_s : 60;
    alarm((unsigned)g_current_s);                     /* setup: keys, certificates */
    log_set_level(LOG_DBG);
    log_set_sink(sink, NULL);

    printf("\ncertificate fixtures\n\n");

    g_ca_key    = new_key();
    g_key       = new_key();
    g_other_key = new_key();
    g_ca        = make_cert(g_ca_key, "Test Reflector CA", -365 * DAY, 3650 * DAY, NULL, NULL);
    g_key_pem   = pem_of_key(g_key);

    config_defaults(&g_cfg);
    snprintf(g_cfg.callsign,  sizeof(g_cfg.callsign),  "%s", CALL);
    snprintf(g_cfg.email,     sizeof(g_cfg.email),     "test@example.invalid");
    snprintf(g_cfg.reflector, sizeof(g_cfg.reflector), "127.0.0.1");

    RUN(60, t_status());
    RUN(60, t_expired_file_detected());
    RUN(60, t_banner());
    RUN(60, t_push());
    RUN(60, t_csr_keeps_key());
    RUN(60, t_expired_login_requests_new_cert());
    RUN(60, t_expired_login_unsigned());
    RUN(60, t_midsession_push(1));
    RUN(60, t_midsession_push(0));
    RUN(60, t_refused_login_requests_new_cert(1));
    RUN(60, t_refused_login_requests_new_cert(0));
    RUN(60, t_refused_across_attempts());
    RUN(60, t_enroll_expired());
    RUN(60, t_enroll_wrong_cert());

    printf("\n%d checks, %d failed\n\n", g_run, g_fail);
    return g_fail ? 1 : 0;
}
