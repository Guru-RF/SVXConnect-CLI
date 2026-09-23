/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * Connection fixtures: the real reflector client against a fake reflector on
 * loopback (tests/fakerefl.c).
 *
 * What they pin down is behaviour an embedding GUI depends on and the unit
 * tests cannot see: that disconnecting, reconnecting or pressing PTT never
 * freezes the calling thread however the server misbehaves; that a reason the
 * reflector gives before it hangs up reaches the log; that different ways of
 * losing the link read differently; that a silent link is noticed; and that
 * sockets are only closed inside the service call.
 *
 * Run with `make check` (also under TSan and ASan: `make check-tsan`,
 * `make check-asan`). The TLS handshake timeout test waits the full 15 s.
 * CONNECTTEST_ONLY=stop-silent,fds,... runs a subset; CONNECTTEST_DEBUG=1
 * shows the client's own log.
 */
#include "fakerefl.h"

#include "app.h"
#include "common/config.h"
#include "common/log.h"
#include "common/tls.h"
#include "common/util.h"
#include "reflector/client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>

static int g_fail, g_run;

#define CHECK(cond, ...) do {                               \
    g_run++;                                                \
    if (!(cond)) { g_fail++; printf("  FAIL  " __VA_ARGS__);\
                   printf("\n        at %s:%d\n", __FILE__, __LINE__); } \
} while (0)

/* How long a caller may be held by stop / reconnect / PTT. The audit measured
 * 14 s and "forever"; anything in the tens of milliseconds is fine. */
#define MAX_CALL_MS 250

static char        g_pki[256];
static svx_config  g_cfg;

/* What the client reported. */
static char g_error[512];
static int  g_errors;

static void cb_error(void *u, const char *msg) {
    (void)u;
    snprintf(g_error, sizeof(g_error), "%s", msg);
    g_errors++;
}

static rc_client *new_client(int port) {
    g_cfg.port = port;
    g_error[0] = '\0';
    g_errors   = 0;
    rc_callbacks cb = { .on_error = cb_error };
    return rc_new(&g_cfg, &cb);
}

/* Run the service loop the way a front end does, for up to `ms`, or until
 * the client reaches `want` (pass -1 to just run for `ms`). */
static int run_until(rc_client *c, int want, int ms) {
    uint64_t until = now_ms() + (uint64_t)ms;
    while (now_ms() < until) {
        struct pollfd p[8];
        int n = rc_poll_fds(c, p, 8);
        int to = rc_next_timeout_ms(c, now_ms());
        poll(p, (nfds_t)n, to > 20 ? 20 : to);
        rc_service(c, now_ms());
        if (want >= 0 && (int)rc_get_state(c) == want) return 1;
    }
    return want < 0;
}

/* CONNECTTEST_ONLY=name[,name...] runs a subset. */
static int want(const char *name) {
    const char *only = getenv("CONNECTTEST_ONLY");
    if (!only || !*only) return 1;
    size_t n = strlen(name);
    for (const char *p = only; (p = strstr(p, name)) != NULL; p += n)
        if ((p == only || p[-1] == ',') && (p[n] == '\0' || p[n] == ',')) return 1;
    return 0;
}

static int fd_open(int fd) { return fcntl(fd, F_GETFD) != -1 || errno != EBADF; }

/* ------------------------------------------------------------ freezes */

/* The worker is mid-handshake (server silent, or stalled inside TLS); the
 * user disconnects. rc_stop() must return at once, and the abandoned worker
 * must still let go of its socket promptly. */
static void t_stop_does_not_block(fr_mode mode, const char *what) {
    printf("connect: rc_stop while %s returns at once\n", what);
    fakerefl f = { 0 };
    CHECK(fr_start(&f, mode, FR_HOLD, g_pki, "TEST") == 0, "fake reflector did not start");

    rc_client *c = new_client(f.port);
    rc_start(c);
    run_until(c, -1, 400);
    CHECK(rc_get_state(c) == RC_CONNECTING, "expected to still be connecting, state %s",
          rc_state_name(rc_get_state(c)));

    uint64_t t0 = now_ms();
    rc_stop(c, "disconnected by you");
    uint64_t took = now_ms() - t0;
    CHECK(took < MAX_CALL_MS, "rc_stop blocked the caller for %llu ms", (unsigned long long)took);
    CHECK(rc_get_state(c) == RC_IDLE, "not idle after rc_stop");

    /* The worker notices the abort within its 100 ms slices and closes. */
    uint64_t until = now_ms() + 2000;
    while (!atomic_load(&f.client_gone_at) && now_ms() < until) msleep(10);
    uint64_t gone = atomic_load(&f.client_gone_at);
    CHECK(gone != 0 && gone - t0 < 1000,
          "the abandoned worker kept its socket for %lld ms", gone ? (long long)(gone - t0) : -1LL);

    rc_free(c);
    fr_stop(&f);
}

static void t_reconnect_does_not_block(void) {
    printf("connect: rc_reconnect_now while connecting returns at once\n");
    fakerefl f = { 0 };
    CHECK(fr_start(&f, FR_STALL_TLS, FR_HOLD, g_pki, "TEST") == 0, "fake reflector did not start");

    rc_client *c = new_client(f.port);
    rc_start(c);
    run_until(c, -1, 400);

    uint64_t t0 = now_ms();
    rc_reconnect_now(c);
    uint64_t took = now_ms() - t0;
    CHECK(took < MAX_CALL_MS, "rc_reconnect_now blocked the caller for %llu ms",
          (unsigned long long)took);
    CHECK(rc_get_state(c) == RC_CONNECTING, "not connecting after rc_reconnect_now");
    run_until(c, -1, 300);
    CHECK(atomic_load(&f.accepts) == 2, "expected a second attempt, saw %d connections",
          atomic_load(&f.accepts));

    t0 = now_ms();
    rc_free(c);
    took = now_ms() - t0;
    CHECK(took < 1000, "rc_free took %llu ms", (unsigned long long)took);
    fr_stop(&f);
}

/* SSL_connect() used to block with no timeout: a server that answers
 * StartEncryption and then never speaks TLS left the client "connecting"
 * forever. It must now give up after the per-step timeout and back off. */
static void t_tls_handshake_times_out(void) {
    printf("connect: a TLS handshake the server never answers times out (15 s)\n");
    fakerefl f = { 0 };
    CHECK(fr_start(&f, FR_STALL_TLS, FR_HOLD, g_pki, "TEST") == 0, "fake reflector did not start");

    rc_client *c = new_client(f.port);
    rc_start(c);
    uint64_t t0 = now_ms();
    int backed_off = run_until(c, RC_BACKOFF, 20000);
    CHECK(backed_off, "still %s after 20 s", rc_state_name(rc_get_state(c)));
    CHECK(strstr(rc_last_error(c), "timed out") != NULL, "reason: '%s'", rc_last_error(c));
    printf("        gave up after %llu ms: %s\n", (unsigned long long)(now_ms() - t0),
           rc_last_error(c));
    rc_free(c);
    fr_stop(&f);
}

/* PTT while a connect is in flight: refuse it, but do not throw the login
 * away (MEDIUM-1), and do not block (HIGH-1). Driven through the app, the
 * way every front end reaches it. */
static void t_ptt_while_connecting(void) {
    printf("connect: PTT while connecting neither blocks nor restarts the login\n");
    fakerefl f = { 0 };
    CHECK(fr_start(&f, FR_SILENT, FR_HOLD, g_pki, "TEST") == 0, "fake reflector did not start");

    g_cfg.port = f.port;
    int level = log_get_level();
    log_set_level(LOG_DBG);            /* into the ring below, not the terminal */
    svx_app *a = app_new(&g_cfg, 1);
    app_capture_log(a);                /* the worker now logs into the app's ring */
    app_reconnect(a);
    for (int i = 0; i < 20; i++) {     /* main-thread logging racing the worker's */
        app_service(a, now_ms());
        log_info("main tick %d", i);
        msleep(20);
    }
    CHECK(rc_get_state(app_rc(a)) == RC_CONNECTING, "expected to be connecting");

    uint64_t t0 = now_ms();
    app_ptt(a, CTL_ON);
    app_ptt(a, CTL_ON);
    uint64_t took = now_ms() - t0;
    CHECK(took < MAX_CALL_MS, "PTT blocked the caller for %llu ms", (unsigned long long)took);
    for (int i = 0; i < 15; i++) { app_service(a, now_ms()); msleep(20); }
    CHECK(atomic_load(&f.accepts) == 1, "PTT restarted the connect: %d connections",
          atomic_load(&f.accepts));

    t0 = now_ms();
    app_toggle_connect(a);
    took = now_ms() - t0;
    CHECK(took < MAX_CALL_MS, "disconnect blocked the caller for %llu ms", (unsigned long long)took);

    app_log_line lines[APP_LOG_LINES];
    int n = app_log_snapshot(a, lines, APP_LOG_LINES);
    int saw_refusal = 0;
    for (int i = 0; i < n; i++)
        if (strstr(lines[i].text, "PTT refused: still connecting")) saw_refusal = 1;
    CHECK(saw_refusal, "no 'PTT refused: still connecting' in the log");

    app_free(a);
    log_set_level(level);
    fr_stop(&f);
}

/* ----------------------------------------------------- why it dropped */

/* The reflector sends MsgError and hangs up in the same breath. The text
 * must reach on_error and rc_last_error(), not be freed with the buffer. */
static void t_error_before_close(fr_after how, const char *what) {
    printf("connect: MsgError followed by %s reaches the log\n", what);
    fakerefl f = { .error_text = "TCP heartbeat timeout" };
    CHECK(fr_start(&f, FR_LOGIN, how, g_pki, "TEST") == 0, "fake reflector did not start");

    rc_client *c = new_client(f.port);
    rc_start(c);
    CHECK(run_until(c, RC_CONNECTED, 5000), "never connected: %s", rc_last_error(c));
    CHECK(run_until(c, RC_BACKOFF, 3000), "did not notice the close");

    CHECK(g_errors == 1 && strcmp(g_error, "TCP heartbeat timeout") == 0,
          "on_error got %d call(s), last '%s'", g_errors, g_error);
    CHECK(strstr(rc_last_error(c), "the reflector closed the connection: TCP heartbeat timeout"),
          "reason: '%s'", rc_last_error(c));
    const char *kind = how == FR_ERROR_NOTIFY ? "(TLS close_notify" : "(TCP close, no TLS close_notify";
    CHECK(strstr(rc_last_error(c), kind), "expected '%s' in '%s'", kind, rc_last_error(c));
    printf("        %s\n", rc_last_error(c));
    rc_free(c);
    fr_stop(&f);
}

static void t_reset_reads_as_reset(void) {
    printf("connect: a reset is not reported as the reflector closing\n");
    fakerefl f = { 0 };
    CHECK(fr_start(&f, FR_LOGIN, FR_RESET, g_pki, "TEST") == 0, "fake reflector did not start");

    rc_client *c = new_client(f.port);
    rc_start(c);
    CHECK(run_until(c, RC_CONNECTED, 5000), "never connected: %s", rc_last_error(c));
    CHECK(run_until(c, RC_BACKOFF, 3000), "did not notice the reset");
    CHECK(strstr(rc_last_error(c), "the connection was reset") &&
          strstr(rc_last_error(c), "ECONNRESET"), "reason: '%s'", rc_last_error(c));
    CHECK(!strstr(rc_last_error(c), "closed the connection"), "reason: '%s'", rc_last_error(c));
    printf("        %s\n", rc_last_error(c));
    rc_free(c);
    fr_stop(&f);
}

/* ----------------------------------------------------- liveness */

static void t_rx_watchdog(void) {
    printf("connect: a reflector that goes quiet without closing is dropped\n");
    fakerefl f = { 0 };
    CHECK(fr_start(&f, FR_LOGIN, FR_HOLD, g_pki, "TEST") == 0, "fake reflector did not start");

    rc_client *c = new_client(f.port);
    rc_set_rx_timeout(c, 1500);
    rc_start(c);
    CHECK(run_until(c, RC_CONNECTED, 5000), "never connected: %s", rc_last_error(c));
    uint64_t t0 = now_ms();
    CHECK(run_until(c, RC_BACKOFF, 4000), "still %s 4 s into the silence",
          rc_state_name(rc_get_state(c)));
    uint64_t took = now_ms() - t0;
    CHECK(took >= 1000 && took <= 2500, "dropped after %llu ms", (unsigned long long)took);
    CHECK(strstr(rc_last_error(c), "no data from the reflector"), "reason: '%s'", rc_last_error(c));
    rc_free(c);
    fr_stop(&f);
}

/* UDP can die while TCP lives: they hold separate NAT mappings, and the
 * control channel's traffic keeps only its own alive. Audio then stops with
 * the UI still saying "connected". Once UDP has worked in a session, silence
 * on it must log in again, and say why. */
static void t_udp_watchdog(void) {
    printf("connect: UDP that goes quiet while TCP stays up logs in again\n");
    fakerefl f = { 0 };
    CHECK(fr_start(&f, FR_LOGIN, FR_UDP_THEN_QUIET, g_pki, "TEST") == 0 && f.ufd >= 0,
          "fake reflector did not start");

    rc_client *c = new_client(f.port);
    rc_set_udp_rx_timeout(c, 1500);
    rc_start(c);
    CHECK(run_until(c, RC_CONNECTED, 5000), "never connected: %s", rc_last_error(c));
    uint64_t t0 = now_ms();
    run_until(c, -1, 700);
    rc_stats st;
    rc_get_stats(c, &st);
    CHECK(st.rx_packets > 0, "no UDP heartbeat was received (the fake sent %d)",
          atomic_load(&f.udp_sent));
    CHECK(rc_get_state(c) == RC_CONNECTED, "dropped while UDP was flowing: %s", rc_last_error(c));

    /* UDP stops ~800 ms after login (300 ms settling + 500 ms of beats). */
    CHECK(run_until(c, RC_BACKOFF, 4000), "still %s 4 s into the UDP silence",
          rc_state_name(rc_get_state(c)));
    uint64_t took = now_ms() - t0;
    CHECK(took >= 1500 && took <= 3500, "dropped %llu ms after login", (unsigned long long)took);
    CHECK(strstr(rc_last_error(c), "no UDP from the reflector") &&
          strstr(rc_last_error(c), "control channel is up"), "reason: '%s'", rc_last_error(c));
    printf("        %s\n", rc_last_error(c));

    /* It logs in again: a new login is what opens a new mapping. */
    CHECK(run_until(c, RC_CONNECTED, 5000), "did not log in again: %s", rc_last_error(c));
    CHECK(atomic_load(&f.logged_in) == 2, "expected a second login, saw %d",
          atomic_load(&f.logged_in));
    rc_free(c);
    fr_stop(&f);
}

static void t_udp_steady_is_left_alone(void) {
    printf("connect: steady UDP heartbeats keep the session\n");
    fakerefl f = { 0 };
    CHECK(fr_start(&f, FR_LOGIN, FR_UDP_STEADY, g_pki, "TEST") == 0 && f.ufd >= 0,
          "fake reflector did not start");

    rc_client *c = new_client(f.port);
    rc_set_udp_rx_timeout(c, 1000);
    rc_start(c);
    CHECK(run_until(c, RC_CONNECTED, 5000), "never connected: %s", rc_last_error(c));
    run_until(c, -1, 3000);
    CHECK(rc_get_state(c) == RC_CONNECTED, "dropped: %s", rc_last_error(c));
    rc_stats st;
    rc_get_stats(c, &st);
    CHECK(st.rx_packets >= 15, "only %llu datagrams in 3 s", (unsigned long long)st.rx_packets);
    CHECK(atomic_load(&f.logged_in) == 1, "%d logins", atomic_load(&f.logged_in));
    rc_free(c);
    fr_stop(&f);
}

static pthread_mutex_t g_warn_mu = PTHREAD_MUTEX_INITIALIZER;
static char            g_warn[512];
static int             g_warns;

static void warn_sink(int level, const char *line, void *u) {
    (void)u;
    if (level > LOG_WARN) return;
    pthread_mutex_lock(&g_warn_mu);
    if (strstr(line, "UDP")) { snprintf(g_warn, sizeof(g_warn), "%s", line); g_warns++; }
    pthread_mutex_unlock(&g_warn_mu);
}

/* A session in which no UDP ever arrives is not dropped every minute — that
 * would change nothing — but said once, plainly. */
static void t_udp_never(void) {
    printf("connect: UDP that never arrives is warned about once, not reconnected\n");
    fakerefl f = { 0 };
    CHECK(fr_start(&f, FR_LOGIN, FR_TCP_ONLY, g_pki, "TEST") == 0, "fake reflector did not start");

    int level = log_get_level();
    log_set_level(LOG_WARN);
    g_warns = 0;
    log_set_sink(warn_sink, NULL);

    rc_client *c = new_client(f.port);
    rc_set_udp_rx_timeout(c, 800);
    rc_start(c);
    CHECK(run_until(c, RC_CONNECTED, 5000), "never connected: %s", rc_last_error(c));
    run_until(c, -1, 2500);
    CHECK(rc_get_state(c) == RC_CONNECTED, "dropped: %s", rc_last_error(c));
    CHECK(atomic_load(&f.logged_in) == 1, "%d logins", atomic_load(&f.logged_in));

    log_set_sink(NULL, NULL);
    log_set_level(level);
    CHECK(g_warns == 1 && strstr(g_warn, "nothing received over UDP"),
          "%d UDP warning(s), last '%s'", g_warns, g_warn);
    rc_free(c);
    fr_stop(&f);
}

/* ----------------------------------------------------- fd lifetime */

/* rc_stop() from a button handler must not close descriptors an event loop
 * is still watching: they stay open until the next rc_service(), and the
 * wake pipe tells the loop to run it. */
static void t_fds_close_inside_service(void) {
    printf("connect: rc_stop leaves the sockets for rc_service to close\n");
    fakerefl f = { 0 };
    CHECK(fr_start(&f, FR_LOGIN, FR_HOLD, g_pki, "TEST") == 0, "fake reflector did not start");

    rc_client *c = new_client(f.port);
    rc_start(c);
    CHECK(run_until(c, RC_CONNECTED, 5000), "never connected: %s", rc_last_error(c));

    struct pollfd before[8];
    int nb = rc_poll_fds(c, before, 8);
    CHECK(nb == 3, "expected wake pipe + TCP + UDP, got %d fds", nb);

    rc_stop(c, "disconnected by you");
    for (int i = 1; i < nb; i++)
        CHECK(fd_open(before[i].fd), "fd %d closed outside rc_service", before[i].fd);

    struct pollfd after[8];
    int na = rc_poll_fds(c, after, 8);
    CHECK(na == 1 && after[0].fd == before[0].fd, "the dropped sockets are still offered to poll");
    CHECK(poll(after, 1, 0) == 1, "the wake pipe did not ask for a service pass");

    rc_service(c, now_ms());
    for (int i = 1; i < nb; i++)
        CHECK(!fd_open(before[i].fd), "fd %d still open after rc_service", before[i].fd);

    rc_free(c);
    fr_stop(&f);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);

    snprintf(g_pki, sizeof(g_pki), "/tmp/svxconnect-test-XXXXXX");
    if (!mkdtemp(g_pki)) { perror("mkdtemp"); return 1; }
    if (fr_make_pki(g_pki, "TEST") != 0) { printf("cannot make a test certificate\n"); return 1; }

    config_defaults(&g_cfg);
    snprintf(g_cfg.callsign,  sizeof(g_cfg.callsign),  "TEST");
    snprintf(g_cfg.reflector, sizeof(g_cfg.reflector), "127.0.0.1");
    snprintf(g_cfg.pki_dir,   sizeof(g_cfg.pki_dir),   "%s", g_pki);
    g_cfg.ctl_fifo[0]    = '\0';
    g_cfg.status_file[0] = '\0';
    /* Quiet unless asked: the tests provoke plenty of errors on purpose. */
    log_set_level(getenv("CONNECTTEST_DEBUG") ? LOG_DBG : LOG_ERR);

    if (want("stop-silent"))    t_stop_does_not_block(FR_SILENT,    "the server is silent");
    if (want("stop-stall-tls")) t_stop_does_not_block(FR_STALL_TLS, "the TLS handshake is stalled");
    if (want("reconnect"))      t_reconnect_does_not_block();
    if (want("ptt"))            t_ptt_while_connecting();
    if (want("error-notify"))   t_error_before_close(FR_ERROR_NOTIFY, "close_notify");
    if (want("error-eof"))      t_error_before_close(FR_ERROR_EOF,    "a bare close");
    if (want("reset"))          t_reset_reads_as_reset();
    if (want("watchdog"))       t_rx_watchdog();
    if (want("udp-watchdog"))   t_udp_watchdog();
    if (want("udp-steady"))     t_udp_steady_is_left_alone();
    if (want("udp-never"))      t_udp_never();
    if (want("fds"))            t_fds_close_inside_service();
    if (want("tls-timeout"))    t_tls_handshake_times_out();

    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_pki);
    if (system(cmd) != 0) { /* a leftover temp dir is harmless */ }

    printf("\n%d checks, %d failed\n", g_run, g_fail);
    return g_fail ? 1 : 0;
}
