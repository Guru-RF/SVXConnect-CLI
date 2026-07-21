/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — Copyright (C) 2026 Joeri Van Dooren
 */
#include "headless.h"

#include "common/log.h"
#include "common/util.h"
#include "reflector/client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>

static volatile sig_atomic_t g_quit;

static void on_signal(int sig) { (void)sig; g_quit = 1; }

typedef struct {
    const svx_config *cfg;
    rc_client        *rc;
    uint64_t          audio_frames;
    uint64_t          last_audio_log;
} hl_app;

/* ------------------------------------------------------------ callbacks */

static void hl_state(void *u, rc_state st, const char *detail) {
    hl_app *a = u;
    if (detail && *detail) log_info("[%s] %s", rc_state_name(st), detail);
    else                   log_info("[%s]", rc_state_name(st));

    if (st == RC_CONNECTED) {
        log_info("client id %u, %d nodes, %s:%u",
                 rc_client_id(a->rc), rc_node_count(a->rc),
                 rc_host(a->rc), rc_port(a->rc));
    }
}

static void hl_talker_start(void *u, uint32_t tg, const char *call) {
    (void)u;
    log_info("TALKER START  TG %-6u %s", tg, call);
}

static void hl_talker_stop(void *u, uint32_t tg, const char *call) {
    (void)u;
    log_info("TALKER STOP   TG %-6u %s", tg, call);
}

static void hl_audio(void *u, const uint8_t *opus, size_t len, int gap) {
    hl_app *a = u;
    (void)opus;
    a->audio_frames++;
    if (gap > 0) log_dbg("audio: %d frame%s lost", gap, gap == 1 ? "" : "s");

    /* Audio arrives 50 times a second; summarise rather than flood. */
    uint64_t now = now_ms();
    if (now - a->last_audio_log >= 5000) {
        a->last_audio_log = now;
        log_dbg("audio: %llu frames, last %zu bytes",
                (unsigned long long)a->audio_frames, len);
    }
}

static void hl_node(void *u, int joined, const char *call) {
    (void)u;
    log_info("NODE %-5s    %s", joined ? "JOIN" : "LEFT", call);
}

static void hl_flushed(void *u) {
    (void)u;
    log_dbg("all samples flushed");
}

static void hl_error(void *u, const char *msg) {
    (void)u;
    log_warn("reflector error: %s", msg);
}

/* ----------------------------------------------------------------- run */

int run_headless(const svx_config *cfg, int no_tx) {
    hl_app app;
    memset(&app, 0, sizeof(app));
    app.cfg = cfg;

    /* No SA_RESTART: we want poll() to return EINTR so the loop notices. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    rc_callbacks cb = {
        .user            = &app,
        .on_state        = hl_state,
        .on_talker_start = hl_talker_start,
        .on_talker_stop  = hl_talker_stop,
        .on_audio        = hl_audio,
        .on_node         = hl_node,
        .on_flushed      = hl_flushed,
        .on_error        = hl_error,
    };

    app.rc = rc_new(cfg, &cb);
    if (!app.rc) {
        log_err("out of memory");
        return 1;
    }

    /* Watch everything the config names, whether switchable or monitored —
     * arrowing onto a talkgroup you cannot hear would be useless. */
    uint32_t mon[SVX_MAX_TG * 2];
    size_t   n_mon = 0;
    for (int i = 0; i < cfg->n_monitored && n_mon < sizeof(mon) / sizeof(mon[0]); i++)
        mon[n_mon++] = cfg->monitored[i].id;
    for (int i = 0; i < cfg->n_switchable && n_mon < sizeof(mon) / sizeof(mon[0]); i++) {
        int dup = 0;
        for (size_t j = 0; j < n_mon; j++) if (mon[j] == cfg->switchable[i].id) { dup = 1; break; }
        if (!dup) mon[n_mon++] = cfg->switchable[i].id;
    }
    rc_set_monitor(app.rc, mon, n_mon);

    uint32_t start_tg = (uint32_t)cfg->default_tg;
    if (start_tg == 0 && cfg->n_switchable > 0) start_tg = cfg->switchable[0].id;
    rc_select_tg(app.rc, start_tg);

    log_info("svxconnect headless — %s -> %s:%d%s",
             cfg->callsign, cfg->reflector, cfg->port, no_tx ? " (receive only)" : "");
    log_info("monitoring %zu talkgroup%s, starting on TG %u",
             n_mon, n_mon == 1 ? "" : "s", start_tg);

    rc_start(app.rc);

    uint64_t last_report = now_ms();

    while (!g_quit) {
        uint64_t now = now_ms();

        struct pollfd p[8];
        int n  = rc_poll_fds(app.rc, p, 8);
        int to = rc_next_timeout_ms(app.rc, now);

        int pr = poll(p, (nfds_t)n, to);
        if (pr < 0 && errno != EINTR) {
            log_err("poll failed: %s", strerror(errno));
            break;
        }

        rc_service(app.rc, now_ms());

        /* A periodic line so a long-running session shows it is alive and so
         * loss and throughput problems are visible in the log after the fact. */
        now = now_ms();
        if (now - last_report >= 60000) {
            last_report = now;
            rc_stats st;
            rc_get_stats(app.rc, &st);
            log_info("stats: rx %llu pkt (%d/s), tx %llu pkt, lost %llu (%.1f%%), "
                     "replayed %llu, bad-auth %llu",
                     (unsigned long long)st.rx_packets, st.rx_pps,
                     (unsigned long long)st.tx_packets,
                     (unsigned long long)st.rx_lost, st.loss_pct,
                     (unsigned long long)st.rx_replayed,
                     (unsigned long long)st.rx_auth_fail);
        }
    }

    log_info("shutting down");
    rc_stop(app.rc, "quit");
    rc_free(app.rc);
    return 0;
}
