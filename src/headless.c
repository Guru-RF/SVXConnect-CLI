/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — Copyright (C) 2026 Joeri Van Dooren
 */
#include "headless.h"

#include "audio/codec.h"
#include "audio/dev.h"
#include "audio/jitter.h"
#include "common/log.h"
#include "common/ring.h"
#include "common/util.h"
#include "ctl/ctlfifo.h"
#include "reflector/client.h"
#include "tg/tgmanager.h"

#include <math.h>
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

    /* receive path */
    svx_codec        *codec;
    svx_ring          play_ring;
    svx_dev          *play_dev;
    svx_jitter        jb;
    _Atomic float     spk_peak;
    int               audio_ready;

    /* transmit path */
    svx_codec        *tx_codec;
    svx_ring          cap_ring;
    svx_dev          *cap_dev;
    _Atomic float     mic_peak;
    int               tx_ready;
    int               no_tx;
    int               tx_active;
    uint64_t          tx_started_ms;
    uint64_t          tx_frames;
    int16_t           tx_pcm[SVX_FRAME];

    /* who is talking right now, so PTT can refuse a busy talkgroup */
    uint32_t          busy_tg;
    char              busy_call[64];

    tg_manager        tgm;
    ctl_fifo          ctl;
    int               quit;
    uint64_t          last_report;
} hl_app;

static void tx_stop(hl_app *a, const char *why);

/* ------------------------------------------------------------ callbacks */

static void hl_state(void *u, rc_state st, const char *detail) {
    hl_app *a = u;
    if (detail && *detail) log_info("[%s] %s", rc_state_name(st), detail);
    else                   log_info("[%s]", rc_state_name(st));

    if (st == RC_CONNECTED) {
        log_info("client id %u, %d nodes, %s:%u",
                 rc_client_id(a->rc), rc_node_count(a->rc),
                 rc_host(a->rc), rc_port(a->rc));
        tgm_after_connect(&a->tgm);
    } else if (a->audio_ready) {
        /* Whatever was queued belongs to a connection that no longer exists. */
        jitter_flush(&a->jb);
    }
}

static void hl_talker_start(void *u, uint32_t tg, const char *call) {
    hl_app *a = u;
    log_info("TALKER START  TG %-6u %s", tg, call);
    if (tg == rc_current_tg(a->rc)) {
        a->busy_tg = tg;
        snprintf(a->busy_call, sizeof(a->busy_call), "%s", call);
    }
    tgm_on_talker_start(&a->tgm, tg, call);
}

static void hl_talker_stop(void *u, uint32_t tg, const char *call) {
    hl_app *a = u;
    log_info("TALKER STOP   TG %-6u %s", tg, call);

    /* Match on the CALLSIGN, not the talkgroup: the tg the server reports on
     * stop can differ from the one it reported on start, and filtering on both
     * leaves a ghost talker that never clears. */
    char stop_base[64], busy_base[64];
    call_strip_ssid(stop_base, sizeof(stop_base), call);
    call_strip_ssid(busy_base, sizeof(busy_base), a->busy_call);
    if (a->busy_call[0] && strcmp(stop_base, busy_base) == 0) {
        a->busy_tg = 0;
        a->busy_call[0] = '\0';
    }
    /* The manager owns the roger beep, the tail trim and the linger window. */
    tgm_on_talker_stop(&a->tgm, tg, call);
    if (a->audio_ready) jitter_end_of_stream(&a->jb);
}

static void hl_audio(void *u, const uint8_t *opus, size_t len, int gap) {
    hl_app *a = u;
    if (!a->audio_ready) return;
    jitter_push(&a->jb, opus, len, gap);
}

static void hl_node(void *u, int joined, const char *call) {
    (void)u;
    log_info("NODE %-5s    %s", joined ? "JOIN" : "LEFT", call);
}

static void hl_flushed(void *u) {
    hl_app *a = u;
    if (a->audio_ready) jitter_end_of_stream(&a->jb);
}

static void hl_error(void *u, const char *msg) {
    (void)u;
    log_warn("reflector error: %s", msg);
}

/* ------------------------------------------------------- audio set-up */

static int audio_start(hl_app *a) {
    if (svx_audio_init() != 0) {
        log_warn("no audio system available — running without sound");
        return -1;
    }

    a->codec = codec_open();
    if (!a->codec) { svx_audio_term(); return -1; }
    codec_set_agc(a->codec, a->cfg->mic_agc, a->cfg->mic_agc_target_pct);

    /* Half a second of playback buffer: comfortably more than the jitter
     * target so a burst never has to be dropped at the ring. */
    if (svx_ring_init(&a->play_ring, SVX_RATE / 2) != 0) {
        codec_close(a->codec); a->codec = NULL;
        svx_audio_term();
        return -1;
    }

    svx_devinfo out;
    svx_audio_resolve(0, a->cfg->output_device, &out);
    a->play_dev = svx_dev_open_playback(out.id, &a->play_ring, &a->spk_peak);
    if (!a->play_dev) {
        svx_ring_free(&a->play_ring);
        codec_close(a->codec); a->codec = NULL;
        svx_audio_term();
        return -1;
    }

    jitter_init(&a->jb, &a->play_ring, a->codec, a->cfg->jitter_ms);
    jitter_set_device(&a->jb, a->play_dev);
    jitter_set_volume(&a->jb, a->cfg->output_volume_pct);

    if (svx_dev_start(a->play_dev) != 0) {
        svx_dev_close(a->play_dev); a->play_dev = NULL;
        svx_ring_free(&a->play_ring);
        codec_close(a->codec); a->codec = NULL;
        svx_audio_term();
        return -1;
    }

    a->audio_ready = 1;
    log_info("audio out: %s (%s, %d Hz, %d ms jitter buffer)",
             svx_dev_name(a->play_dev), svx_audio_backend_name(),
             SVX_RATE, a->cfg->jitter_ms);
    return 0;
}

static void audio_stop(hl_app *a) {
    if (!a->audio_ready) return;
    a->audio_ready = 0;
    svx_dev_close(a->play_dev);  a->play_dev = NULL;
    svx_ring_free(&a->play_ring);
    codec_close(a->codec);       a->codec = NULL;
    svx_audio_term();
}


/* --------------------------------------------------------- transmit */

/* Short beeps carry meaning, and the vocabulary is the same one the macOS app
 * uses so it transfers between the two: 1 = roger, 2 = channel busy,
 * 3 = no link or no talkgroup selected. */
static void tx_beep(hl_app *a, int count) {
    if (!a->audio_ready) return;

    int16_t tone[SVX_RATE / 8];              /* 125 ms */
    const int n     = SVX_RATE / 8;
    const int ramp  = SVX_RATE / 100;        /* 10 ms, so it does not click */
    for (int b = 0; b < count; b++) {
        for (int i = 0; i < n; i++) {
            float env = 1.0f;
            if (i < ramp)          env = (float)i / (float)ramp;
            else if (i > n - ramp) env = (float)(n - i) / (float)ramp;
            float s = sinf(2.0f * (float)M_PI * 800.0f * (float)i / (float)SVX_RATE);
            tone[i] = (int16_t)(s * env * 0.35f * 32767.0f);
        }
        svx_ring_write(&a->play_ring, tone, (uint32_t)n);
        int16_t gap[SVX_RATE / 16];          /* 62 ms of silence between beeps */
        memset(gap, 0, sizeof(gap));
        if (b + 1 < count) svx_ring_write(&a->play_ring, gap, SVX_RATE / 16);
    }
}

static int tx_start(hl_app *a) {
    /* The guard chain, in this order. Each refusal has its own beep so the
     * reason is audible without looking at the screen. */
    if (rc_get_state(a->rc) != RC_CONNECTED) {
        log_warn("PTT refused: not connected");
        tx_beep(a, 3);
        rc_reconnect_now(a->rc);
        return -1;
    }
    if (tgm_selected(&a->tgm) == 0) {
        log_warn("PTT refused: no talkgroup selected");
        tx_beep(a, 3);
        return -1;
    }
    if (a->busy_call[0]) {
        char mine[64], theirs[64];
        call_strip_ssid(mine,   sizeof(mine),   a->cfg->callsign);
        call_strip_ssid(theirs, sizeof(theirs), a->busy_call);
        if (strcmp(mine, theirs) != 0) {
            log_warn("PTT refused: %s is talking on TG %u", a->busy_call, a->busy_tg);
            tx_beep(a, 2);
            return -1;
        }
    }
    if (a->no_tx || !a->tx_ready) {
        log_warn("PTT refused: transmit is not available (receive-only)");
        tx_beep(a, 3);
        return -1;
    }
    if (a->tx_active) return 0;

    /* Start from a clean codec: gain and filter state from the last over must
     * not colour the first syllable of this one. */
    codec_reset(a->tx_codec);
    svx_ring_reset(&a->cap_ring);
    svx_dev_reset_silence(a->cap_dev);

    if (svx_dev_start(a->cap_dev) != 0) {
        log_err("cannot start the microphone");
        tx_beep(a, 3);
        return -1;
    }

    a->tx_active     = 1;
    a->tx_started_ms = now_ms();
    a->tx_frames     = 0;
    log_info("TX ON   TG %u", tgm_selected(&a->tgm));
    return 0;
}

static void tx_stop(hl_app *a, const char *why) {
    if (!a->tx_active) return;
    a->tx_active = 0;

    svx_dev_stop(a->cap_dev);

    /* Tell the reflector the transmission is over. Without this it waits for
     * an audio timeout and logs a complaint about the node. */
    rc_send_flush(a->rc);

    uint64_t secs = (now_ms() - a->tx_started_ms) / 1000;
    log_info("TX OFF  %llu s, %llu frames%s%s",
             (unsigned long long)secs, (unsigned long long)a->tx_frames,
             why ? " — " : "", why ? why : "");

    /* The silent-microphone trap: on macOS a denied terminal yields a device
     * that opens fine and delivers perfect zeros. Say so, because otherwise
     * everything looks normal and nobody heard a word. */
    if (a->tx_frames > 20 && !svx_dev_saw_nonsilence(a->cap_dev)) {
        log_err("the microphone produced nothing but digital silence — nobody heard that.");
#if defined(__APPLE__)
        log_err("grant Microphone access to your terminal application "
                "(System Settings > Privacy & Security > Microphone). See docs/TCC.md.");
#else
        log_err("check the input device with --list-devices, and that it is not muted.");
#endif
    }
}

/* Drain whole 20 ms frames out of the capture ring, encode and send them.
 * The device clock paces this: we send exactly as fast as the microphone
 * produces samples, with no wall-clock timer of our own to drift against. */
static void tx_pump(hl_app *a) {
    if (!a->tx_active) return;

    while (svx_ring_avail(&a->cap_ring) >= SVX_FRAME) {
        if (svx_ring_read(&a->cap_ring, a->tx_pcm, SVX_FRAME) != SVX_FRAME) break;

        codec_dcblock(a->tx_codec, a->tx_pcm, SVX_FRAME);
        codec_agc(a->tx_codec, a->tx_pcm, SVX_FRAME);

        uint8_t opus[SVX_MAX_OPUS];
        int n = codec_encode(a->tx_codec, a->tx_pcm, SVX_FRAME, opus, sizeof(opus));
        if (n <= 0) { log_dbg("Opus encode failed (%d)", n); continue; }

        if (rc_send_audio(a->rc, opus, (size_t)n) != 0) {
            tx_stop(a, "the connection dropped");
            return;
        }
        a->tx_frames++;
    }

    if (a->cfg->tx_timeout_sec > 0 &&
        now_ms() - a->tx_started_ms >= (uint64_t)a->cfg->tx_timeout_sec * 1000) {
        tx_stop(a, "transmit timeout");
        tx_beep(a, 2);
    }
}

static int tx_open(hl_app *a) {
    if (a->no_tx) { log_info("transmit disabled (--no-tx)"); return 0; }
    if (!a->audio_ready) return -1;

#if defined(__APPLE__)
    svx_mic_state m = svx_mic_status();
    if (m == SVX_MIC_UNDETERMINED) {
        log_info("macOS is about to ask your terminal for microphone access.");
        log_info("the dialog will name your terminal application, not SVXConnect.");
        m = svx_mic_request(60000);
    }
    if (m == SVX_MIC_DENIED) {
        log_warn("microphone access denied — running receive-only. See docs/TCC.md.");
        a->no_tx = 1;
        return -1;
    }
#endif

    a->tx_codec = codec_open();
    if (!a->tx_codec) return -1;
    codec_set_agc(a->tx_codec, a->cfg->mic_agc, a->cfg->mic_agc_target_pct);

    /* A second of capture buffer. The main loop drains it every few
     * milliseconds, so this is pure headroom against a scheduling hiccup. */
    if (svx_ring_init(&a->cap_ring, SVX_RATE) != 0) {
        codec_close(a->tx_codec); a->tx_codec = NULL;
        return -1;
    }

    svx_devinfo in;
    svx_audio_resolve(1, a->cfg->input_device, &in);
    a->cap_dev = svx_dev_open_capture(in.id, &a->cap_ring, &a->mic_peak);
    if (!a->cap_dev) {
        svx_ring_free(&a->cap_ring);
        codec_close(a->tx_codec); a->tx_codec = NULL;
        return -1;
    }

    /* The device is opened now but only STARTED while transmitting, so the
     * microphone is genuinely closed the rest of the time — on macOS that is
     * what makes the recording indicator honest. */
    a->tx_ready = 1;
    log_info("audio in:  %s", svx_dev_name(a->cap_dev));
    return 0;
}

static void tx_close(hl_app *a) {
    if (!a->tx_ready) return;
    a->tx_ready = 0;
    svx_dev_close(a->cap_dev);  a->cap_dev = NULL;
    svx_ring_free(&a->cap_ring);
    codec_close(a->tx_codec);   a->tx_codec = NULL;
}

/* -------------------------------------------- talkgroup manager glue */

static void tgm_do_select(void *u, uint32_t tg, int gate) {
    hl_app *a = u;
    if (a->tx_active) tx_stop(a, "talkgroup changed");
    if (gate && a->audio_ready) jitter_flush(&a->jb);
    a->busy_tg = 0;
    a->busy_call[0] = '\0';
    rc_select_tg(a->rc, tg);
}

static void tgm_do_monitor(void *u, const uint32_t *ids, size_t n) {
    hl_app *a = u;
    rc_set_monitor(a->rc, ids, n);
}

static void tgm_do_beep(void *u, int n) { tx_beep((hl_app *)u, n); }

static void tgm_do_tail(void *u, int ms) {
    hl_app *a = u;
    if (a->audio_ready) jitter_trim_tail(&a->jb, ms);
}

static void tgm_do_changed(void *u) { (void)u; }

/* ------------------------------------------------------ control FIFO */

static void ctl_ptt(void *u, ctl_tristate v) {
    hl_app *a = u;
    if (v == CTL_ON)       tx_start(a);
    else if (v == CTL_OFF) tx_stop(a, NULL);
    else                   { if (a->tx_active) tx_stop(a, NULL); else tx_start(a); }
}

static void ctl_tg(void *u, ctl_tg_kind kind, uint32_t tg) {
    hl_app *a = u;
    if      (kind == CTL_TG_NEXT) tgm_next(&a->tgm);
    else if (kind == CTL_TG_PREV) tgm_prev(&a->tgm);
    else                          tgm_select(&a->tgm, tg);
    log_info("TG %u", tgm_selected(&a->tgm));
}

static void ctl_lock(void *u, ctl_tristate v) {
    hl_app *a = u;
    if (v == CTL_TOGGLE) tgm_toggle_lock(&a->tgm);
    else                 tgm_set_lock(&a->tgm, v == CTL_ON);
}

static void ctl_mute(void *u, uint32_t tg, int mute) {
    hl_app *a = u;
    if (tgm_is_muted(&a->tgm, tg) != mute) tgm_toggle_mute(&a->tgm, tg);
}

static void ctl_volume(void *u, int pct) {
    hl_app *a = u;
    if (a->audio_ready) jitter_set_volume(&a->jb, pct);
    log_info("volume %d%%", pct);
}

static void ctl_status(void *u) {
    hl_app *a = u;
    rc_stats st;
    rc_get_stats(a->rc, &st);
    log_info("status: %s, TG %u%s, %s, rx %llu pkt, lost %.1f%%, buffered %u ms",
             rc_state_name(rc_get_state(a->rc)), tgm_selected(&a->tgm),
             tgm_locked(&a->tgm) ? " LOCKED" : "",
             a->tx_active ? "TRANSMITTING" : "idle",
             (unsigned long long)st.rx_packets, st.loss_pct,
             a->audio_ready ? jitter_depth_ms(&a->jb) : 0);
}

static void ctl_quit(void *u) { ((hl_app *)u)->quit = 1; }

/* ----------------------------------------------------------------- run */

int run_headless(const svx_config *cfg, int no_tx) {
    hl_app app;
    memset(&app, 0, sizeof(app));
    app.cfg = cfg;

    /* No SA_RESTART: poll() should return EINTR so the loop notices. */
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

    app.no_tx = no_tx;

    app.rc = rc_new(cfg, &cb);
    if (!app.rc) { log_err("out of memory"); return 1; }

    audio_start(&app);      /* not fatal: monitoring still works without it */
    tx_open(&app);          /* also not fatal: receive-only is a valid mode  */

    ctl_callbacks ccb = {
        .user      = &app,
        .on_ptt    = ctl_ptt,
        .on_tg     = ctl_tg,
        .on_lock   = ctl_lock,
        .on_mute   = ctl_mute,
        .on_volume = ctl_volume,
        .on_status = ctl_status,
        .on_quit   = ctl_quit,
    };
    ctl_open(&app.ctl, cfg->ctl_fifo, &ccb);

    tgm_callbacks tcb = {
        .user        = &app,
        .select_tg   = tgm_do_select,
        .set_monitor = tgm_do_monitor,
        .beep        = tgm_do_beep,
        .changed     = tgm_do_changed,
        .tail_trim   = tgm_do_tail,
    };
    tgm_init(&app.tgm, cfg, &tcb);

    log_info("svxconnect headless — %s -> %s:%d%s",
             cfg->callsign, cfg->reflector, cfg->port, no_tx ? " (receive only)" : "");
    log_info("starting on TG %u%s", tgm_selected(&app.tgm),
             tgm_locked(&app.tgm) ? " (locked)" : "");

    rc_start(app.rc);
    app.last_report = now_ms();

    while (!g_quit && !app.quit) {
        uint64_t now = now_ms();

        struct pollfd p[10];
        int n  = rc_poll_fds(app.rc, p, 10);

        int ctl_idx = -1;
        if (ctl_fd(&app.ctl) >= 0 && n < 10) {
            ctl_idx = n;
            p[n].fd = ctl_fd(&app.ctl); p[n].events = POLLIN; p[n].revents = 0;
            n++;
        }

        int to = rc_next_timeout_ms(app.rc, now);
        /* The jitter buffer's state machine wants servicing on roughly a frame
         * boundary, so never sleep longer than that while audio is running.
         * While transmitting, poll the capture ring harder still: the device
         * never wakes us (it may not — see dev.h), so this cadence is what
         * bounds the extra latency we add on the transmit path. */
        if (app.audio_ready && to > 20) to = 20;
        if (app.tx_active   && to > 5)  to = 5;

        int pr = poll(p, (nfds_t)n, to);
        if (pr < 0 && errno != EINTR) {
            log_err("poll failed: %s", strerror(errno));
            break;
        }

        (void)ctl_idx;
        ctl_drain(&app.ctl);

        now = now_ms();
        rc_service(app.rc, now);
        if (app.audio_ready) jitter_tick(&app.jb, now);
        tgm_tick(&app.tgm, now);
        tx_pump(&app);

        /* If the link went away mid-over, stop rather than encode into a void. */
        if (app.tx_active && rc_get_state(app.rc) != RC_CONNECTED)
            tx_stop(&app, "the connection dropped");

        if (now - app.last_report >= 60000) {
            app.last_report = now;
            rc_stats st;
            rc_get_stats(app.rc, &st);
            log_info("stats: rx %llu pkt (%d/s), tx %llu pkt, lost %llu (%.1f%%), "
                     "replayed %llu, bad-auth %llu",
                     (unsigned long long)st.rx_packets, st.rx_pps,
                     (unsigned long long)st.tx_packets,
                     (unsigned long long)st.rx_lost, st.loss_pct,
                     (unsigned long long)st.rx_replayed,
                     (unsigned long long)st.rx_auth_fail);
            if (app.audio_ready) {
                log_info("audio: %llu frames, %llu concealed, %llu underruns, "
                         "%llu dropped, %u ms buffered, device underruns %u",
                         (unsigned long long)app.jb.n_frames,
                         (unsigned long long)app.jb.n_concealed,
                         (unsigned long long)app.jb.n_underruns,
                         (unsigned long long)app.jb.n_dropped,
                         jitter_depth_ms(&app.jb),
                         svx_dev_underruns(app.play_dev));
            }
        }
    }

    log_info("shutting down");
    if (app.tx_active) tx_stop(&app, "shutting down");
    ctl_close(&app.ctl);
    rc_stop(app.rc, "quit");
    rc_free(app.rc);
    tx_close(&app);
    audio_stop(&app);
    return 0;
}
