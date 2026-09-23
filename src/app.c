/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "app.h"

#include "audio/codec.h"
#include "audio/dev.h"
#include "audio/jitter.h"
#include "audio/watchdog.h"
#include "common/log.h"
#include "common/ring.h"
#include "common/status.h"
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

/* Audio device watchdog timings (see audio/watchdog.h for why there is one).
 *
 * Capture: a healthy stream delivers its first samples 6-36 ms after the
 * start on PipeWire, then every 20 ms. Half a second of nothing is a stall,
 * and short enough that the over is rescued before anyone notices the gap.
 * One reopen; if that yields nothing too, stop rather than transmit a void.
 *
 * Playback runs all the time, so a slower trigger costs nothing and keeps a
 * busy machine from reopening a device that was only late. After a reopen that
 * does not help, keep trying at PLAY_RETRY_MS: receive is otherwise dead for
 * good, as it was for 31 hours once. */
#define CAP_GRACE_MS      500
#define CAP_STALL_MS      500
#define PLAY_GRACE_MS    1000
#define PLAY_STALL_MS    1000
#define PLAY_RETRY_MS   30000

/* An over this long that sent nothing is reported, not just counted. */
#define TX_NO_AUDIO_MS    200

static const char PLAY_STALLED_BANNER[] =
    "SPEAKER STALLED - the output device stopped playing and reopening it did not "
    "help, so received audio is not heard. Still retrying. 'x' dismisses.";

struct svx_app {
    const svx_config *cfg;
    rc_client        *rc;

    /* receive path */
    svx_codec        *codec;
    svx_ring          play_ring;
    svx_dev          *play_dev;
    svx_jitter        jb;
    _Atomic float     spk_peak;
    int               audio_ready;
    svx_watchdog      play_wd;
    int               play_stalled;   /* gave up on the output; retrying slowly */
    uint64_t          play_retry_ms;

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
    uint64_t          tx_encode_fails;
    int               tx_saw_sound;   /* a device reopened mid-over heard sound */
    svx_watchdog      cap_wd;
    int16_t           tx_pcm[SVX_FRAME];

    tg_manager        tgm;
    ctl_fifo          ctl;
    int               quit;
    uint64_t          last_report;

    /* Status export for a companion panel widget. owner_kind names which front
     * end we are; the last written line and its time throttle the writes to
     * "on change, plus a 1 Hz heartbeat so the reader can trust the mtime". */
    char              owner_kind[16];
    char              status_line[256];
    uint64_t          last_status;

    /* Output mute remembers the level it was at, so unmuting restores it
     * rather than jumping to some default. */
    int               out_muted;
    int               volume_before_mute;

    /* A message the interface should show until the user dismisses it. */
    char              banner[240];

    /* Log ring, so the interface can show recent lines without reopening the
     * log file. Fed by the sink installed in app_new(). */
    app_log_line      logbuf[APP_LOG_LINES];
    int               log_head;      /* next slot to write */
    int               log_count;
    uint64_t          log_serial;

    void            (*observer)(void *);
    void             *observer_user;
};

static void tx_stop(svx_app *a, const char *why);

static void notify(svx_app *a) {
    if (a->observer) a->observer(a->observer_user);
}

static void banner_set(svx_app *a, const char *msg) {
    snprintf(a->banner, sizeof(a->banner), "%s", msg ? msg : "");
    notify(a);
}

/* ------------------------------------------------------------ callbacks */

static void hl_state(void *u, rc_state st, const char *detail) {
    svx_app *a = u;
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
    svx_app *a = u;
    log_info("TALKER START  TG %-6u %s", tg, call);

    /* The manager tracks every active talker on every watched talkgroup; the
     * PTT busy-guard reads that, so nothing extra needs recording here. */
    tgm_on_talker_start(&a->tgm, tg, call);
}

static void hl_talker_stop(void *u, uint32_t tg, const char *call) {
    svx_app *a = u;
    log_info("TALKER STOP   TG %-6u %s", tg, call);
    /* The manager owns talker bookkeeping, the roger beep, the tail trim and
     * the linger window — and matches the stop on callsign, since the server
     * may report it on a different talkgroup than the start. */
    tgm_on_talker_stop(&a->tgm, tg, call);
    if (a->audio_ready) jitter_end_of_stream(&a->jb);
}

static void hl_audio(void *u, const uint8_t *opus, size_t len, int gap) {
    svx_app *a = u;
    if (!a->audio_ready) return;
    jitter_push(&a->jb, opus, len, gap);
}

static void hl_node(void *u, int joined, const char *call) {
    (void)u;
    log_info("NODE %-5s    %s", joined ? "JOIN" : "LEFT", call);
}

static void hl_flushed(void *u) {
    svx_app *a = u;
    if (a->audio_ready) jitter_end_of_stream(&a->jb);
}

static void hl_error(void *u, const char *msg) {
    svx_app *a = u;
    log_warn("reflector error: %s", msg);
    banner_set(a, msg);
}

/* ------------------------------------------------------- audio set-up */

static int audio_start(svx_app *a) {
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

    a->audio_ready  = 1;
    a->play_stalled = 0;
    svx_wd_start(&a->play_wd, now_ms(), svx_dev_frames(a->play_dev));
    log_info("audio out: %s (%s, %d Hz, %d ms jitter buffer)",
             svx_dev_name(a->play_dev), svx_audio_backend_name(),
             SVX_RATE, a->cfg->jitter_ms);
    return 0;
}

static void audio_stop(svx_app *a) {
    if (!a->audio_ready) return;
    a->audio_ready = 0;
    svx_dev_close(a->play_dev);  a->play_dev = NULL;
    svx_ring_free(&a->play_ring);
    codec_close(a->codec);       a->codec = NULL;
    svx_audio_term();
}

/* Close the output device and open it again, keeping the codec, the ring and
 * the jitter buffer — what a restart would do for this one device. What was
 * buffered is dropped: it is stale by now. On failure play_dev stays NULL and
 * the next retry tries again; the jitter buffer copes with no device. */
static int play_reopen(svx_app *a) {
    jitter_set_device(&a->jb, NULL);
    svx_dev_close(a->play_dev);          /* joins its thread: the ring has no consumer now */
    a->play_dev = NULL;
    jitter_flush(&a->jb);                /* with no device this resets the ring directly */

    svx_devinfo out;
    svx_audio_resolve(0, a->cfg->output_device, &out);
    svx_dev *d = svx_dev_open_playback(out.id, &a->play_ring, &a->spk_peak);
    if (!d) return -1;
    if (svx_dev_start(d) != 0) { svx_dev_close(d); return -1; }

    a->play_dev = d;
    jitter_set_device(&a->jb, d);
    svx_wd_restarted(&a->play_wd, now_ms(), svx_dev_frames(d));
    return 0;
}

/* The output device runs for the life of the program, so its callback must
 * keep being called. If it is not, received audio piles up unheard — the ring
 * once sat full at 512 ms for 31 hours with nothing reported. */
static void play_watch(svx_app *a) {
    uint64_t now = now_ms();

    if (a->play_stalled) {
        if (a->play_dev && svx_dev_frames(a->play_dev) != a->play_wd.last_count) {
            a->play_stalled = 0;
            svx_wd_start(&a->play_wd, now, svx_dev_frames(a->play_dev));
            log_info("the output device is playing again");
            if (strcmp(a->banner, PLAY_STALLED_BANNER) == 0) app_dismiss_banner(a);
        } else if (now >= a->play_retry_ms) {
            a->play_retry_ms = now + PLAY_RETRY_MS;
            log_dbg("retrying the stalled output device");
            play_reopen(a);
        }
        return;
    }

    svx_wd_verdict v   = SVX_WD_OK;
    const char    *why = NULL;
    switch (svx_dev_poll_event(a->play_dev)) {
    case SVX_DEV_STOPPED:
    case SVX_DEV_LOST:
        v   = svx_wd_trip(&a->play_wd);
        why = "was stopped by the system";
        break;
    case SVX_DEV_REROUTED:
        /* The system moved the stream; it is still running, and if the move
         * broke it the counter below will say so. */
        log_info("the output device was rerouted by the system");
        break;
    default:
        break;
    }
    if (v == SVX_WD_OK) {
        v   = svx_wd_check(&a->play_wd, now, svx_dev_frames(a->play_dev));
        why = "stopped playing";
    }

    if (v == SVX_WD_REOPEN) {
        log_warn("the output device %s — reopening it", why);
        if (play_reopen(a) == 0) return;
        v = SVX_WD_GIVE_UP;
    }
    if (v == SVX_WD_GIVE_UP) {
        log_err("the output device %s and reopening it did not help — "
                "received audio is not heard; retrying every %d s", why, PLAY_RETRY_MS / 1000);
        banner_set(a, PLAY_STALLED_BANNER);
        a->play_stalled  = 1;
        a->play_retry_ms = now + PLAY_RETRY_MS;
    }
}


/* --------------------------------------------------------- transmit */

/* Short beeps carry meaning, and the vocabulary is the same one the macOS app
 * uses so it transfers between the two: 1 = roger, 2 = channel busy,
 * 3 = no link or no talkgroup selected. */
static void tx_beep(svx_app *a, int count) {
    if (!a->audio_ready) return;

    /* Beeps are written straight into the playback ring, which sits BELOW the
     * jitter buffer — and the jitter buffer's volume is where both the volume
     * setting and mute actually live (app_set_volume, app_toggle_output_mute
     * do nothing else). So a beep that does not apply them itself plays at
     * full level through a muted output, which is what the roger beep did.
     *
     * app_test_tone() still works while muted: it lifts the volume and clears
     * the mute before it gets here, because proving the output path is the
     * whole point of it. */
    if (a->out_muted) return;
    const float gain = (float)a->cfg->output_volume_pct / 100.0f;
    if (gain <= 0.0f) return;

    int16_t tone[SVX_RATE / 8];              /* 125 ms */
    const int n     = SVX_RATE / 8;
    const int ramp  = SVX_RATE / 100;        /* 10 ms, so it does not click */
    for (int b = 0; b < count; b++) {
        for (int i = 0; i < n; i++) {
            float env = 1.0f;
            if (i < ramp)          env = (float)i / (float)ramp;
            else if (i > n - ramp) env = (float)(n - i) / (float)ramp;
            float s = sinf(2.0f * (float)M_PI * 800.0f * (float)i / (float)SVX_RATE);
            tone[i] = (int16_t)(s * env * gain * 0.35f * 32767.0f);
        }
        svx_ring_write(&a->play_ring, tone, (uint32_t)n);
        int16_t gap[SVX_RATE / 16];          /* 62 ms of silence between beeps */
        memset(gap, 0, sizeof(gap));
        if (b + 1 < count) svx_ring_write(&a->play_ring, gap, SVX_RATE / 16);
    }
    /* Most beeps come while nothing is being received, when the jitter buffer
     * keeps the output gated; without a kick they waited in the ring for the
     * next over and played in front of it. */
    jitter_kick(&a->jb);
}

/* Open the configured input device onto cap_ring. Not started. */
static int cap_dev_open(svx_app *a) {
    svx_devinfo in;
    svx_audio_resolve(1, a->cfg->input_device, &in);
    a->cap_dev = svx_dev_open_capture(in.id, &a->cap_ring, &a->mic_peak);
    return a->cap_dev ? 0 : -1;
}

/* Close the input device and open it again in the middle of an over: what
 * tx_close() + tx_open() do, or a restart, which were the only cures for a
 * capture stream that started and then never delivered. The codec, the ring
 * and the over's counters carry on. */
static int cap_reopen(svx_app *a, const char *why) {
    log_warn("the microphone %s — reopening the input device", why);

    if (svx_dev_saw_nonsilence(a->cap_dev)) a->tx_saw_sound = 1;
    svx_dev_close(a->cap_dev);           /* joins its thread: nothing writes cap_ring now */
    a->cap_dev = NULL;
    if (cap_dev_open(a) != 0) return -1;
    svx_dev_reset_silence(a->cap_dev);
    if (svx_dev_start(a->cap_dev) != 0) return -1;

    svx_wd_restarted(&a->cap_wd, now_ms(), svx_dev_frames(a->cap_dev));
    return 0;
}

/* Called while transmitting: is the microphone still delivering? */
static void cap_watch(svx_app *a) {
    svx_wd_verdict v   = SVX_WD_OK;
    const char    *why = NULL;

    switch (svx_dev_poll_event(a->cap_dev)) {
    case SVX_DEV_STOPPED:
    case SVX_DEV_LOST:
        v   = svx_wd_trip(&a->cap_wd);
        why = "was stopped by the system";
        break;
    case SVX_DEV_REROUTED:
        log_info("the input device was rerouted by the system");
        break;
    default:
        break;
    }
    if (v == SVX_WD_OK) {
        v   = svx_wd_check(&a->cap_wd, now_ms(), svx_dev_frames(a->cap_dev));
        why = a->cap_wd.flowing ? "stopped delivering audio" : "delivered no audio";
    }

    if (v == SVX_WD_REOPEN) {
        if (cap_reopen(a, why) == 0) return;
        v = SVX_WD_GIVE_UP;
    }
    if (v == SVX_WD_GIVE_UP) {
        /* Stop rather than stay keyed sending nothing: the reflector gives
         * the floor to whoever speaks next, and the operator believes they
         * are on the air. */
        log_err("the microphone %s and reopening the input device did not help", why);
        tx_stop(a, "the microphone delivers no audio");
        banner_set(a, "MIC STALLED - the input device stopped delivering audio and "
                      "reopening it did not help; nothing was sent. Check the device "
                      "(--list-devices) or restart. 'x' dismisses.");
        tx_beep(a, 3);
    }
}

static int tx_start(svx_app *a) {
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
    /* Refuse to key up over a station already talking on our talkgroup.
     *
     * Ask the talkgroup manager, not the busy_tg/busy_call shortcut: that
     * shortcut is only set when a talker_start arrives while we are ALREADY on
     * their talkgroup, so a station that was already transmitting when we
     * switched onto their talkgroup is invisible to it — and we would key
     * straight over them. The manager tracks every active talker on every
     * watched talkgroup, so tgm_talker_on(selected) is the authoritative
     * answer. */
    {
        const tgm_talker *t = tgm_talker_on(&a->tgm, tgm_selected(&a->tgm));
        if (t) {
            char mine[64], theirs[64];
            call_strip_ssid(mine,   sizeof(mine),   a->cfg->callsign);
            call_strip_ssid(theirs, sizeof(theirs), t->call);
            if (strcmp(mine, theirs) != 0) {
                log_warn("PTT refused: %s is talking on TG %u", t->call, t->tg);
                tx_beep(a, 2);
                return -1;
            }
        }
    }
    if (a->no_tx || !a->tx_ready) {
        log_warn("PTT refused: transmit is not available (receive-only)");
        tx_beep(a, 3);
        return -1;
    }
    if (a->tx_active) return 0;

    /* A mid-over reopen that failed leaves no device; try once more now. */
    if (!a->cap_dev && cap_dev_open(a) != 0) {
        log_err("cannot open the microphone");
        tx_beep(a, 3);
        return -1;
    }

    /* Start from a clean codec: gain and filter state from the last over must
     * not colour the first syllable of this one. */
    codec_reset(a->tx_codec);
    svx_ring_reset(&a->cap_ring);
    svx_dev_reset_silence(a->cap_dev);
    /* Whatever the device reported while it was idle belongs to the last
     * over; this one is judged by the watchdog from here. */
    (void)svx_dev_poll_event(a->cap_dev);

    if (svx_dev_start(a->cap_dev) != 0) {
        log_err("cannot start the microphone");
        tx_beep(a, 3);
        return -1;
    }

    a->tx_active       = 1;
    a->tx_started_ms   = now_ms();
    a->tx_frames       = 0;
    a->tx_encode_fails = 0;
    a->tx_saw_sound    = 0;
    svx_wd_start(&a->cap_wd, a->tx_started_ms, svx_dev_frames(a->cap_dev));
    log_info("TX ON   TG %u", tgm_selected(&a->tgm));
    return 0;
}

static void tx_stop(svx_app *a, const char *why) {
    if (!a->tx_active) return;
    a->tx_active = 0;

    svx_dev_stop(a->cap_dev);

    /* Tell the reflector the transmission is over. Without this it waits for
     * an audio timeout and logs a complaint about the node. */
    rc_send_flush(a->rc);

    uint64_t ms   = now_ms() - a->tx_started_ms;
    uint64_t secs = ms / 1000;

    /* An over that sent nothing is a warning, never just a number in an info
     * line: four such overs in a row once went by without one, while the
     * microphone had silently stopped delivering. */
    int no_audio = a->tx_frames == 0 && ms >= TX_NO_AUDIO_MS;
    if (no_audio)
        log_warn("TX OFF  %llu s, %llu frames%s%s",
                 (unsigned long long)secs, (unsigned long long)a->tx_frames,
                 why ? " — " : "", why ? why : "");
    else
        log_info("TX OFF  %llu s, %llu frames%s%s",
                 (unsigned long long)secs, (unsigned long long)a->tx_frames,
                 why ? " — " : "", why ? why : "");
    if (no_audio) {
        log_warn("keyed for %llu ms but the microphone delivered no audio — nothing was sent",
                 (unsigned long long)ms);
        if (ms >= 1000)
            banner_set(a, "MIC STALLED - that over sent no audio: the input device "
                          "delivered nothing. Check the device (--list-devices). 'x' dismisses.");
    } else if (ms >= 1000 && a->tx_frames * 2 < ms / 20) {
        log_warn("only %llu of about %llu frames were sent",
                 (unsigned long long)a->tx_frames, (unsigned long long)(ms / 20));
    }
    if (a->tx_encode_fails)
        log_warn("%llu frames could not be encoded", (unsigned long long)a->tx_encode_fails);

    /* The silent-microphone trap: on macOS a denied terminal yields a device
     * that opens fine and delivers perfect zeros. Say so, because otherwise
     * everything looks normal and nobody heard a word. */
    if (a->tx_frames > 20 && !a->tx_saw_sound && !svx_dev_saw_nonsilence(a->cap_dev)) {
#if defined(__APPLE__)
        banner_set(a, "MIC BLOCKED - macOS gave us only silence. Grant your terminal "
                      "Microphone access (Privacy & Security), then restart. 'x' dismisses.");
#else
        banner_set(a, "MIC SILENT - the input device produced only silence. "
                      "Check --list-devices and that it is not muted. 'x' dismisses.");
#endif
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
static void tx_pump(svx_app *a) {
    if (!a->tx_active) return;

    while (svx_ring_avail(&a->cap_ring) >= SVX_FRAME) {
        if (svx_ring_read(&a->cap_ring, a->tx_pcm, SVX_FRAME) != SVX_FRAME) break;

        codec_dcblock(a->tx_codec, a->tx_pcm, SVX_FRAME);
        /* Fixed pre-gain first: it lifts a quiet mic above the AGC's noise gate
         * (and is the only boost when the AGC is off). DC is removed before it
         * so the gain does not amplify any offset. */
        if (a->cfg->mic_gain != 0)
            codec_apply_gain_db(a->tx_pcm, SVX_FRAME, (float)a->cfg->mic_gain);
        codec_agc(a->tx_codec, a->tx_pcm, SVX_FRAME);

        uint8_t opus[SVX_MAX_OPUS];
        int n = codec_encode(a->tx_codec, a->tx_pcm, SVX_FRAME, opus, sizeof(opus));
        if (n <= 0) {
            /* Visible at the default level (once per over; tx_stop gives the
             * count), or it cannot be told apart from a stalled microphone. */
            if (a->tx_encode_fails++ == 0) log_warn("Opus encode failed (%d)", n);
            continue;
        }

        if (rc_send_audio(a->rc, opus, (size_t)n) != 0) {
            tx_stop(a, "the connection dropped");
            return;
        }
        a->tx_frames++;
    }

    cap_watch(a);
    if (!a->tx_active) return;

    if (a->cfg->tx_timeout_sec > 0 &&
        now_ms() - a->tx_started_ms >= (uint64_t)a->cfg->tx_timeout_sec * 1000) {
        tx_stop(a, "transmit timeout");
        tx_beep(a, 2);
    }
}

static int tx_open(svx_app *a) {
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
        banner_set(a, "RX ONLY - microphone access denied. See docs/TCC.md. 'x' dismisses.");
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

    if (cap_dev_open(a) != 0) {
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

static void tx_close(svx_app *a) {
    if (!a->tx_ready) return;
    a->tx_ready = 0;
    svx_dev_close(a->cap_dev);  a->cap_dev = NULL;
    svx_ring_free(&a->cap_ring);
    codec_close(a->tx_codec);   a->tx_codec = NULL;
}

/* -------------------------------------------- talkgroup manager glue */

static void tgm_do_select(void *u, uint32_t tg, int gate) {
    svx_app *a = u;
    if (a->tx_active) tx_stop(a, "talkgroup changed");
    if (gate && a->audio_ready) jitter_flush(&a->jb);
    rc_select_tg(a->rc, tg);
}

static void tgm_do_monitor(void *u, const uint32_t *ids, size_t n) {
    svx_app *a = u;
    rc_set_monitor(a->rc, ids, n);
}

static void tgm_do_beep(void *u, int n) { tx_beep((svx_app *)u, n); }

static void tgm_do_tail(void *u, int ms) {
    svx_app *a = u;
    if (a->audio_ready) jitter_trim_tail(&a->jb, ms);
}

static void tgm_do_changed(void *u) { (void)u; }

/* ------------------------------------------------------ control FIFO */

static void ctl_ptt(void *u, ctl_tristate v) {
    svx_app *a = u;
    if (v == CTL_ON)       tx_start(a);
    else if (v == CTL_OFF) tx_stop(a, NULL);
    else                   { if (a->tx_active) tx_stop(a, NULL); else tx_start(a); }
}

static void ctl_tg(void *u, ctl_tg_kind kind, uint32_t tg) {
    svx_app *a = u;
    if      (kind == CTL_TG_NEXT) tgm_next(&a->tgm);
    else if (kind == CTL_TG_PREV) tgm_prev(&a->tgm);
    else                          tgm_select(&a->tgm, tg);
    log_info("TG %u", tgm_selected(&a->tgm));
}

static void ctl_lock(void *u, ctl_tristate v) {
    svx_app *a = u;
    if (v == CTL_TOGGLE) tgm_toggle_lock(&a->tgm);
    else                 tgm_set_lock(&a->tgm, v == CTL_ON);
}

static void ctl_mute(void *u, uint32_t tg, int mute) {
    svx_app *a = u;
    if (tgm_is_muted(&a->tgm, tg) != mute) tgm_toggle_mute(&a->tgm, tg);
}

static void ctl_volume(void *u, int pct) {
    svx_app *a = u;
    /* Mirror into cfg, exactly as the keyboard path does — otherwise the TUI
     * keeps showing the old level and the next volume keypress, which computes
     * from cfg->output_volume_pct, jumps the audio back. Same 0..100 range as
     * the keys, so the two controls agree. */
    pct = CLAMP(pct, 0, 100);
    ((svx_config *)a->cfg)->output_volume_pct = pct;
    a->out_muted = 0;
    if (a->audio_ready) jitter_set_volume(&a->jb, pct);
    notify(a);
    log_info("volume %d%%", pct);
}

static void ctl_status(void *u) {
    svx_app *a = u;
    rc_stats st;
    rc_get_stats(a->rc, &st);
    log_info("status: %s, TG %u%s, %s, rx %llu pkt, lost %.1f%%, buffered %u ms",
             rc_state_name(rc_get_state(a->rc)), tgm_selected(&a->tgm),
             tgm_locked(&a->tgm) ? " LOCKED" : "",
             a->tx_active ? "TRANSMITTING" : "idle",
             (unsigned long long)st.rx_packets, st.loss_pct,
             a->audio_ready ? jitter_depth_ms(&a->jb) : 0);
}

static void ctl_quit(void *u) { ((svx_app *)u)->quit = 1; }

/* -------------------------------------------------------------- logging */

/* Log sink: keep the last APP_LOG_LINES lines so the interface's log pane has
 * something to show. Also writes through to the file sink when one is open. */
static void app_log_sink(int level, const char *line, void *user) {
    svx_app *a = user;

    app_log_line *slot = &a->logbuf[a->log_head];
    slot->level = level;
    snprintf(slot->text, sizeof(slot->text), "%s", line);

    a->log_head = (a->log_head + 1) % APP_LOG_LINES;
    if (a->log_count < APP_LOG_LINES) a->log_count++;
    a->log_serial++;
}

int app_log_snapshot(const svx_app *a, app_log_line *out, int max) {
    int n = a->log_count < max ? a->log_count : max;
    /* Oldest first, so the caller can print top to bottom. */
    int start = (a->log_head - n + APP_LOG_LINES) % APP_LOG_LINES;
    for (int i = 0; i < n; i++) out[i] = a->logbuf[(start + i) % APP_LOG_LINES];
    return n;
}

uint64_t app_log_serial(const svx_app *a) { return a->log_serial; }

void app_capture_log(svx_app *a) {
    /* Only a front end that owns the terminal calls this. Under the TUI a
     * stray log line written to stdout would tear a hole in the screen, so
     * from here on everything is diverted into the ring above and rendered
     * by the log pane instead. The headless front end does not call it and
     * keeps its plain stdout logging. */
    log_set_sink(app_log_sink, a);
}

void app_set_observer(svx_app *a, void (*fn)(void *), void *user) {
    a->observer      = fn;
    a->observer_user = user;
}

void app_set_owner_kind(svx_app *a, const char *kind) {
    if (!a || !kind || !*kind) return;
    snprintf(a->owner_kind, sizeof(a->owner_kind), "%s", kind);
}

/* Write the status snapshot, throttled: immediately when the meaningful state
 * changed, otherwise at most once a second to keep the file's mtime fresh so a
 * reader can tell a live client from a crashed one. Cheap enough to call every
 * service tick — the string is short and usually identical to the last. */
static void status_export(svx_app *a) {
    if (!a->cfg->status_file[0]) return;    /* export disabled */

    svx_status s = {
        .owner     = a->owner_kind[0] ? a->owner_kind : "cli",
        .conn      = rc_state_name(rc_get_state(a->rc)),
        .callsign  = a->cfg->callsign,
        .reflector = a->cfg->reflector,
        .tg        = tgm_selected(&a->tgm),
        .locked    = tgm_locked(&a->tgm),
        .tx        = a->tx_active,
        .pid       = (long)getpid(),
    };

    char line[256];
    svx_status_format(line, sizeof(line), &s);

    uint64_t now = now_ms();
    int changed = strcmp(line, a->status_line) != 0;
    if (!changed && now - a->last_status < 1000) return;

    svx_status_write(a->cfg->status_file, &s);
    snprintf(a->status_line, sizeof(a->status_line), "%s", line);
    a->last_status = now;
}

/* ------------------------------------------------------------- lifetime */

svx_app *app_new(const svx_config *cfg, int no_tx) {
    svx_app *a = calloc(1, sizeof(*a));
    if (!a) return NULL;

    a->cfg      = cfg;
    a->no_tx    = no_tx;
    a->out_muted = 0;
    a->volume_before_mute = cfg->output_volume_pct;
    snprintf(a->owner_kind, sizeof(a->owner_kind), "cli");
    svx_wd_init(&a->cap_wd,  CAP_GRACE_MS,  CAP_STALL_MS,  1);
    svx_wd_init(&a->play_wd, PLAY_GRACE_MS, PLAY_STALL_MS, 1);

    rc_callbacks cb = {
        .user            = a,
        .on_state        = hl_state,
        .on_talker_start = hl_talker_start,
        .on_talker_stop  = hl_talker_stop,
        .on_audio        = hl_audio,
        .on_node         = hl_node,
        .on_flushed      = hl_flushed,
        .on_error        = hl_error,
    };
    a->rc = rc_new(cfg, &cb);
    if (!a->rc) { free(a); return NULL; }

    tgm_callbacks tcb = {
        .user        = a,
        .select_tg   = tgm_do_select,
        .set_monitor = tgm_do_monitor,
        .beep        = tgm_do_beep,
        .changed     = tgm_do_changed,
        .tail_trim   = tgm_do_tail,
    };
    tgm_init(&a->tgm, cfg, &tcb);

    return a;
}

void app_start(svx_app *a) {
    audio_start(a);    /* not fatal: monitoring still works without sound   */
    tx_open(a);        /* also not fatal: receive-only is a valid mode      */

    ctl_callbacks ccb = {
        .user      = a,
        .on_ptt    = ctl_ptt,
        .on_tg     = ctl_tg,
        .on_lock   = ctl_lock,
        .on_mute   = ctl_mute,
        .on_volume = ctl_volume,
        .on_status = ctl_status,
        .on_quit   = ctl_quit,
    };
    ctl_open(&a->ctl, a->cfg->ctl_fifo, &ccb);

    rc_start(a->rc);
    a->last_report = now_ms();
    status_export(a);       /* publish an initial snapshot right away */
}

void app_free(svx_app *a) {
    if (!a) return;
    svx_status_clear(a->cfg->status_file);   /* no owner running now */
    if (a->tx_active) tx_stop(a, "shutting down");
    ctl_close(&a->ctl);
    if (a->rc) { rc_stop(a->rc, "quit"); rc_free(a->rc); }
    tx_close(a);
    audio_stop(a);
    free(a);
}

/* ------------------------------------------------------------ poll glue */

int app_poll_fds(svx_app *a, struct pollfd *p, int max) {
    int n = rc_poll_fds(a->rc, p, max);
    if (ctl_fd(&a->ctl) >= 0 && n < max) {
        p[n].fd = ctl_fd(&a->ctl);
        p[n].events = POLLIN;
        p[n].revents = 0;
        n++;
    }
    return n;
}

int app_next_timeout_ms(svx_app *a, uint64_t now) {
    int to = rc_next_timeout_ms(a->rc, now);
    /* The jitter buffer wants servicing on roughly a frame boundary. While
     * transmitting, poll the capture ring harder still: the realtime thread
     * deliberately never wakes us, so this cadence is what bounds the latency
     * we add on the transmit path. */
    if (a->audio_ready && to > 20) to = 20;
    if (a->tx_active   && to > 5)  to = 5;
    return to;
}

void app_service(svx_app *a, uint64_t now) {
    ctl_drain(&a->ctl);

    rc_service(a->rc, now);
    if (a->audio_ready) {
        jitter_tick(&a->jb, now);
        play_watch(a);
    }
    /* Re-sample the clock: rc_service() and the callbacks it fires (talker
     * events, connect) stamp timestamps with a fresh now_ms(), which is LATER
     * than the `now` sampled at entry. Passing the stale `now` to tgm_tick made
     * `now - last_traffic` underflow and the idle-drop fire the instant we
     * connected or a talker stopped. */
    /* Our own over is traffic too: without this a long over whose echo never
     * came back was cut by the idle drop's talkgroup change. */
    if (a->tx_active) tgm_note_local_tx(&a->tgm, now_ms());
    tgm_tick(&a->tgm, now_ms());
    tx_pump(a);

    /* If the link went away mid-over, stop rather than encode into a void. */
    if (a->tx_active && rc_get_state(a->rc) != RC_CONNECTED)
        tx_stop(a, "the connection dropped");

    /* Publish state for the panel widget. Self-throttling; catches connection,
     * talkgroup and PTT changes that reach here via rc_service and tx_pump. */
    status_export(a);

    if (now - a->last_report >= 60000) {
        a->last_report = now;
        rc_stats st;
        rc_get_stats(a->rc, &st);
        log_info("stats: rx %llu pkt (%d/s), tx %llu pkt, lost %llu (%.1f%%), "
                 "replayed %llu, bad-auth %llu",
                 (unsigned long long)st.rx_packets, st.rx_pps,
                 (unsigned long long)st.tx_packets,
                 (unsigned long long)st.rx_lost, st.loss_pct,
                 (unsigned long long)st.rx_replayed,
                 (unsigned long long)st.rx_auth_fail);
        if (a->audio_ready) {
            log_info("audio: %llu frames, %llu concealed, %llu underruns, "
                     "%llu dropped, %u ms buffered",
                     (unsigned long long)a->jb.n_frames,
                     (unsigned long long)a->jb.n_concealed,
                     (unsigned long long)a->jb.n_underruns,
                     (unsigned long long)jitter_dropped(&a->jb),
                     jitter_depth_ms(&a->jb));
        }
    }
}

/* ------------------------------------------------------------- actions */

void app_ptt(svx_app *a, ctl_tristate v)     { ctl_ptt(a, v); }
void app_tg_next(svx_app *a)                 { tgm_next(&a->tgm); }
void app_tg_prev(svx_app *a)                 { tgm_prev(&a->tgm); }
void app_tg_select(svx_app *a, uint32_t tg)  { tgm_select(&a->tgm, tg); }
void app_tg_index(svx_app *a, int idx)       { tgm_select_index(&a->tgm, idx); }
void app_toggle_lock(svx_app *a)             { tgm_toggle_lock(&a->tgm); }
void app_toggle_mute(svx_app *a, uint32_t t) { tgm_toggle_mute(&a->tgm, t); }
void app_reconnect(svx_app *a)               { rc_reconnect_now(a->rc); }
void app_quit(svx_app *a)                    { a->quit = 1; }
int  app_should_quit(const svx_app *a)       { return a->quit; }

void app_toggle_connect(svx_app *a) {
    if (rc_get_state(a->rc) == RC_IDLE) rc_start(a->rc);
    else                                rc_stop(a->rc, "disconnected by you");
}

void app_volume_delta(svx_app *a, int delta) {
    app_set_volume(a, a->cfg->output_volume_pct + delta);
}

void app_set_volume(svx_app *a, int pct) {
    int v = CLAMP(pct, 0, 100);
    /* The live value lives in the jitter buffer; cfg is const, so keep the
     * authoritative copy there and mirror it here for the display. */
    ((svx_config *)a->cfg)->output_volume_pct = v;
    a->out_muted = 0;
    if (a->audio_ready) jitter_set_volume(&a->jb, v);
    notify(a);
}

void app_toggle_output_mute(svx_app *a) {
    if (a->out_muted) {
        a->out_muted = 0;
        ((svx_config *)a->cfg)->output_volume_pct = a->volume_before_mute;
    } else {
        a->volume_before_mute = a->cfg->output_volume_pct;
        a->out_muted = 1;
        ((svx_config *)a->cfg)->output_volume_pct = 0;
    }
    if (a->audio_ready) jitter_set_volume(&a->jb, a->cfg->output_volume_pct);
    notify(a);
}

void app_set_input_device(svx_app *a, const char *dev) {
    if (a->no_tx) return;                 /* receive-only: nothing to open */
    if (a->tx_active) tx_stop(a, "input device changed");
    tx_close(a);
    snprintf(((svx_config *)a->cfg)->input_device,
             sizeof(a->cfg->input_device), "%s", (dev && *dev) ? dev : "default");
    tx_open(a);
    log_info("input device -> %s", a->cfg->input_device);
    notify(a);
}

void app_set_output_device(svx_app *a, const char *dev) {
    /* The capture device shares the audio context that audio_stop() tears down,
     * so close it first and re-open it afterwards. */
    int had_tx = a->tx_ready;
    if (a->tx_active) tx_stop(a, "output device changed");
    if (had_tx) tx_close(a);
    audio_stop(a);
    snprintf(((svx_config *)a->cfg)->output_device,
             sizeof(a->cfg->output_device), "%s", (dev && *dev) ? dev : "default");
    audio_start(a);
    if (had_tx) tx_open(a);
    log_info("output device -> %s", a->cfg->output_device);
    notify(a);
}

void app_test_tone(svx_app *a) {
    /* The point of a test tone is to prove the output path, so force the level
     * up: leaving it inaudible because the volume happened to be at 5% would
     * defeat the purpose. */
    if (!a->audio_ready) return;
    if (a->cfg->output_volume_pct < 50) {
        ((svx_config *)a->cfg)->output_volume_pct = 50;
        a->out_muted = 0;
        jitter_set_volume(&a->jb, 50);
    }
    tx_beep(a, 2);                  /* which kicks the gate open so it plays */
}

/* ----------------------------------------------------------- accessors */

const svx_config *app_config(const svx_app *a) { return a->cfg; }
rc_client        *app_rc(svx_app *a)           { return a->rc; }
tg_manager       *app_tgm(svx_app *a)          { return &a->tgm; }

int      app_tx_active(const svx_app *a)    { return a->tx_active; }
int      app_audio_ready(const svx_app *a)  { return a->audio_ready; }
int      app_volume(const svx_app *a)       { return a->cfg->output_volume_pct; }
int      app_output_muted(const svx_app *a) { return a->out_muted; }

int app_tx_available(const svx_app *a) { return !a->no_tx && a->tx_ready; }

uint64_t app_tx_elapsed_ms(const svx_app *a) {
    return a->tx_active ? now_ms() - a->tx_started_ms : 0;
}

float app_mic_level(const svx_app *a) {
    return atomic_load_explicit(&((svx_app *)a)->mic_peak, memory_order_relaxed);
}
float app_spk_level(const svx_app *a) {
    return atomic_load_explicit(&((svx_app *)a)->spk_peak, memory_order_relaxed);
}

uint32_t    app_jitter_ms(const svx_app *a)    { return a->audio_ready ? jitter_depth_ms(&a->jb) : 0; }
const char *app_jitter_state(const svx_app *a) { return a->audio_ready ? jitter_state_name(&a->jb) : "off"; }

const char *app_banner(const svx_app *a) { return a->banner[0] ? a->banner : NULL; }
void app_dismiss_banner(svx_app *a)      { a->banner[0] = '\0'; notify(a); }

/* ------------------------------------------------------------- headless */

static volatile sig_atomic_t g_quit;
static void on_signal(int sig) { (void)sig; g_quit = 1; }

int run_headless(const svx_config *cfg, int no_tx) {
    /* No SA_RESTART: poll() should return EINTR so the loop notices. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    svx_app *a = app_new(cfg, no_tx);
    if (!a) { log_err("out of memory"); return 1; }
    app_set_owner_kind(a, "headless");

    log_info("svxconnect headless — %s -> %s:%d%s",
             cfg->callsign, cfg->reflector, cfg->port, no_tx ? " (receive only)" : "");

    app_start(a);
    log_info("starting on TG %u%s", tgm_selected(&a->tgm),
             tgm_locked(&a->tgm) ? " (locked)" : "");

    while (!g_quit && !app_should_quit(a)) {
        uint64_t now = now_ms();

        struct pollfd p[10];
        int n  = app_poll_fds(a, p, 10);
        int to = app_next_timeout_ms(a, now);

        int pr = poll(p, (nfds_t)n, to);
        if (pr < 0 && errno != EINTR) {
            log_err("poll failed: %s", strerror(errno));
            break;
        }
        app_service(a, now_ms());
    }

    log_info("shutting down");
    app_free(a);
    return 0;
}
