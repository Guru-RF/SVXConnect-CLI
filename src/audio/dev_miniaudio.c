/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — Copyright (C) 2026 Joeri Van Dooren
 *
 * Audio device backend built on miniaudio (third_party/miniaudio.h, MIT-0).
 *
 * Covers CoreAudio on macOS and PulseAudio/ALSA/JACK on Linux. On Linux the
 * client libraries are dlopen()ed at runtime rather than linked, which is why
 * this project has no audio -dev package to install on either platform.
 */

/* Trim the build to what a voice client needs. Decoding, encoding, the node
 * graph and the high-level engine are all dead weight here. */
#define MA_NO_DECODING
#define MA_NO_ENCODING
#define MA_NO_GENERATION
#define MA_NO_RESOURCE_MANAGER
#define MA_NO_NODE_GRAPH
#define MA_NO_ENGINE
#define MA_ENABLE_ONLY_SPECIFIC_BACKENDS
#if defined(__APPLE__)
#  define MA_ENABLE_COREAUDIO
#else
#  define MA_ENABLE_PULSEAUDIO
#  define MA_ENABLE_ALSA
#  define MA_ENABLE_JACK
#endif
#define MINIAUDIO_IMPLEMENTATION
#include "miniaudio.h"

#include "dev.h"
#include "common/log.h"
#include "common/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

struct svx_dev {
    ma_device        ma;
    int              is_capture;
    int              started;
    int              inited;

    svx_ring        *ring;
    _Atomic float   *peak;

    _Atomic uint32_t underruns;
    _Atomic uint32_t overruns;
    _Atomic int      gate;           /* playback: 0 = emit silence, do not drain */
    _Atomic int      flush_req;      /* playback: consumer drops everything      */
    _Atomic uint32_t drop_req;       /* playback: consumer drops this many oldest */
    _Atomic int      event;          /* svx_dev_event, set by the RT thread */
    _Atomic int      saw_nonsilence;

    char             name[256];
};

static ma_context g_ctx;
static int        g_ctx_ready;

const char *svx_audio_backend_name(void) {
    if (!g_ctx_ready) return "none";
    return ma_get_backend_name(g_ctx.backend);
}

int svx_audio_init(void) {
    if (g_ctx_ready) return 0;

#if defined(__APPLE__)
    ma_backend be[] = { ma_backend_coreaudio };
#else
    /* PulseAudio first: on Pi OS Bookworm and Ubuntu 22.04+ that is
     * pipewire-pulse, i.e. the native PipeWire graph. ALSA second for older
     * or bare systems, JACK last for anyone who has deliberately set it up. */
    ma_backend be[] = { ma_backend_pulseaudio, ma_backend_alsa, ma_backend_jack };
#endif

    ma_context_config cc = ma_context_config_init();
    cc.threadPriority         = ma_thread_priority_realtime;
    cc.pulse.pApplicationName = "SVXConnect";

    if (ma_context_init(be, (ma_uint32)(sizeof(be) / sizeof(be[0])), &cc, &g_ctx) != MA_SUCCESS) {
        log_err("cannot initialise the audio system");
        return -1;
    }
    g_ctx_ready = 1;
    log_dbg("audio backend: %s", svx_audio_backend_name());
    return 0;
}

void svx_audio_term(void) {
    if (!g_ctx_ready) return;
    ma_context_uninit(&g_ctx);
    g_ctx_ready = 0;
}

/* ------------------------------------------------------- enumeration */

/* The device id is a union of fixed-size members; the ones we care about are
 * all char arrays, so they round-trip through the config file as text. */
static void id_to_string(const ma_device_id *id, char *out, size_t cap) {
    out[0] = '\0';
    if (!id) return;
#if defined(MA_SUPPORT_COREAUDIO)
    snprintf(out, cap, "%s", id->coreaudio);
#elif defined(MA_SUPPORT_PULSEAUDIO)
    snprintf(out, cap, "%s", id->pulse);
#elif defined(MA_SUPPORT_ALSA)
    snprintf(out, cap, "%s", id->alsa);
#else
    (void)cap;
#endif
}

static int string_to_id(const char *s, ma_device_id *out) {
    if (!s || !*s) return 0;
    memset(out, 0, sizeof(*out));
#if defined(MA_SUPPORT_COREAUDIO)
    snprintf(out->coreaudio, sizeof(out->coreaudio), "%s", s);
    return 1;
#elif defined(MA_SUPPORT_PULSEAUDIO)
    snprintf(out->pulse, sizeof(out->pulse), "%s", s);
    return 1;
#elif defined(MA_SUPPORT_ALSA)
    snprintf(out->alsa, sizeof(out->alsa), "%s", s);
    return 1;
#else
    return 0;
#endif
}

int svx_audio_list(int capture, svx_devinfo *out, int max) {
    if (svx_audio_init() != 0) return -1;

    ma_device_info *pb = NULL, *cap = NULL;
    ma_uint32       npb = 0, ncap = 0;
    if (ma_context_get_devices(&g_ctx, &pb, &npb, &cap, &ncap) != MA_SUCCESS) {
        log_err("cannot enumerate audio devices");
        return -1;
    }

    ma_device_info *list = capture ? cap  : pb;
    ma_uint32       n    = capture ? ncap : npb;

    int got = 0;
    for (ma_uint32 i = 0; i < n && got < max; i++) {
        id_to_string(&list[i].id, out[got].id, sizeof(out[got].id));
        snprintf(out[got].name, sizeof(out[got].name), "%s", list[i].name);
        out[got].is_default = list[i].isDefault ? 1 : 0;
        got++;
    }
    return got;
}

int svx_audio_resolve(int capture, const char *want, svx_devinfo *out) {
    memset(out, 0, sizeof(*out));

    svx_devinfo devs[64];
    int n = svx_audio_list(capture, devs, 64);
    if (n <= 0) return 0;

    int def = -1;
    for (int i = 0; i < n; i++) if (devs[i].is_default) { def = i; break; }
    if (def < 0) def = 0;

    if (!want || !*want || str_ieq(want, "default")) {
        *out = devs[def];
        out->id[0] = '\0';          /* let the backend pick, so it tracks changes */
        return 0;
    }

    for (int i = 0; i < n; i++) if (strcmp(devs[i].id, want) == 0)   { *out = devs[i]; return 1; }
    for (int i = 0; i < n; i++) if (str_ieq(devs[i].name, want))     { *out = devs[i]; return 1; }
    for (int i = 0; i < n; i++) if (strcasestr(devs[i].name, want))  { *out = devs[i]; return 1; }

    log_warn("no %s device matches \"%s\" — using the system default (%s)",
             capture ? "input" : "output", want, devs[def].name);
    *out = devs[def];
    out->id[0] = '\0';
    return 0;
}

/* --------------------------------------------------- realtime callbacks */

static float peak_abs_s16(const int16_t *p, ma_uint32 n) {
    int32_t m = 0;
    for (ma_uint32 i = 0; i < n; i++) {
        int32_t v = p[i] < 0 ? -(int32_t)p[i] : (int32_t)p[i];
        if (v > m) m = v;
    }
    return (float)m / 32768.0f;
}

/* REALTIME THREAD. Arithmetic, memcpy and lock-free ring only — see dev.h. */
static void on_capture(ma_device *dev, void *out, const void *in, ma_uint32 n) {
    (void)out;
    svx_dev *d = (svx_dev *)dev->pUserData;
    const int16_t *s = (const int16_t *)in;

    float pk = peak_abs_s16(s, n);
    atomic_store_explicit(d->peak, pk, memory_order_relaxed);

    /* A genuinely open microphone always has at least a bit of noise. Perfect
     * zeros mean macOS denied us and said nothing (see docs/TCC.md). */
    if (pk > 0.0f) atomic_store_explicit(&d->saw_nonsilence, 1, memory_order_relaxed);

    uint32_t wrote = svx_ring_write(d->ring, s, n);
    if (wrote < n)
        atomic_fetch_add_explicit(&d->overruns, n - wrote, memory_order_relaxed);
}

/* REALTIME THREAD. */
static void on_playback(ma_device *dev, void *out, const void *in, ma_uint32 n) {
    (void)in;
    svx_dev *d = (svx_dev *)dev->pUserData;
    int16_t *o = (int16_t *)out;

    /* Flush and catch-up drops are requested by the producer (the main thread)
     * but PERFORMED here, because svx_ring's tail belongs to the consumer and
     * this callback is that consumer. Doing them on the producer side would be
     * two threads writing tail — a data race on a live audio path. Handled
     * before the gate check so a flush requested while gated still takes
     * effect. */
    if (atomic_exchange_explicit(&d->flush_req, 0, memory_order_relaxed))
        svx_ring_reset(d->ring);
    uint32_t drop = atomic_exchange_explicit(&d->drop_req, 0, memory_order_relaxed);
    if (drop) svx_ring_discard(d->ring, drop);

    /* Gate closed: emit silence and leave the ring alone so it can fill.
     * Draining here regardless is what keeps a jitter buffer permanently
     * starved, because the device always takes exactly as much as arrives. */
    if (!atomic_load_explicit(&d->gate, memory_order_relaxed)) {
        memset(o, 0, (size_t)n * sizeof(int16_t));
        atomic_store_explicit(d->peak, 0.0f, memory_order_relaxed);
        return;
    }

    uint32_t got = svx_ring_read(d->ring, o, n);
    if (got < n) {
        memset(o + got, 0, (n - got) * sizeof(int16_t));
        atomic_fetch_add_explicit(&d->underruns, 1, memory_order_relaxed);
    }
    atomic_store_explicit(d->peak, peak_abs_s16(o, n), memory_order_relaxed);
}

/* REALTIME-ADJACENT: store an enum, nothing more. The main loop reacts. */
static void on_notify(const ma_device_notification *n) {
    if (!n || !n->pDevice) return;
    svx_dev *d = (svx_dev *)n->pDevice->pUserData;
    if (!d) return;

    switch (n->type) {
    case ma_device_notification_type_stopped:
        atomic_store_explicit(&d->event, SVX_DEV_STOPPED, memory_order_relaxed);
        break;
    case ma_device_notification_type_rerouted:
        atomic_store_explicit(&d->event, SVX_DEV_REROUTED, memory_order_relaxed);
        break;
    default:
        break;
    }
}

/* --------------------------------------------------------------- open */

static svx_dev *dev_open(int capture, const char *id,
                         svx_ring *ring, _Atomic float *peak) {
    if (svx_audio_init() != 0) return NULL;

    svx_dev *d = calloc(1, sizeof(*d));
    if (!d) return NULL;
    d->is_capture = capture;
    d->ring       = ring;
    d->peak       = peak;

    ma_device_id  did;
    int           have_id = string_to_id(id, &did);

    ma_device_config c = ma_device_config_init(capture ? ma_device_type_capture
                                                       : ma_device_type_playback);
    if (capture) {
        c.capture.pDeviceID = have_id ? &did : NULL;
        c.capture.format    = ma_format_s16;
        c.capture.channels  = 1;
        c.capture.shareMode = ma_share_mode_shared;
    } else {
        c.playback.pDeviceID = have_id ? &did : NULL;
        c.playback.format    = ma_format_s16;
        c.playback.channels  = 1;
        c.playback.shareMode = ma_share_mode_shared;
    }

    /* Ask for exactly what the reflector speaks and let miniaudio resample.
     * The hardware will be running at 44.1 or 48 kHz; 48000/16000 = 3 is a
     * clean integer decimation. This is what removes the need for any
     * conversion code of our own. */
    c.sampleRate           = SVX_RATE;
    c.periodSizeInFrames   = SVX_FRAME;      /* 20 ms, matching an Opus frame */
    c.periods              = 3;              /* 60 ms of device buffering     */
    c.performanceProfile   = ma_performance_profile_low_latency;
    c.resampling.algorithm = ma_resample_algorithm_linear;
    c.resampling.linear.lpfOrder = 4;
#if defined(MA_SUPPORT_COREAUDIO)
    /* Do not renegotiate the hardware rate: changing the system sample rate
     * out from under other applications is rude and can glitch them. */
    c.coreaudio.allowNominalSampleRateChange = MA_FALSE;
#endif
    c.dataCallback         = capture ? on_capture : on_playback;
    c.notificationCallback = on_notify;
    c.pUserData            = d;

    if (ma_device_init(&g_ctx, &c, &d->ma) != MA_SUCCESS) {
        log_err("cannot open the %s device%s%s",
                capture ? "input" : "output",
                (id && *id) ? " " : "", (id && *id) ? id : "");
        free(d);
        return NULL;
    }
    d->inited = 1;

    ma_device_get_name(&d->ma, capture ? ma_device_type_capture : ma_device_type_playback,
                       d->name, sizeof(d->name), NULL);
    log_dbg("%s device: %s", capture ? "input" : "output", d->name);
    return d;
}

svx_dev *svx_dev_open_capture(const char *id, svx_ring *to_app, _Atomic float *peak) {
    return dev_open(1, id, to_app, peak);
}

svx_dev *svx_dev_open_playback(const char *id, svx_ring *from_app, _Atomic float *peak) {
    return dev_open(0, id, from_app, peak);
}

void svx_dev_set_gate(svx_dev *d, int open) {
    if (d) atomic_store_explicit(&d->gate, open ? 1 : 0, memory_order_relaxed);
}

void svx_dev_request_flush(svx_dev *d) {
    if (d) atomic_store_explicit(&d->flush_req, 1, memory_order_relaxed);
}

void svx_dev_request_drop(svx_dev *d, uint32_t samples) {
    /* Accumulate: several trims between callbacks must all be honoured. */
    if (d && samples) atomic_fetch_add_explicit(&d->drop_req, samples, memory_order_relaxed);
}

int svx_dev_start(svx_dev *d) {
    if (!d || !d->inited) return -1;
    if (d->started) return 0;
    if (ma_device_start(&d->ma) != MA_SUCCESS) {
        log_err("cannot start the %s device", d->is_capture ? "input" : "output");
        return -1;
    }
    d->started = 1;
    return 0;
}

int svx_dev_stop(svx_dev *d) {
    if (!d || !d->inited || !d->started) return 0;
    ma_device_stop(&d->ma);
    d->started = 0;
    return 0;
}

void svx_dev_close(svx_dev *d) {
    if (!d) return;
    if (d->inited) { svx_dev_stop(d); ma_device_uninit(&d->ma); }
    free(d);
}

/* --------------------------------------------------------- accessors */

const char *svx_dev_name(svx_dev *d) { return d && d->name[0] ? d->name : "(unknown)"; }

uint32_t svx_dev_underruns(svx_dev *d) {
    return d ? atomic_load_explicit(&d->underruns, memory_order_relaxed) : 0;
}
uint32_t svx_dev_overruns(svx_dev *d) {
    return d ? atomic_load_explicit(&d->overruns, memory_order_relaxed) : 0;
}

svx_dev_event svx_dev_poll_event(svx_dev *d) {
    if (!d) return SVX_DEV_OK;
    return (svx_dev_event)atomic_exchange_explicit(&d->event, SVX_DEV_OK, memory_order_relaxed);
}

int svx_dev_saw_nonsilence(svx_dev *d) {
    return d ? atomic_load_explicit(&d->saw_nonsilence, memory_order_relaxed) : 1;
}
void svx_dev_reset_silence(svx_dev *d) {
    if (d) atomic_store_explicit(&d->saw_nonsilence, 0, memory_order_relaxed);
}
