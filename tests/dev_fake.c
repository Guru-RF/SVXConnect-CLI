/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * A fake audio backend for the tests: audio/dev.h with no sound card. The ring
 * handling for playback is the real one (playout.c); only the thread that
 * would call it is simulated, by fake_pump().
 */
#include "fakes.h"
#include "audio/playout.h"
#include "common/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct svx_dev {
    int              is_capture;
    int              started;
    int              dead;
    svx_ring        *ring;
    _Atomic float   *peak;
    svx_playout      po;
    _Atomic uint64_t cap_frames;
    _Atomic int      event;
    int              saw_nonsilence;
    uint64_t         last_pump_ms;
    uint32_t         noise;
};

#define MAX_DEVS 8
static svx_dev *g_devs[MAX_DEVS];
static int      g_opens[2];
static int      g_dead_next[2];

void fake_open_dead(int capture, int n) { g_dead_next[capture ? 1 : 0] = n; }
int  fake_opens(int capture)            { return g_opens[capture ? 1 : 0]; }

svx_dev *fake_current(int capture) {
    for (int i = MAX_DEVS - 1; i >= 0; i--)
        if (g_devs[i] && g_devs[i]->is_capture == (capture ? 1 : 0)) return g_devs[i];
    return NULL;
}

void fake_kill(svx_dev *d)                        { if (d) d->dead = 1; }
void fake_notify(svx_dev *d, svx_dev_event ev)    { if (d) atomic_store(&d->event, (int)ev); }
int  fake_gate(svx_dev *d)                        { return d ? atomic_load(&d->po.gate) : -1; }

void fake_pump(void) {
    uint64_t now = now_ms();
    for (int i = 0; i < MAX_DEVS; i++) {
        svx_dev *d = g_devs[i];
        if (!d || !d->started) continue;
        uint64_t ms = now - d->last_pump_ms;
        d->last_pump_ms = now;
        if (d->dead || ms == 0) continue;

        uint32_t n = (uint32_t)(ms * (SVX_RATE / 1000));
        int16_t  buf[SVX_RATE];
        if (n > SVX_RATE) n = SVX_RATE;
        if (d->is_capture) {
            for (uint32_t k = 0; k < n; k++) {
                d->noise = d->noise * 1103515245u + 12345u;
                buf[k] = (int16_t)((d->noise >> 16) % 200) - 100;
            }
            d->saw_nonsilence = 1;
            svx_ring_write(d->ring, buf, n);
            atomic_fetch_add(&d->cap_frames, n);
        } else {
            playout_consume(&d->po, d->ring, buf, n);
        }
    }
}

void fake_consume(svx_dev *d, int16_t *out, uint32_t n) {
    playout_consume(&d->po, d->ring, out, n);
}

/* ---- audio/dev.h ---- */

int  svx_audio_init(void)                 { return 0; }
void svx_audio_term(void)                 { }
const char *svx_audio_backend_name(void)  { return "fake"; }

int svx_audio_list(int capture, svx_devinfo *out, int max) {
    (void)capture;
    if (max < 1) return 0;
    memset(out, 0, sizeof(*out));
    snprintf(out->name, sizeof(out->name), "Fake");
    out->is_default = 1;
    return 1;
}

int svx_audio_resolve(int capture, const char *want, svx_devinfo *out) {
    (void)want;
    svx_audio_list(capture, out, 1);
    return 0;
}

static svx_dev *open_dev(int capture, svx_ring *ring, _Atomic float *peak) {
    int slot = -1;
    for (int i = 0; i < MAX_DEVS; i++) if (!g_devs[i]) { slot = i; break; }
    if (slot < 0) return NULL;
    svx_dev *d = calloc(1, sizeof(*d));
    d->is_capture = capture;
    d->ring       = ring;
    d->peak       = peak;
    d->noise      = 1;
    int k = capture ? 1 : 0;
    g_opens[k]++;
    if (g_dead_next[k] > 0) { d->dead = 1; g_dead_next[k]--; }
    g_devs[slot] = d;
    return d;
}

svx_dev *svx_dev_open_capture(const char *id, svx_ring *r, _Atomic float *pk)  { (void)id; return open_dev(1, r, pk); }
svx_dev *svx_dev_open_playback(const char *id, svx_ring *r, _Atomic float *pk) { (void)id; return open_dev(0, r, pk); }

int svx_dev_start(svx_dev *d) {
    if (!d) return -1;
    if (!d->started) { d->started = 1; d->last_pump_ms = now_ms(); }
    return 0;
}

int svx_dev_stop(svx_dev *d) { if (d) d->started = 0; return 0; }

void svx_dev_close(svx_dev *d) {
    if (!d) return;
    for (int i = 0; i < MAX_DEVS; i++) if (g_devs[i] == d) g_devs[i] = NULL;
    free(d);
}

void svx_dev_set_gate(svx_dev *d, int open)           { if (d) atomic_store(&d->po.gate, open ? 1 : 0); }
void svx_dev_request_flush(svx_dev *d)                { if (d) atomic_store(&d->po.flush_req, 1); }
void svx_dev_request_drop(svx_dev *d, uint32_t n)     { if (d && n) atomic_fetch_add(&d->po.drop_req, n); }
uint32_t svx_dev_drop_pending(svx_dev *d)             { return d ? atomic_load(&d->po.drop_req) : 0; }
void svx_dev_request_trim_newest(svx_dev *d, uint32_t n) { if (d) playout_request_trim_newest(&d->po, d->ring, n); }

const char *svx_dev_name(svx_dev *d)   { (void)d; return "Fake"; }
uint32_t svx_dev_underruns(svx_dev *d) { return d ? atomic_load(&d->po.underruns) : 0; }
uint32_t svx_dev_overruns(svx_dev *d)  { (void)d; return 0; }
uint64_t svx_dev_dropped(svx_dev *d)   { return d ? atomic_load(&d->po.dropped) : 0; }

uint64_t svx_dev_frames(svx_dev *d) {
    if (!d) return 0;
    return d->is_capture ? atomic_load(&d->cap_frames) : atomic_load(&d->po.frames);
}

svx_dev_event svx_dev_poll_event(svx_dev *d) {
    return d ? (svx_dev_event)atomic_exchange(&d->event, SVX_DEV_OK) : SVX_DEV_OK;
}

int  svx_dev_saw_nonsilence(svx_dev *d) { return d ? d->saw_nonsilence : 1; }
void svx_dev_reset_silence(svx_dev *d)  { if (d) d->saw_nonsilence = 0; }

svx_mic_state svx_mic_status(void)            { return SVX_MIC_GRANTED; }
svx_mic_state svx_mic_request(int timeout_ms) { (void)timeout_ms; return SVX_MIC_GRANTED; }
