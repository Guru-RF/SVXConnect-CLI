/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * Playback fixtures: the consumer side of the playback ring (what the output
 * callback does) and the jitter buffer's requests to it. Runs on the fake
 * device, with this file standing in for the audio thread.
 */
#include "audio/playout.h"
#include "audio/jitter.h"
#include "audio/codec.h"
#include "common/log.h"
#include "fakes.h"

#include <stdio.h>
#include <string.h>

static int g_fail, g_run;

#define CHECK(cond, ...) do {                               \
    g_run++;                                                \
    if (!(cond)) { g_fail++; printf("  FAIL  " __VA_ARGS__);\
                   printf("\n        at %s:%d\n", __FILE__, __LINE__); } \
} while (0)

/* Write the values from..to-1 as samples, so what comes out says exactly
 * which part of the stream was played. */
static void write_ramp(svx_ring *r, int from, int to) {
    for (int v = from; v < to; v++) {
        int16_t s = (int16_t)v;
        svx_ring_write(r, &s, 1);
    }
}

static void t_drop_counts_what_was_dropped(void) {
    printf("playout: the drop counter counts samples really discarded\n");
    svx_ring r; svx_ring_init(&r, 8192);
    svx_playout p; memset(&p, 0, sizeof(p));
    int16_t out[320];

    write_ramp(&r, 0, 100);
    atomic_store(&p.drop_req, 1000);          /* more than is buffered */
    playout_consume(&p, &r, out, 320);
    CHECK(atomic_load(&p.dropped) == 100,
          "only 100 samples existed to drop, counter says %llu",
          (unsigned long long)atomic_load(&p.dropped));
    svx_ring_free(&r);
}

static void t_gate_closed_counts_but_keeps(void) {
    printf("playout: gated, the callback still counts but leaves the ring alone\n");
    svx_ring r; svx_ring_init(&r, 8192);
    svx_playout p; memset(&p, 0, sizeof(p));
    int16_t out[320];

    write_ramp(&r, 1, 641);
    playout_consume(&p, &r, out, 320);
    CHECK(svx_ring_avail(&r) == 640, "gated must not drain, %u left", svx_ring_avail(&r));
    CHECK(atomic_load(&p.frames) == 320, "frames is the proof of life, even gated");
    CHECK(out[0] == 0 && out[319] == 0, "gated output is silence");
    svx_ring_free(&r);
}

static void t_trim_cuts_the_newest(void) {
    printf("playout: a tail trim removes the newest audio, not the oldest\n");
    svx_ring r; svx_ring_init(&r, 8192);
    svx_playout p; memset(&p, 0, sizeof(p));
    atomic_store(&p.gate, 1);
    int16_t out[2000];

    write_ramp(&r, 0, 1000);                  /* an over; its last 300 are squelch tail */
    playout_request_trim_newest(&p, &r, 300);
    write_ramp(&r, 1000, 1100);               /* the next over begins */

    playout_consume(&p, &r, out, 800);
    int ok = 1;
    for (int i = 0; i < 700; i++) if (out[i] != i) { ok = 0; break; }
    CHECK(ok, "the first 700 samples of the over must play in order");
    CHECK(out[700] == 1000 && out[799] == 1099,
          "after the trimmed span the next over plays (got %d .. %d)", out[700], out[799]);
    CHECK(atomic_load(&p.dropped) == 300, "300 trimmed, counter says %llu",
          (unsigned long long)atomic_load(&p.dropped));
    CHECK(atomic_load(&p.trim_req) == 0, "the trim request is cleared once done");
    svx_ring_free(&r);
}

static void t_trim_partly_played(void) {
    printf("playout: a trim whose span is already partly played drops the rest\n");
    svx_ring r; svx_ring_init(&r, 8192);
    svx_playout p; memset(&p, 0, sizeof(p));
    atomic_store(&p.gate, 1);
    int16_t out[1000];

    write_ramp(&r, 0, 1000);
    playout_consume(&p, &r, out, 800);        /* played into the last 300 already */
    playout_request_trim_newest(&p, &r, 300);
    playout_consume(&p, &r, out, 320);
    CHECK(svx_ring_avail(&r) == 0, "the unplayed 200 of the span must go, %u left",
          svx_ring_avail(&r));
    CHECK(atomic_load(&p.dropped) == 200, "200 trimmed, counter says %llu",
          (unsigned long long)atomic_load(&p.dropped));
    svx_ring_free(&r);
}

static void t_jitter_trim_via_device(void) {
    printf("jitter: trim_tail cuts the squelch tail off the end of the over\n");
    svx_ring r; svx_ring_init(&r, 8192);
    _Atomic float pk = 0;
    svx_codec *c = codec_open();
    svx_jitter j; jitter_init(&j, &r, c, 80);
    svx_dev *d = svx_dev_open_playback("", &r, &pk);
    jitter_set_device(&j, d);
    svx_dev_set_gate(d, 1);

    write_ramp(&r, 0, 1600);                  /* 100 ms of over */
    jitter_trim_tail(&j, 25);                 /* its last 25 ms (400) are squelch */
    int16_t out[1600];
    fake_consume(d, out, 1600);
    CHECK(out[0] == 0 && out[1199] == 1199, "the speech plays (got %d .. %d)", out[0], out[1199]);
    CHECK(out[1200] == 0 && out[1599] == 0, "the squelch tail does not (got %d)", out[1200]);
    CHECK(jitter_dropped(&j) == 400, "400 trimmed, counter says %llu",
          (unsigned long long)jitter_dropped(&j));
    svx_dev_close(d);
    codec_close(c);
    svx_ring_free(&r);
}

static void t_jitter_drop_requests_do_not_pile_up(void) {
    printf("jitter: catch-up drops are not requested faster than they happen\n");
    svx_ring r; svx_ring_init(&r, 8192);
    _Atomic float pk = 0;
    svx_codec *c = codec_open();
    svx_jitter j; jitter_init(&j, &r, c, 80);
    svx_dev *d = svx_dev_open_playback("", &r, &pk);
    jitter_set_device(&j, d);

    write_ramp(&r, 0, 8000);                  /* 500 ms, far above the 300 ms cap */
    j.state = JB_PLAYING;
    j.last_audio_ms = 1;
    for (int i = 0; i < 1000; i++) jitter_tick(&j, 2);   /* the callback is not running */
    CHECK(svx_dev_drop_pending(d) == SVX_FRAME,
          "one 20 ms drop outstanding, not %u samples", svx_dev_drop_pending(d));
    CHECK(jitter_dropped(&j) == 0,
          "nothing was dropped yet, the counter says %llu",
          (unsigned long long)jitter_dropped(&j));
    svx_dev_close(d);
    codec_close(c);
    svx_ring_free(&r);
}

static void t_kick_plays_a_beep_while_idle(void) {
    printf("jitter: audio queued while idle opens the gate\n");
    svx_ring r; svx_ring_init(&r, 8192);
    _Atomic float pk = 0;
    svx_codec *c = codec_open();
    svx_jitter j; jitter_init(&j, &r, c, 80);
    svx_dev *d = svx_dev_open_playback("", &r, &pk);
    jitter_set_device(&j, d);

    jitter_kick(&j);
    CHECK(fake_gate(d) == 0 && j.state == JB_IDLE, "nothing queued: stay idle and gated");

    write_ramp(&r, 1, 2001);                  /* a beep */
    jitter_kick(&j);
    CHECK(fake_gate(d) == 1, "the gate must open so the beep plays now");
    CHECK(j.state == JB_PLAYING, "state %s", jitter_state_name(&j));

    /* Drained: back to idle cleanly, not counted as an underrun. */
    svx_ring_reset(&r);
    jitter_tick(&j, 10000);
    CHECK(j.state == JB_IDLE && fake_gate(d) == 0 && j.n_underruns == 0,
          "after the beep: idle, gated, no underrun (state %s, underruns %llu)",
          jitter_state_name(&j), (unsigned long long)j.n_underruns);
    svx_dev_close(d);
    codec_close(c);
    svx_ring_free(&r);
}

int main(void) {
    log_set_level(LOG_ERR);
    printf("\nplayback fixtures\n\n");
    t_drop_counts_what_was_dropped();
    t_gate_closed_counts_but_keeps();
    t_trim_cuts_the_newest();
    t_trim_partly_played();
    t_jitter_trim_via_device();
    t_jitter_drop_requests_do_not_pile_up();
    t_kick_plays_a_beep_while_idle();
    printf("\n%d checks, %d failed\n\n", g_run, g_fail);
    return g_fail ? 1 : 0;
}
