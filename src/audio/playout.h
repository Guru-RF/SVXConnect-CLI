/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * The playback consumer: what the output device's realtime callback does with
 * the playback ring, pulled out of the backend so it can be tested without a
 * sound card.
 *
 * The main thread is the ring's producer and may not move its tail, so every
 * change to what is buffered (a flush, a catch-up drop, a squelch-tail trim)
 * is a REQUEST stored here in an atomic, and playout_consume() — the consumer —
 * performs it. See dev.h for the realtime rule this code lives under.
 */
#ifndef SVX_AUDIO_PLAYOUT_H
#define SVX_AUDIO_PLAYOUT_H

#include <stdint.h>
#include <stdatomic.h>

#include "common/ring.h"

typedef struct {
    _Atomic int      gate;        /* 0 = emit silence, do not drain */
    _Atomic int      flush_req;   /* drop everything */
    _Atomic uint32_t drop_req;    /* drop this many of the OLDEST samples */
    /* Drop a span at the NEWEST end, as ring positions: bit 63 = pending,
     * bits 32..62 = length, bits 0..31 = the write position it starts at. One
     * 64-bit word, so the consumer never sees half of a request. */
    _Atomic uint64_t trim_req;

    _Atomic uint64_t frames;      /* samples the device asked for: proof of life */
    _Atomic uint64_t dropped;     /* samples actually discarded by drop and trim */
    _Atomic uint32_t underruns;
} svx_playout;

/* REALTIME THREAD. Fill `out` with `n` samples from `ring`, honouring the
 * requests above. Returns the peak level of what was written (0.0 .. 1.0). */
float playout_consume(svx_playout *p, svx_ring *ring, int16_t *out, uint32_t n);

/* Main thread (the producer). Discard the newest `n` samples written so far —
 * the squelch tail of an over that just ended. What the consumer has already
 * played is simply not trimmed again. */
void playout_request_trim_newest(svx_playout *p, const svx_ring *ring, uint32_t n);

#endif
