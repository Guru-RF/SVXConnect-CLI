/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "playout.h"

#include <string.h>

#define TRIM_PENDING  ((uint64_t)1 << 63)

static float peak_abs_s16(const int16_t *p, uint32_t n) {
    int32_t m = 0;
    for (uint32_t i = 0; i < n; i++) {
        int32_t v = p[i] < 0 ? -(int32_t)p[i] : (int32_t)p[i];
        if (v > m) m = v;
    }
    return (float)m / 32768.0f;
}

/* How many of the next `want` samples may be played before the pending trim
 * span begins. When the read position has reached the span, the span is
 * discarded here and the request cleared. */
static uint32_t trim_limit(svx_playout *p, svx_ring *ring, uint32_t want) {
    uint64_t req = atomic_load_explicit(&p->trim_req, memory_order_acquire);
    if (!(req & TRIM_PENDING)) return want;

    uint32_t start = (uint32_t)req;
    uint32_t end   = start + (uint32_t)((req >> 32) & 0x7fffffffu);
    uint32_t tail  = svx_ring_read_pos(ring);

    /* Signed differences, because the positions are free-running and wrap. */
    if ((int32_t)(tail - start) < 0) {
        uint32_t before = start - tail;
        return want < before ? want : before;
    }

    /* At or inside the span (a flush or a catch-up drop may already have
     * carried us into it): discard what is left of it. */
    if ((int32_t)(end - tail) > 0) {
        uint32_t gone = svx_ring_discard(ring, end - tail);
        atomic_fetch_add_explicit(&p->dropped, gone, memory_order_relaxed);
    }
    /* Compare-exchange, so a newer request stored meanwhile is not lost. */
    atomic_compare_exchange_strong_explicit(&p->trim_req, &req, 0,
                                            memory_order_acq_rel, memory_order_relaxed);
    return want;
}

float playout_consume(svx_playout *p, svx_ring *ring, int16_t *out, uint32_t n) {
    /* Counted before anything can return early: this is what the watchdog
     * reads to know the callback is still being called at all. */
    atomic_fetch_add_explicit(&p->frames, n, memory_order_relaxed);

    /* Handled before the gate check so a flush or drop requested while gated
     * still takes effect. */
    if (atomic_exchange_explicit(&p->flush_req, 0, memory_order_relaxed))
        svx_ring_reset(ring);
    uint32_t drop = atomic_exchange_explicit(&p->drop_req, 0, memory_order_relaxed);
    if (drop) {
        /* Count what was really discarded, not what was asked for: a request
         * can exceed what is buffered, and the counter must not claim audio
         * was thrown away that never existed. */
        uint32_t gone = svx_ring_discard(ring, drop);
        atomic_fetch_add_explicit(&p->dropped, gone, memory_order_relaxed);
    }

    /* Gate closed: emit silence and leave the ring alone so it can fill.
     * Draining here regardless is what keeps a jitter buffer permanently
     * starved, because the device always takes exactly as much as arrives. */
    if (!atomic_load_explicit(&p->gate, memory_order_relaxed)) {
        memset(out, 0, (size_t)n * sizeof(int16_t));
        return 0.0f;
    }

    /* At most two reads: up to the start of a trim span, then — the span
     * discarded — on into whatever was written after it. */
    uint32_t got = 0;
    for (int pass = 0; pass < 2 && got < n; pass++) {
        uint32_t want = trim_limit(p, ring, n - got);
        uint32_t r    = svx_ring_read(ring, out + got, want);
        got += r;
        if (r < want) break;                     /* the ring ran dry */
    }

    if (got < n) {
        memset(out + got, 0, (n - got) * sizeof(int16_t));
        atomic_fetch_add_explicit(&p->underruns, 1, memory_order_relaxed);
    }
    return peak_abs_s16(out, n);
}

void playout_request_trim_newest(svx_playout *p, const svx_ring *ring, uint32_t n) {
    if (n == 0) return;
    if (n > 0x7fffffffu) n = 0x7fffffffu;
    uint32_t end   = svx_ring_write_pos(ring);
    uint32_t start = end - n;
    /* A second trim before the consumer reaches the first replaces it. Trims
     * come one per finished over, so that needs two overs to end inside one
     * buffer's worth of audio, and costs only the older squelch tail. */
    atomic_store_explicit(&p->trim_req,
                          TRIM_PENDING | ((uint64_t)n << 32) | start,
                          memory_order_release);
}
