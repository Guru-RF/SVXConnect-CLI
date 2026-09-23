/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "ring.h"

#include <stdlib.h>
#include <string.h>

static uint32_t next_pow2(uint32_t v) {
    if (v < 2) return 2;
    v--;
    v |= v >> 1; v |= v >> 2; v |= v >> 4; v |= v >> 8; v |= v >> 16;
    return v + 1;
}

int svx_ring_init(svx_ring *r, uint32_t cap_samples) {
    memset(r, 0, sizeof(*r));
    uint32_t cap = next_pow2(cap_samples);
    r->buf = calloc(cap, sizeof(int16_t));
    if (!r->buf) return -1;
    r->cap  = cap;
    r->mask = cap - 1;
    atomic_store_explicit(&r->head, 0, memory_order_relaxed);
    atomic_store_explicit(&r->tail, 0, memory_order_relaxed);
    return 0;
}

void svx_ring_free(svx_ring *r) {
    if (!r) return;
    free(r->buf);
    r->buf = NULL;
    r->cap = r->mask = 0;
}

/* head and tail are free-running counters, never wrapped. Only the indices
 * derived from them are masked. The difference is therefore always the true
 * fill level, and it stays correct across the 32-bit wrap because unsigned
 * subtraction wraps consistently. */

uint32_t svx_ring_avail(const svx_ring *r) {
    uint32_t h = atomic_load_explicit(&r->head, memory_order_acquire);
    uint32_t t = atomic_load_explicit(&r->tail, memory_order_relaxed);
    return h - t;
}

uint32_t svx_ring_space(const svx_ring *r) {
    return r->cap - svx_ring_avail(r);
}

uint32_t svx_ring_write(svx_ring *r, const int16_t *src, uint32_t n) {
    uint32_t h     = atomic_load_explicit(&r->head, memory_order_relaxed);
    uint32_t t     = atomic_load_explicit(&r->tail, memory_order_acquire);
    uint32_t space = r->cap - (h - t);
    if (n > space) n = space;
    if (n == 0) return 0;

    uint32_t idx   = h & r->mask;
    uint32_t first = r->cap - idx;
    if (first > n) first = n;

    memcpy(r->buf + idx, src, first * sizeof(int16_t));
    if (n > first) memcpy(r->buf, src + first, (n - first) * sizeof(int16_t));

    /* Release: the samples above must be visible before the consumer can see
     * the new head and start reading them. */
    atomic_store_explicit(&r->head, h + n, memory_order_release);
    return n;
}

uint32_t svx_ring_read(svx_ring *r, int16_t *dst, uint32_t n) {
    uint32_t t    = atomic_load_explicit(&r->tail, memory_order_relaxed);
    uint32_t h    = atomic_load_explicit(&r->head, memory_order_acquire);
    uint32_t have = h - t;
    if (n > have) n = have;
    if (n == 0) return 0;

    uint32_t idx   = t & r->mask;
    uint32_t first = r->cap - idx;
    if (first > n) first = n;

    memcpy(dst, r->buf + idx, first * sizeof(int16_t));
    if (n > first) memcpy(dst + first, r->buf, (n - first) * sizeof(int16_t));

    atomic_store_explicit(&r->tail, t + n, memory_order_release);
    return n;
}

uint32_t svx_ring_discard(svx_ring *r, uint32_t n) {
    uint32_t t    = atomic_load_explicit(&r->tail, memory_order_relaxed);
    uint32_t h    = atomic_load_explicit(&r->head, memory_order_acquire);
    uint32_t have = h - t;
    if (n > have) n = have;
    if (n == 0) return 0;
    atomic_store_explicit(&r->tail, t + n, memory_order_release);
    return n;
}

void svx_ring_reset(svx_ring *r) {
    /* Move the tail up to the head rather than zeroing both: writing head
     * here would race with the producer, which owns it. */
    uint32_t h = atomic_load_explicit(&r->head, memory_order_acquire);
    atomic_store_explicit(&r->tail, h, memory_order_release);
}

uint32_t svx_ring_write_pos(const svx_ring *r) {
    return atomic_load_explicit(&r->head, memory_order_relaxed);
}

uint32_t svx_ring_read_pos(const svx_ring *r) {
    return atomic_load_explicit(&r->tail, memory_order_relaxed);
}
