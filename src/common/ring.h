/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * Single-producer / single-consumer lock-free ring of int16 samples.
 *
 * This is the ONLY thing that crosses the boundary between the audio device's
 * realtime callback thread and the main loop (that, and a couple of atomic
 * scalars). It allocates nothing after init, takes no locks, and never blocks,
 * because the realtime thread may do none of those things.
 *
 * The contract is strict and unenforced by the compiler, so state it plainly:
 *
 *   - EXACTLY ONE thread may call svx_ring_write(). It alone touches `head`.
 *   - EXACTLY ONE thread may call svx_ring_read()/_discard()/_reset(). It
 *     alone touches `tail`.
 *
 * For capture, the producer is the device thread and the consumer is the main
 * loop. For playback it is the other way round. Calling reset() from the wrong
 * side races with the realtime thread; do it from the consumer only.
 */
#ifndef SVX_RING_H
#define SVX_RING_H

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>

typedef struct {
    int16_t          *buf;
    uint32_t          cap;      /* always a power of two */
    uint32_t          mask;     /* cap - 1 */
    _Atomic uint32_t  head;     /* producer only */
    _Atomic uint32_t  tail;     /* consumer only */
} svx_ring;

/* `cap_samples` is rounded up to a power of two. Returns 0 on success. */
int  svx_ring_init(svx_ring *r, uint32_t cap_samples);
void svx_ring_free(svx_ring *r);

/* Write up to `n` samples. Returns how many were taken — a short return means
 * the consumer has fallen behind and the rest were dropped, which is the right
 * thing to do on a realtime thread. */
uint32_t svx_ring_write(svx_ring *r, const int16_t *src, uint32_t n);

/* Read up to `n` samples. Returns how many were delivered. */
uint32_t svx_ring_read(svx_ring *r, int16_t *dst, uint32_t n);

/* Samples available to read. */
uint32_t svx_ring_avail(const svx_ring *r);

/* Space available to write. */
uint32_t svx_ring_space(const svx_ring *r);

/* Throw away up to `n` samples without copying them. Consumer side only.
 * Used to trim a squelch tail and to catch up when the buffer has grown. */
uint32_t svx_ring_discard(svx_ring *r, uint32_t n);

/* Drop everything. Consumer side only. */
void svx_ring_reset(svx_ring *r);

#endif
