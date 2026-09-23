/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * Playback jitter buffer and loss concealment.
 *
 * Neither reference implementation has one of these: the macOS app leans on
 * AVAudioPlayerNode's scheduled-buffer queue to hide the problem, and
 * SvxBridge decodes straight into a vocoder that does not care. Feeding raw
 * device callbacks from a WAN socket without a jitter buffer clicks on every
 * hiccup, so this is new code rather than a port.
 *
 * The state machine, over the playback ring:
 *
 *   IDLE ---- first packet ----> PREFILL ---- enough buffered ----> PLAYING
 *     ^                             ^                                  |
 *     |                             +--------- underrun ---------------+
 *     +------------------- silence timeout ---------------------------+
 *
 * In IDLE and PREFILL the device outputs silence, which is correct: there is
 * genuinely nothing to play yet. Starting playback the instant the first
 * packet lands is the classic mistake — it guarantees an underrun a few
 * milliseconds later.
 */
#ifndef SVX_JITTER_H
#define SVX_JITTER_H

#include <stdint.h>
#include <stddef.h>

#include "codec.h"
#include "common/ring.h"

typedef enum {
    JB_IDLE = 0,
    JB_PREFILL,
    JB_PLAYING
} jb_state;

struct svx_dev;

typedef struct {
    svx_ring         *ring;   /* the playback ring, not owned */
    svx_codec        *codec;  /* not owned */
    struct svx_dev   *dev;    /* playback device, not owned; drives the gate */

    jb_state   state;
    uint32_t   prefill_samples;
    uint32_t   max_samples;   /* above this we are drifting; drop the oldest */

    int        volume_pct;

    /* counters, for the status line */
    uint64_t   n_frames;      /* decoded and queued          */
    uint64_t   n_concealed;   /* synthesised to cover loss   */
    uint64_t   n_underruns;   /* fell back to PREFILL        */
    uint64_t   n_dropped;     /* discarded: ring full, or by a replaced device;
                               * jitter_dropped() adds the current device's */
    uint64_t   last_audio_ms;
} svx_jitter;

/* `jitter_ms` is the target prefill depth; 80 ms is a good default and the
 * config clamps it to 40..300. */
void jitter_init(svx_jitter *j, svx_ring *ring, svx_codec *codec, int jitter_ms);

/* Tell the buffer which playback device to gate. Until this is set the buffer
 * still works, but the device drains freely and prefill cannot accumulate. */
void jitter_set_device(svx_jitter *j, struct svx_dev *dev);

/* Feed one received Opus packet. `gap` is how many datagrams were lost
 * immediately before it, taken from the AES-GCM counter — the protocol has no
 * audio sequence number, but that counter is in the AAD in the clear and is
 * monotonic, so it serves. Each lost frame is concealed before this one is
 * decoded, which keeps the decoder's internal state continuous. */
void jitter_push(svx_jitter *j, const uint8_t *opus, size_t len, int gap);

/* Call once per main-loop iteration. Runs the state machine and the
 * silence timeout. */
void jitter_tick(svx_jitter *j, uint64_t now);

/* A transmission ended: let what is buffered drain, but stop expecting more. */
void jitter_end_of_stream(svx_jitter *j);

/* Throw everything away — a talkgroup change, so what is queued belongs to
 * the talkgroup we just left. */
void jitter_flush(svx_jitter *j);

/* Discard `ms` from the tail of what is buffered, to cut the squelch tail a
 * far-end repeater sends after a talker stops. */
void jitter_trim_tail(svx_jitter *j, int ms);

void jitter_set_volume(svx_jitter *j, int pct);

/* Samples discarded so far, for the statistics. */
uint64_t jitter_dropped(const svx_jitter *j);

/* Milliseconds currently buffered. */
uint32_t jitter_depth_ms(const svx_jitter *j);

const char *jitter_state_name(const svx_jitter *j);

#endif
