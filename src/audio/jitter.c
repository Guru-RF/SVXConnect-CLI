/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "jitter.h"
#include "audio/dev.h"
#include "common/log.h"
#include "common/util.h"

#include <string.h>

/* Beyond this much buffered we are accumulating rather than playing — either
 * the sender's clock runs slightly fast or we joined mid-transmission. Drop
 * the oldest audio to catch up; a growing delay is worse than a small glitch. */
#define JB_MAX_MS       300

/* No audio for this long means the transmission is over, whether or not we
 * were told. Back to IDLE so the next one prefills properly. */
#define JB_SILENCE_MS   400

static void gate(svx_jitter *j, int open) {
    if (j->dev) svx_dev_set_gate(j->dev, open);
}

void jitter_init(svx_jitter *j, svx_ring *ring, svx_codec *codec, int jitter_ms) {
    memset(j, 0, sizeof(*j));
    j->ring       = ring;
    j->codec      = codec;
    j->state      = JB_IDLE;
    j->volume_pct = 100;

    if (jitter_ms < 40)  jitter_ms = 40;
    if (jitter_ms > 300) jitter_ms = 300;

    j->prefill_samples = (uint32_t)jitter_ms * SVX_RATE / 1000;
    j->max_samples     = (uint32_t)JB_MAX_MS * SVX_RATE / 1000;
    if (j->max_samples < j->prefill_samples * 2)
        j->max_samples = j->prefill_samples * 2;
}

void jitter_set_device(svx_jitter *j, svx_dev *dev) {
    j->dev = dev;
    gate(j, j->state == JB_PLAYING);
}

static void queue_pcm(svx_jitter *j, int16_t *pcm, int n) {
    if (n <= 0) return;

    if (j->volume_pct != 100) codec_apply_volume(pcm, n, j->volume_pct);

    uint32_t wrote = svx_ring_write(j->ring, pcm, (uint32_t)n);
    if (wrote < (uint32_t)n) {
        /* The ring is full, which means playback is not draining it. Rare, and
         * always a symptom of something else, so count it rather than paper
         * over it. */
        j->n_dropped += (uint32_t)n - wrote;
    }
}

void jitter_push(svx_jitter *j, const uint8_t *opus, size_t len, int gap) {
    int16_t pcm[SVX_FRAME * 4];

    /* Conceal the lost frames FIRST, in order. Opus builds each concealed
     * frame from its running internal state, so running them before decoding
     * the packet that follows keeps that state continuous — doing it the other
     * way round produces an audible discontinuity. */
    for (int i = 0; i < gap && i < 8; i++) {
        int n = codec_decode(j->codec, NULL, 0, pcm, SVX_FRAME);
        if (n > 0) { queue_pcm(j, pcm, n); j->n_concealed++; }
    }

    int n = codec_decode(j->codec, opus, (int)len, pcm, SVX_FRAME * 4);
    if (n <= 0) return;

    queue_pcm(j, pcm, n);
    j->n_frames++;
    j->last_audio_ms = now_ms();

    if (j->state == JB_IDLE) {
        j->state = JB_PREFILL;
        log_dbg("jitter: prefilling %u ms", j->prefill_samples * 1000 / SVX_RATE);
    }
}

void jitter_tick(svx_jitter *j, uint64_t now) {
    uint32_t avail = svx_ring_avail(j->ring);

    switch (j->state) {
    case JB_IDLE:
        break;

    case JB_PREFILL:
        if (avail >= j->prefill_samples) {
            j->state = JB_PLAYING;
            gate(j, 1);
            log_dbg("jitter: playing, %u ms buffered", avail * 1000 / SVX_RATE);
        } else if (j->last_audio_ms && now - j->last_audio_ms > JB_SILENCE_MS) {
            /* Nothing more has arrived for JB_SILENCE_MS, so the sender has
             * stopped — either the over was shorter than the prefill target,
             * or this is a pause between segments (a parrot's courtesy tone
             * before its replay does exactly this). Either way, play out what
             * we have instead of sitting on it: waiting for a prefill that is
             * never coming would just swallow the audio. If more arrives
             * afterwards the buffer refills naturally from PLAYING. */
            j->state = JB_PLAYING;
            gate(j, 1);
            log_dbg("jitter: sender paused, playing the %u ms we have",
                    avail * 1000 / SVX_RATE);
        }
        break;

    case JB_PLAYING:
        if (avail == 0) {
            if (!j->last_audio_ms || now - j->last_audio_ms > JB_SILENCE_MS) {
                j->state = JB_IDLE;          /* over, cleanly */
                gate(j, 0);
            } else {
                j->state = JB_PREFILL;       /* starved mid-transmission */
                gate(j, 0);
                j->n_underruns++;
                log_dbg("jitter: underrun, refilling");
            }
        } else if (avail > j->max_samples) {
            /* Clock drift or a late join. Ask the CONSUMER to drop 20 ms of the
             * oldest audio; we must not advance the tail from this thread. The
             * request accumulates and svx_ring_discard caps to what is actually
             * buffered, so a tick outrunning a callback can never over-drop. */
            svx_dev_request_drop(j->dev, SVX_FRAME);
            j->n_dropped += SVX_FRAME;
            log_dbg("jitter: %u ms buffered, dropping 20 ms to catch up",
                    avail * 1000 / SVX_RATE);
        }
        break;
    }
}

void jitter_end_of_stream(svx_jitter *j) {
    /* Do NOT flush: what is buffered is the tail of the over and the listener
     * should hear it. Open the gate so it actually drains, and stop treating a
     * dry ring as an underrun. */
    j->last_audio_ms = 0;
    if (j->state == JB_PREFILL) j->state = JB_PLAYING;
    if (j->state == JB_PLAYING) gate(j, 1);
}

void jitter_flush(svx_jitter *j) {
    gate(j, 0);
    /* Clearing the ring is a tail operation, so the consumer does it. If there
     * is no device (the tests, and any front end that never opened audio) we
     * are the only thread touching the ring and can reset it directly. */
    if (j->dev) svx_dev_request_flush(j->dev);
    else        svx_ring_reset(j->ring);
    j->state         = JB_IDLE;
    j->last_audio_ms = 0;
    /* The decoder's state belongs to the stream we just abandoned; carrying it
     * into the next talkgroup would concealment-blend one into the other. */
    codec_reset(j->codec);
}

void jitter_trim_tail(svx_jitter *j, int ms) {
    if (ms <= 0) return;
    uint32_t want  = (uint32_t)ms * SVX_RATE / 1000;
    uint32_t avail = svx_ring_avail(j->ring);
    if (want > avail) want = avail;
    if (want == 0) return;
    /* Dropping the tail is the consumer's job — request it rather than racing
     * the callback. */
    if (j->dev) svx_dev_request_drop(j->dev, want);
    else        svx_ring_discard(j->ring, want);
    j->n_dropped += want;
}

void jitter_set_volume(svx_jitter *j, int pct) {
    j->volume_pct = CLAMP(pct, 0, 200);
}

uint32_t jitter_depth_ms(const svx_jitter *j) {
    return svx_ring_avail(j->ring) * 1000 / SVX_RATE;
}

const char *jitter_state_name(const svx_jitter *j) {
    switch (j->state) {
    case JB_IDLE:    return "idle";
    case JB_PREFILL: return "prefill";
    case JB_PLAYING: return "playing";
    default:         return "?";
    }
}
