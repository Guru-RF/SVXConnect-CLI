/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * Opus codec plus the microphone conditioning chain.
 *
 * Everything here works in the reflector's native format — 16 kHz mono, 20 ms
 * frames of 320 int16 samples. There is deliberately no resampling: the device
 * layer already delivers 16 kHz (see audio/dev.h), which is what makes this
 * module so much smaller than the equivalent in SvxBridge, where the whole
 * point was converting to the vocoder's 8 kHz.
 */
#ifndef SVX_CODEC_H
#define SVX_CODEC_H

#include <stdint.h>
#include <stddef.h>

#include "dev.h"     /* SVX_RATE, SVX_FRAME */

/* Largest Opus packet we will send or accept. Real frames at 20 kbit/s are
 * around 50 bytes; this is generous and still far below the UDP MTU. */
#define SVX_MAX_OPUS 400

typedef struct svx_codec svx_codec;

svx_codec *codec_open(void);
void       codec_close(svx_codec *c);

/* Decode one Opus packet into 16 kHz PCM. Returns the sample count, or < 0.
 *
 * Pass opus == NULL, len == 0 to run packet loss concealment for one frame:
 * Opus synthesises a plausible continuation rather than leaving a hole, which
 * sounds enormously better than silence on a lossy link. */
int codec_decode(svx_codec *c, const uint8_t *opus, int len,
                 int16_t *pcm, int max_samples);

/* Encode exactly one frame (SVX_FRAME samples). Returns the byte count, or < 0. */
int codec_encode(svx_codec *c, const int16_t *pcm, int n,
                 uint8_t *out, int cap);

/* Clear all filter, AGC and codec state.
 *
 * Must be called at the start of every transmission and after every talkgroup
 * change. Neither reference implementation does this, so AGC gain and the DC
 * blocker's history leak across unrelated transmissions — the first syllable
 * of an over gets the gain that suited the previous one. */
void codec_reset(svx_codec *c);

/* ---- microphone conditioning, applied in place before encoding ---- */

/* Level the audio toward `target_pct` of full scale. Slow attack and release
 * with a soft tanh limiter, deliberately gentle so it does not pump. */
void codec_set_agc(svx_codec *c, int on, int target_pct);
void codec_agc(svx_codec *c, int16_t *pcm, int n);

/* One-pole high pass, corner around 12 Hz at 16 kHz. Removes DC offset and
 * sub-audible rumble without touching voice, including low male fundamentals. */
void codec_dcblock(svx_codec *c, int16_t *pcm, int n);

/* Peak level of a block, 0.0 .. 1.0. */
float codec_peak(const int16_t *pcm, int n);

/* Apply a linear volume in place, 0..100 percent, with a soft ceiling. */
void codec_apply_volume(int16_t *pcm, int n, int volume_pct);

#endif
