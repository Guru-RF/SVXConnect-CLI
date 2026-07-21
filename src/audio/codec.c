/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "codec.h"
#include "common/log.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include <opus.h>

struct svx_codec {
    OpusDecoder *dec;
    OpusEncoder *enc;

    /* AGC */
    int   agc_on;
    float agc_target;      /* wanted peak, linear */
    float agc_gain;
    float agc_env;

    /* DC blocker */
    float dc_x1, dc_y1;
};

static int16_t clamp16(float v) {
    if (v >  32767.0f) return  32767;
    if (v < -32768.0f) return -32768;
    return (int16_t)lrintf(v);
}

svx_codec *codec_open(void) {
    svx_codec *c = calloc(1, sizeof(*c));
    if (!c) return NULL;

    int err = 0;
    c->dec = opus_decoder_create(SVX_RATE, 1, &err);
    if (err != OPUS_OK || !c->dec) {
        log_err("cannot create the Opus decoder: %s", opus_strerror(err));
        codec_close(c);
        return NULL;
    }

    c->enc = opus_encoder_create(SVX_RATE, 1, OPUS_APPLICATION_AUDIO, &err);
    if (err != OPUS_OK || !c->enc) {
        log_err("cannot create the Opus encoder: %s", opus_strerror(err));
        codec_close(c);
        return NULL;
    }

    /* These match what SvxLink itself uses, which matters: a reflector mixes
     * our stream with others, and an encoder configured differently from the
     * rest of the network stands out.
     *
     * OPUS_APPLICATION_AUDIO rather than VOIP, with an explicit VOICE signal
     * hint — SvxBridge uses VOIP at 16 kbit/s, but that was a compromise for
     * feeding a 3600 bit/s vocoder, not what a human listener wants. */
    opus_encoder_ctl(c->enc, OPUS_SET_BITRATE(20000));
    opus_encoder_ctl(c->enc, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));
    opus_encoder_ctl(c->enc, OPUS_SET_COMPLEXITY(10));
    /* In-band FEC costs a little bitrate and lets the decoder rebuild a lost
     * frame from the next one. On a WAN path that is a good trade. */
    opus_encoder_ctl(c->enc, OPUS_SET_INBAND_FEC(1));
    opus_encoder_ctl(c->enc, OPUS_SET_PACKET_LOSS_PERC(5));
    /* No DTX: the reflector expects a continuous 50 frames a second while a
     * transmission is up, and gaps look like loss to everyone downstream. */
    opus_encoder_ctl(c->enc, OPUS_SET_DTX(0));

    c->agc_on     = 0;
    c->agc_target = 0.30f * 32767.0f;
    c->agc_gain   = 1.0f;
    c->agc_env    = 0.0f;
    return c;
}

void codec_close(svx_codec *c) {
    if (!c) return;
    if (c->dec) opus_decoder_destroy(c->dec);
    if (c->enc) opus_encoder_destroy(c->enc);
    free(c);
}

void codec_reset(svx_codec *c) {
    if (!c) return;
    if (c->dec) opus_decoder_ctl(c->dec, OPUS_RESET_STATE);
    if (c->enc) opus_encoder_ctl(c->enc, OPUS_RESET_STATE);
    c->agc_gain = 1.0f;
    c->agc_env  = 0.0f;
    c->dc_x1    = 0.0f;
    c->dc_y1    = 0.0f;
}

int codec_decode(svx_codec *c, const uint8_t *opus, int len,
                 int16_t *pcm, int max_samples) {
    /* opus_decode() treats a NULL packet as "conceal one frame". It needs to
     * be told how many samples to produce, since there is no packet to infer
     * it from. */
    if (!opus || len <= 0)
        return opus_decode(c->dec, NULL, 0, pcm,
                           max_samples < SVX_FRAME ? max_samples : SVX_FRAME, 0);
    return opus_decode(c->dec, opus, len, pcm, max_samples, 0);
}

int codec_encode(svx_codec *c, const int16_t *pcm, int n,
                 uint8_t *out, int cap) {
    return opus_encode(c->enc, pcm, n, out, cap);
}

/* ------------------------------------------------------------ filters */

void codec_set_agc(svx_codec *c, int on, int target_pct) {
    if (!c) return;
    c->agc_on = on;
    if (target_pct < 5)  target_pct = 5;
    if (target_pct > 95) target_pct = 95;
    c->agc_target = (float)target_pct / 100.0f * 32767.0f;
}

void codec_dcblock(svx_codec *c, int16_t *pcm, int n) {
    /* y = x - x1 + R*y1. R = 0.9976 at 16 kHz puts the corner near 12 Hz —
     * below anything a voice produces, so this is always safe to leave on. */
    const float R = 0.9976f;
    for (int i = 0; i < n; i++) {
        float x = (float)pcm[i];
        float y = x - c->dc_x1 + R * c->dc_y1;
        c->dc_x1 = x;
        c->dc_y1 = y;
        pcm[i] = clamp16(y);
    }
}

void codec_agc(svx_codec *c, int16_t *pcm, int n) {
    if (!c->agc_on) return;

    /* Deliberately slow. A fast AGC fighting the compressor at the far end is
     * what produces audible pumping, and the reflector network has plenty of
     * those already. */
    const float ATT     = 0.25f,  REL  = 0.0004f;   /* envelope   */
    const float G_DOWN  = 0.03f,  G_UP = 0.0010f;   /* gain       */
    const float MAXGAIN = 4.0f,   GATE = 300.0f;    /* boost cap / noise floor */
    const float CEIL    = 29000.0f;                 /* about -1 dBFS */

    for (int i = 0; i < n; i++) {
        float s   = (float)pcm[i];
        float mag = fabsf(s);

        c->agc_env += (mag - c->agc_env) * (mag > c->agc_env ? ATT : REL);

        float want = 1.0f;
        if (c->agc_env > GATE) {           /* do not amplify room hiss */
            want = c->agc_target / c->agc_env;
            if (want > MAXGAIN) want = MAXGAIN;
        }
        c->agc_gain += (want - c->agc_gain) * (want < c->agc_gain ? G_DOWN : G_UP);

        float o = s * c->agc_gain;
        /* Soft limiter. Hard clipping would inject broadband harmonics that
         * Opus then spends bits encoding faithfully. */
        o = CEIL * tanhf(o / CEIL);
        pcm[i] = clamp16(o);
    }
}

float codec_peak(const int16_t *pcm, int n) {
    int32_t m = 0;
    for (int i = 0; i < n; i++) {
        int32_t v = pcm[i] < 0 ? -(int32_t)pcm[i] : (int32_t)pcm[i];
        if (v > m) m = v;
    }
    return (float)m / 32768.0f;
}

void codec_apply_volume(int16_t *pcm, int n, int volume_pct) {
    if (volume_pct == 100) return;
    if (volume_pct <= 0) { memset(pcm, 0, (size_t)n * sizeof(int16_t)); return; }

    float g = (float)volume_pct / 100.0f;
    if (g <= 1.0f) {
        for (int i = 0; i < n; i++) pcm[i] = clamp16((float)pcm[i] * g);
    } else {
        /* Above 100% soft-limit, so turning it up cannot produce clipping
         * distortion that sounds like a fault in the link. */
        const float CEIL = 30000.0f;
        for (int i = 0; i < n; i++)
            pcm[i] = clamp16(CEIL * tanhf((float)pcm[i] * g / CEIL));
    }
}
