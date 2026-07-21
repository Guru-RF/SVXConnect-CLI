/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — Copyright (C) 2026 Joeri Van Dooren
 *
 * The audio device seam.
 *
 * This is the ONLY audio-device API the rest of the program sees. Today there
 * is one implementation behind it (dev_miniaudio.c, covering CoreAudio on
 * macOS and ALSA/PulseAudio/PipeWire/JACK on Linux); a native backend can be
 * added later as another .c file without touching a single call site.
 *
 * ==========================================================================
 * THE REALTIME RULE
 * ==========================================================================
 * The capture and playback callbacks run on a realtime thread owned by the
 * audio system. In them we may do arithmetic, memcpy, and lock-free ring
 * operations. We may NOT: malloc, free, take a lock, write to a file or pipe,
 * call log_*(), touch ncurses, run Opus, run OpenSSL, or call a socket
 * function. Any of those can block, and blocking a realtime callback produces
 * a click in the audio at best.
 *
 * Everything that is not arithmetic happens on the main thread. Audio crosses
 * the boundary through an svx_ring and a couple of atomic scalars, and nothing
 * else crosses at all — in particular the realtime thread never wakes the main
 * loop. The main loop polls the ring instead, which costs a few milliseconds
 * of latency on a 20 ms frame and makes realtime safety trivially provable.
 */
#ifndef SVX_AUDIO_DEV_H
#define SVX_AUDIO_DEV_H

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>

#include "common/ring.h"

/* The reflector carries 16 kHz mono Opus in 20 ms frames. Everything upstream
 * of the device layer works in exactly this format; the backend is responsible
 * for converting whatever the hardware actually runs at. */
#define SVX_RATE   16000
#define SVX_FRAME  320            /* samples in 20 ms at 16 kHz, mono */

typedef struct svx_dev svx_dev;

typedef struct {
    char id[256];        /* backend-stable identifier; "" means system default */
    char name[256];      /* what to show a human */
    int  is_default;
} svx_devinfo;

typedef enum {
    SVX_DEV_OK = 0,
    SVX_DEV_STOPPED,     /* the device stopped on its own */
    SVX_DEV_REROUTED,    /* the default device changed under us */
    SVX_DEV_LOST         /* unplugged */
} svx_dev_event;

/* ---- library lifetime ---- */
int  svx_audio_init(void);
void svx_audio_term(void);
const char *svx_audio_backend_name(void);

/* List devices into `out`. `capture` selects inputs vs outputs. Returns the
 * count written, or -1. */
int  svx_audio_list(int capture, svx_devinfo *out, int max);

/* Resolve a user-supplied device string to an id.
 *
 * Matching is id first, then an exact name, then a case-insensitive substring
 * of the name, then the system default. "" and "default" mean the default
 * outright. This ordering matters: a device saved by id survives being renamed,
 * and one saved by name survives being re-enumerated with a different id.
 * Returns 1 if a specific device matched, 0 if it fell through to the default. */
int  svx_audio_resolve(int capture, const char *want, svx_devinfo *out);

/* ---- streams ----
 * Both take the ring the realtime thread will touch and an atomic slot it
 * writes the current peak level into (0.0 .. 1.0). Nothing else crosses. */
svx_dev *svx_dev_open_capture (const char *id, svx_ring *to_app,   _Atomic float *peak);
svx_dev *svx_dev_open_playback(const char *id, svx_ring *from_app, _Atomic float *peak);

int   svx_dev_start(svx_dev *d);
int   svx_dev_stop (svx_dev *d);          /* idempotent */
void  svx_dev_close(svx_dev *d);

/* Playback only: open or close the output gate.
 *
 * While the gate is CLOSED the callback emits silence and does NOT drain the
 * ring, which is what lets the jitter buffer accumulate its prefill. Without
 * this the device consumes every sample the instant it arrives, the ring
 * hovers at empty, the prefill target is never reached and playback stutters
 * permanently. The gate starts closed. */
void  svx_dev_set_gate(svx_dev *d, int open);

const char *svx_dev_name(svx_dev *d);
uint32_t    svx_dev_underruns(svx_dev *d);   /* playback: starved callbacks */
uint32_t    svx_dev_overruns (svx_dev *d);   /* capture: samples dropped    */

/* Drained by the main loop. The realtime thread only stores an enum. */
svx_dev_event svx_dev_poll_event(svx_dev *d);

/* Has the capture stream produced anything but bit-exact silence since the
 * last svx_dev_reset_silence()? On macOS a microphone the user's terminal was
 * denied access to opens successfully and then delivers perfect zeros forever,
 * with no error anywhere — this is how that gets caught. A real microphone
 * always produces at least a least-significant bit of noise. */
int  svx_dev_saw_nonsilence(svx_dev *d);
void svx_dev_reset_silence(svx_dev *d);

/* ---- microphone permission (macOS TCC; a no-op elsewhere) ---- */
typedef enum {
    SVX_MIC_DENIED       = -1,
    SVX_MIC_UNDETERMINED =  0,
    SVX_MIC_GRANTED      =  1
} svx_mic_state;

svx_mic_state svx_mic_status(void);

/* Ask for access. BLOCKS while the system dialog is up, so it must be called
 * before ncurses takes over the terminal. Returns the resulting state. */
svx_mic_state svx_mic_request(int timeout_ms);

#endif
