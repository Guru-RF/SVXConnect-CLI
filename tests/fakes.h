/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * Test doubles for the two things app.c talks to that need the outside world:
 * the audio device (dev_fake.c, a second implementation of audio/dev.h) and
 * the reflector client (rc_stub.c, of reflector/client.h). Link them in place
 * of dev_miniaudio.c and client.c.
 */
#ifndef SVX_TESTS_FAKES_H
#define SVX_TESTS_FAKES_H

#include <stdint.h>

#include "audio/dev.h"
#include "reflector/client.h"

/* ---- fake audio devices ---- */

/* Devices opened from now on for `capture` (1) or playback (0) whose callback
 * never runs once started — the "started, then nothing" stall. The next `n`
 * opens are dead; the ones after that work. */
void fake_open_dead(int capture, int n);

int      fake_opens(int capture);            /* opens so far */
svx_dev *fake_current(int capture);          /* the most recently opened, if still open */
void     fake_kill(svx_dev *d);              /* stop its callback from now on */
void     fake_notify(svx_dev *d, svx_dev_event ev);   /* the system says so */
int      fake_gate(svx_dev *d);              /* playback gate as last set */

/* Run every started, live device's callback for the real time elapsed since
 * the last call, the way the audio thread would. Capture writes a quiet noise
 * into its ring; playback consumes through playout_consume(). */
void fake_pump(void);

/* Run one playback callback for exactly `n` samples, gate and all. */
void fake_consume(svx_dev *d, int16_t *out, uint32_t n);

/* ---- reflector stub ---- */

void     stub_rc_set_state(rc_state st);
uint64_t stub_rc_audio_sent(void);
void     stub_rc_talker_start(uint32_t tg, const char *call);

#endif
