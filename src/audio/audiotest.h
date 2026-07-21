/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#ifndef SVX_AUDIOTEST_H
#define SVX_AUDIOTEST_H

#include "common/config.h"

/* `svxconnect --list-devices` */
int audio_list_devices(const svx_config *cfg);

/* `svxconnect --audio-test` — microphone straight back to the speaker through
 * a short delay, with text level meters. Proves the whole device path works
 * before any reflector or codec is involved. */
int audio_run_test(const svx_config *cfg);

#endif
