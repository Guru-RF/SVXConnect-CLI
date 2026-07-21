/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — Copyright (C) 2026 Joeri Van Dooren
 *
 * Microphone permission, wrapped so the rest of the program never has to know
 * which platform it is on. On macOS this defers to mic_tcc.m; everywhere else
 * there is no permission model outside Flatpak, which we do not ship, so
 * access is simply granted.
 */
#include "dev.h"

#if defined(__APPLE__)

/* Implemented in mic_tcc.m. */
int svx_mic_status_impl(void);
int svx_mic_request_impl(int timeout_ms);

svx_mic_state svx_mic_status(void) {
    return (svx_mic_state)svx_mic_status_impl();
}

svx_mic_state svx_mic_request(int timeout_ms) {
    return (svx_mic_state)svx_mic_request_impl(timeout_ms);
}

#else

svx_mic_state svx_mic_status(void)                { return SVX_MIC_GRANTED; }
svx_mic_state svx_mic_request(int timeout_ms)     { (void)timeout_ms; return SVX_MIC_GRANTED; }

#endif
