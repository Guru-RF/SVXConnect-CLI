/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — Copyright (C) 2026 Joeri Van Dooren
 *
 * macOS microphone permission (TCC).
 *
 * The awkward part is not this code, it is the model: macOS attributes a
 * microphone request to the *responsible process*, which for a program run
 * from a shell is the terminal application, not us. So the dialog says
 * "Terminal would like to access the microphone". See docs/TCC.md.
 *
 * Worse, a previously-denied terminal produces no prompt, no error and no
 * failure code — the device opens and delivers digital silence forever. That
 * case cannot be detected here at all; it is caught in dev_miniaudio.c by
 * watching for bit-exact zeros. This file only handles the case macOS is
 * willing to tell us about.
 */
#import <AVFoundation/AVFoundation.h>
#include <dispatch/dispatch.h>

/* Mirrors svx_mic_state in dev.h; kept as plain ints so this file does not
 * have to include a header that pulls in stdatomic and miniaudio. */
int svx_mic_status_impl(void) {
    if (@available(macOS 10.14, *)) {
        switch ([AVCaptureDevice authorizationStatusForMediaType:AVMediaTypeAudio]) {
        case AVAuthorizationStatusAuthorized:    return  1;
        case AVAuthorizationStatusNotDetermined: return  0;
        default:                                 return -1;   /* denied / restricted */
        }
    }
    return 1;   /* before 10.14 there was no microphone gate at all */
}

int svx_mic_request_impl(int timeout_ms) {
    if (@available(macOS 10.14, *)) {
        __block int r = -1;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);

        [AVCaptureDevice requestAccessForMediaType:AVMediaTypeAudio
                                 completionHandler:^(BOOL granted) {
            r = granted ? 1 : -1;
            dispatch_semaphore_signal(sem);
        }];

        /* Bounded wait: with no GUI session (over SSH, say) the completion
         * handler may simply never run, and hanging forever before the
         * interface has even started would be worse than giving up. */
        dispatch_time_t deadline =
            dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeout_ms * NSEC_PER_MSEC);
        if (dispatch_semaphore_wait(sem, deadline) != 0) return 0;   /* timed out */
        return r;
    }
    return 1;
}
