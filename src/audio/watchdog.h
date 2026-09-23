/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * Audio device watchdog: the decision, and nothing else.
 *
 * A device whose start succeeds can still never run its callback. PulseAudio
 * over PipeWire does exactly that when the stream's link in the graph goes
 * away while it is corked: the uncork is acknowledged, miniaudio reports
 * success, and no sample ever arrives. Nothing is signalled anywhere, so the
 * only way to notice is to watch the callback's own progress counter — and the
 * only cure found is to close the device and open it again.
 *
 * This module decides WHEN to do that, from a monotonic count of frames the
 * device has processed. It does no I/O and reads no clock, so the rules can be
 * tested exactly; the app owns the device and does the reopening.
 *
 *   start ── progress within grace_ms ──> flowing ── gap > stall_ms ──┐
 *     │                                                                │
 *     └── nothing within grace_ms ──> REOPEN (up to max_reopens) <─────┘
 *                                        └── still nothing ──> GIVE_UP
 *
 * Progress at any point clears the reopen count, so a device that recovers
 * after a reopen gets the full allowance again next time.
 */
#ifndef SVX_AUDIO_WATCHDOG_H
#define SVX_AUDIO_WATCHDOG_H

#include <stdint.h>

typedef enum {
    SVX_WD_OK = 0,
    SVX_WD_REOPEN,     /* close and reopen the device, then svx_wd_restarted() */
    SVX_WD_GIVE_UP     /* reopening did not help; stop relying on the device */
} svx_wd_verdict;

typedef struct {
    uint32_t grace_ms;       /* the first frames are due within this long of a (re)start */
    uint32_t stall_ms;       /* once flowing, no gap may be longer than this */
    int      max_reopens;    /* consecutive reopens without progress before giving up */

    uint64_t since_ms;       /* last progress, or the last (re)start */
    uint64_t last_count;
    int      flowing;        /* progress seen since the last (re)start */
    int      reopens;        /* reopens since progress was last seen */
} svx_watchdog;

void svx_wd_init(svx_watchdog *w, uint32_t grace_ms, uint32_t stall_ms, int max_reopens);

/* The device was started afresh (a new over, say): full allowance again. */
void svx_wd_start(svx_watchdog *w, uint64_t now, uint64_t count);

/* The device was reopened on our REOPEN verdict. Unlike svx_wd_start this keeps
 * the reopen count, which is what lets a reopen that does not help end in
 * GIVE_UP instead of reopening forever. */
void svx_wd_restarted(svx_watchdog *w, uint64_t now, uint64_t count);

/* Call regularly while the device is meant to be running. */
svx_wd_verdict svx_wd_check(svx_watchdog *w, uint64_t now, uint64_t count);

/* The device told us it stopped: the same verdict a timeout would give, now. */
svx_wd_verdict svx_wd_trip(svx_watchdog *w);

#endif
