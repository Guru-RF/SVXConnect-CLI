/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "watchdog.h"

#include <string.h>

void svx_wd_init(svx_watchdog *w, uint32_t grace_ms, uint32_t stall_ms, int max_reopens) {
    memset(w, 0, sizeof(*w));
    w->grace_ms    = grace_ms;
    w->stall_ms    = stall_ms;
    w->max_reopens = max_reopens;
}

void svx_wd_start(svx_watchdog *w, uint64_t now, uint64_t count) {
    w->reopens = 0;
    svx_wd_restarted(w, now, count);
}

void svx_wd_restarted(svx_watchdog *w, uint64_t now, uint64_t count) {
    w->since_ms   = now;
    w->last_count = count;
    w->flowing    = 0;
}

svx_wd_verdict svx_wd_trip(svx_watchdog *w) {
    if (w->reopens >= w->max_reopens) return SVX_WD_GIVE_UP;
    w->reopens++;
    return SVX_WD_REOPEN;
}

svx_wd_verdict svx_wd_check(svx_watchdog *w, uint64_t now, uint64_t count) {
    if (count != w->last_count) {
        w->last_count = count;
        w->since_ms   = now;
        w->flowing    = 1;
        w->reopens    = 0;
        return SVX_WD_OK;
    }

    /* A `now` behind since_ms (the caller sampled its clock before we were
     * restarted) is "no time has passed", never an unsigned underflow into a
     * 49-day stall. */
    uint64_t quiet = now > w->since_ms ? now - w->since_ms : 0;
    uint32_t limit = w->flowing ? w->stall_ms : w->grace_ms;
    if (quiet < limit) return SVX_WD_OK;

    return svx_wd_trip(w);
}
