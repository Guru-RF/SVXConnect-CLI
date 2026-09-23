/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * Audio watchdog fixtures: when a device that "started" but is not running
 * gets reopened, and when the app stops relying on it. Pure logic on a
 * made-up clock, so every boundary is exact.
 */
#include "audio/watchdog.h"

#include <stdio.h>

static int g_fail, g_run;

#define CHECK(cond, ...) do {                               \
    g_run++;                                                \
    if (!(cond)) { g_fail++; printf("  FAIL  " __VA_ARGS__);\
                   printf("\n        at %s:%d\n", __FILE__, __LINE__); } \
} while (0)

static void t_healthy_device_is_left_alone(void) {
    printf("a device that delivers every 20 ms is never reopened\n");
    svx_watchdog w; svx_wd_init(&w, 500, 500, 1);
    svx_wd_start(&w, 1000, 0);
    int bad = 0;
    for (uint64_t t = 1000, n = 0; t < 61000; t += 20, n += 320)
        if (svx_wd_check(&w, t, n) != SVX_WD_OK) bad++;
    CHECK(bad == 0, "%d false alarms in a minute of normal audio", bad);
}

static void t_nothing_after_start(void) {
    printf("started but nothing arrives: reopen at the grace period, not before\n");
    svx_watchdog w; svx_wd_init(&w, 500, 500, 1);
    svx_wd_start(&w, 1000, 42);
    CHECK(svx_wd_check(&w, 1499, 42) == SVX_WD_OK,     "499 ms is still within grace");
    CHECK(svx_wd_check(&w, 1500, 42) == SVX_WD_REOPEN, "500 ms of nothing must reopen");
}

static void t_reopen_that_helps(void) {
    printf("a reopen that brings audio back resets the allowance\n");
    svx_watchdog w; svx_wd_init(&w, 500, 500, 1);
    svx_wd_start(&w, 0, 0);
    CHECK(svx_wd_check(&w, 500, 0) == SVX_WD_REOPEN, "first stall reopens");
    svx_wd_restarted(&w, 510, 0);                        /* new device counts from 0 */
    CHECK(svx_wd_check(&w, 540, 320) == SVX_WD_OK,   "the reopened device delivers");
    CHECK(w.reopens == 0, "progress must clear the reopen count, got %d", w.reopens);
    /* So a later, unrelated stall gets its own reopen rather than a give-up. */
    CHECK(svx_wd_check(&w, 1040, 320) == SVX_WD_REOPEN, "a later stall reopens again");
}

static void t_reopen_that_does_not_help(void) {
    printf("a reopen that brings nothing gives up instead of looping\n");
    svx_watchdog w; svx_wd_init(&w, 500, 500, 1);
    svx_wd_start(&w, 0, 0);
    CHECK(svx_wd_check(&w, 500, 0) == SVX_WD_REOPEN, "first stall reopens");
    svx_wd_restarted(&w, 500, 0);
    CHECK(svx_wd_check(&w, 999, 0)  == SVX_WD_OK,      "the reopened device gets its grace");
    CHECK(svx_wd_check(&w, 1000, 0) == SVX_WD_GIVE_UP, "still nothing: give up");
}

static void t_stall_mid_stream(void) {
    printf("audio that stops in the middle is caught after the stall limit\n");
    svx_watchdog w; svx_wd_init(&w, 500, 300, 1);
    svx_wd_start(&w, 0, 0);
    CHECK(svx_wd_check(&w, 20, 320)  == SVX_WD_OK, "flowing");
    CHECK(svx_wd_check(&w, 40, 640)  == SVX_WD_OK, "flowing");
    CHECK(svx_wd_check(&w, 339, 640) == SVX_WD_OK, "299 ms gap is tolerated");
    CHECK(svx_wd_check(&w, 340, 640) == SVX_WD_REOPEN,
          "once flowing, the stall limit (300) applies, not the grace (500)");
}

static void t_new_start_restores_allowance(void) {
    printf("a new over starts with a full reopen allowance\n");
    svx_watchdog w; svx_wd_init(&w, 500, 500, 1);
    svx_wd_start(&w, 0, 0);
    svx_wd_check(&w, 500, 0);                 /* reopen */
    svx_wd_restarted(&w, 500, 0);
    svx_wd_start(&w, 5000, 0);                /* key-up, next over */
    CHECK(svx_wd_check(&w, 5500, 0) == SVX_WD_REOPEN,
          "the next over must get its own reopen, not inherit a give-up");
}

static void t_trip(void) {
    printf("a device-reported stop reopens at once, then gives up\n");
    svx_watchdog w; svx_wd_init(&w, 500, 500, 1);
    svx_wd_start(&w, 0, 0);
    CHECK(svx_wd_trip(&w) == SVX_WD_REOPEN,  "first stop: reopen");
    CHECK(svx_wd_trip(&w) == SVX_WD_GIVE_UP, "second stop without progress: give up");
}

static void t_clock_behind(void) {
    printf("a 'now' older than the last restart is not a stall\n");
    /* The app samples its clock, then reopens and restarts the watchdog with a
     * fresher one; an unsigned subtraction would see ~49 days of silence. */
    svx_watchdog w; svx_wd_init(&w, 500, 500, 1);
    svx_wd_start(&w, 10000, 0);
    CHECK(svx_wd_check(&w, 9990, 0) == SVX_WD_OK, "must not underflow into a stall");
}

int main(void) {
    printf("\naudio watchdog fixtures\n\n");
    t_healthy_device_is_left_alone();
    t_nothing_after_start();
    t_reopen_that_helps();
    t_reopen_that_does_not_help();
    t_stall_mid_stream();
    t_new_start_restores_allowance();
    t_trip();
    t_clock_behind();
    printf("\n%d checks, %d failed\n\n", g_run, g_fail);
    return g_fail ? 1 : 0;
}
