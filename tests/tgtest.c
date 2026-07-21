/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — Copyright (C) 2026 Joeri Van Dooren
 *
 * Talkgroup manager fixtures.
 *
 * The preemption rules are the one piece of this program whose behaviour is
 * pure logic with no I/O, so it is the one piece that can be tested properly.
 * Run with `make test`.
 */
#include "tg/tgmanager.h"
#include "common/config.h"
#include "common/log.h"
#include "common/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail;
static int g_run;

/* What the manager asked the reflector to do. */
static uint32_t g_selected;
static int      g_gate;
static uint32_t g_monitor[64];
static size_t   g_n_monitor;
static int      g_beeps;

static void cb_select(void *u, uint32_t tg, int gate) {
    (void)u; g_selected = tg; g_gate = gate;
}
static void cb_monitor(void *u, const uint32_t *ids, size_t n) {
    (void)u;
    g_n_monitor = n > 64 ? 64 : n;
    memcpy(g_monitor, ids, g_n_monitor * sizeof(uint32_t));
}
static void cb_beep(void *u, int n) { (void)u; g_beeps += n; }
static void cb_changed(void *u)     { (void)u; }
static void cb_tail(void *u, int ms){ (void)u; (void)ms; }

static const tgm_callbacks CB = {
    .user = NULL, .select_tg = cb_select, .set_monitor = cb_monitor,
    .beep = cb_beep, .changed = cb_changed, .tail_trim = cb_tail,
};

#define CHECK(cond, ...) do {                                    \
    g_run++;                                                     \
    if (!(cond)) {                                               \
        g_fail++;                                                \
        printf("  FAIL  " __VA_ARGS__);                          \
        printf("\n        at %s:%d\n", __FILE__, __LINE__);      \
    }                                                            \
} while (0)

static void setup(svx_config *cfg, const char *switchable, const char *monitored) {
    config_defaults(cfg);
    snprintf(cfg->callsign, sizeof(cfg->callsign), "ON3TST");
    config_set(cfg, "switchable", switchable);
    config_set(cfg, "monitored",  monitored);
    cfg->linger_seconds = 30;
    cfg->idle_seconds   = 60;
    cfg->roger_beep     = 0;
    cfg->default_tg     = 0;
}

static void reset_spy(void) {
    g_selected = 0xFFFFFFFF; g_gate = -1; g_n_monitor = 0; g_beeps = 0;
}

/* ------------------------------------------------------------- fixtures */

static void t_priority_preempts_idle(void) {
    printf("priority: a talker on any watched TG takes an IDLE channel\n");
    svx_config cfg; setup(&cfg, "8, 1745", "8, 1745");
    tg_manager m; tgm_init(&m, &cfg, &CB);
    tgm_select(&m, 8);
    m.linger_until = 0;                    /* pretend the linger has expired */

    reset_spy();
    tgm_on_talker_start(&m, 1745, "ON4XYZ");
    CHECK(tgm_selected(&m) == 1745, "expected a move to 1745, got %u", tgm_selected(&m));
    CHECK(g_gate == 1, "a real channel change must gate the audio");
}

static void t_prio0_cannot_take_busy(void) {
    printf("priority: a priority-0 TG cannot take a BUSY channel\n");
    svx_config cfg; setup(&cfg, "8, 1745", "8, 1745");   /* both priority 0 */
    tg_manager m; tgm_init(&m, &cfg, &CB);
    tgm_select(&m, 8);
    m.linger_until = 0;

    tgm_on_talker_start(&m, 8, "ON4AAA");     /* our channel is busy */
    reset_spy();
    tgm_on_talker_start(&m, 1745, "ON4BBB");  /* another priority-0 keys up */
    CHECK(tgm_selected(&m) == 8,
          "priority 0 must not steal a busy channel, but we moved to %u", tgm_selected(&m));
}

static void t_higher_prio_takes_busy(void) {
    printf("priority: a HIGHER priority TG does take a busy channel\n");
    svx_config cfg; setup(&cfg, "8, 1745", "8, 1745+");
    tg_manager m; tgm_init(&m, &cfg, &CB);
    tgm_select(&m, 8);
    m.linger_until = 0;

    tgm_on_talker_start(&m, 8, "ON4AAA");
    reset_spy();
    tgm_on_talker_start(&m, 1745, "ON4BBB");
    CHECK(tgm_selected(&m) == 1745,
          "priority 1 should take a busy priority-0 channel, still on %u", tgm_selected(&m));
}

static void t_equal_prio_no_steal(void) {
    printf("priority: equal non-zero priorities do not steal from each other\n");
    svx_config cfg; setup(&cfg, "8, 1745", "8+, 1745+");
    tg_manager m; tgm_init(&m, &cfg, &CB);
    tgm_select(&m, 8);
    m.linger_until = 0;

    tgm_on_talker_start(&m, 8, "ON4AAA");
    reset_spy();
    tgm_on_talker_start(&m, 1745, "ON4BBB");
    CHECK(tgm_selected(&m) == 8,
          "equal priority must not preempt, moved to %u", tgm_selected(&m));
}

static void t_linger_protects_the_gap(void) {
    printf("linger: the gap between overs resists an EQUAL priority\n");
    /* Linger makes the channel count as busy. Busy means only a strictly
     * higher, non-zero priority may take it — so an equal-priority talkgroup
     * cannot grab you the moment your QSO partner unkeys, which is exactly
     * what linger is for. */
    svx_config cfg; setup(&cfg, "8, 1745", "8, 1745");   /* both priority 0 */
    tg_manager m; tgm_init(&m, &cfg, &CB);
    tgm_select(&m, 8);
    m.linger_until = 0;

    tgm_on_talker_start(&m, 8, "ON4AAA");
    tgm_on_talker_stop (&m, 8, "ON4AAA");     /* arms the linger window */
    CHECK(m.linger_until != 0, "a stop on our TG must arm the linger window");

    reset_spy();
    tgm_on_talker_start(&m, 1745, "ON4BBB");
    CHECK(tgm_selected(&m) == 8,
          "linger must hold the channel against equal priority, moved to %u",
          tgm_selected(&m));

    /* Once linger expires the channel is idle again and anyone may take it. */
    m.linger_until = 1;                        /* in the past */
    tgm_tick(&m, now_ms());
    CHECK(tgm_selected(&m) == 1745,
          "after linger expires the waiting talker should win, on %u", tgm_selected(&m));
}

static void t_linger_yields_to_higher_priority(void) {
    printf("linger: but a HIGHER priority still gets through\n");
    /* Deliberate: priority is meant to be able to interrupt. If linger blocked
     * a higher priority too, marking a talkgroup '+' would do nothing during
     * the very gaps when it matters most. */
    svx_config cfg; setup(&cfg, "8, 1745", "8, 1745+");
    tg_manager m; tgm_init(&m, &cfg, &CB);
    tgm_select(&m, 8);
    m.linger_until = 0;

    tgm_on_talker_start(&m, 8, "ON4AAA");
    tgm_on_talker_stop (&m, 8, "ON4AAA");     /* lingering */

    tgm_on_talker_start(&m, 1745, "ON4BBB");  /* priority 1 */
    CHECK(tgm_selected(&m) == 1745,
          "a higher priority must still preempt during linger, still on %u",
          tgm_selected(&m));
}

static void t_lock_blocks_everything(void) {
    printf("lock: nothing moves a locked talkgroup, and monitoring is emptied\n");
    svx_config cfg; setup(&cfg, "8, 1745", "8, 1745++");
    tg_manager m; tgm_init(&m, &cfg, &CB);
    tgm_select(&m, 8);
    m.linger_until = 0;

    reset_spy();
    tgm_set_lock(&m, 1);
    CHECK(g_n_monitor == 0,
          "a locked TG must send an EMPTY monitor set, got %zu entries", g_n_monitor);

    tgm_on_talker_start(&m, 1745, "ON4BBB");   /* priority 2, would normally win */
    CHECK(tgm_selected(&m) == 8,
          "lock must block preemption, moved to %u", tgm_selected(&m));

    /* Unlocking re-evaluates at once — that is the point of unlocking. */
    tgm_set_lock(&m, 0);
    CHECK(tgm_selected(&m) == 1745,
          "unlocking should hand over immediately, on %u", tgm_selected(&m));
    CHECK(g_n_monitor > 0, "unlocking must restore the monitor set");
}

static void t_stop_matches_callsign_only(void) {
    printf("talkers: STOP is matched on callsign, not on talkgroup\n");
    svx_config cfg; setup(&cfg, "8, 1745", "8, 1745");
    tg_manager m; tgm_init(&m, &cfg, &CB);

    tgm_on_talker_start(&m, 8, "ON4AAA");
    CHECK(tgm_talker_on(&m, 8) != NULL, "the talker should be recorded on TG 8");

    /* The server reports the stop on a DIFFERENT talkgroup, which it does. */
    tgm_on_talker_stop(&m, 1745, "ON4AAA");
    CHECK(tgm_talker_on(&m, 8) == NULL,
          "a stop on the wrong TG must still clear the talker (ghost talker bug)");
}

static void t_ssid_is_stripped(void) {
    printf("talkers: an SSID suffix does not create a second talker\n");
    svx_config cfg; setup(&cfg, "8", "8");
    tg_manager m; tgm_init(&m, &cfg, &CB);

    tgm_on_talker_start(&m, 8, "ON4AAA-7");
    tgm_on_talker_stop (&m, 8, "ON4AAA");
    CHECK(tgm_talker_on(&m, 8) == NULL, "ON4AAA-7 and ON4AAA are the same station");
}

static void t_tiebreak_is_deterministic(void) {
    printf("priority: ties break by earliest start, then lowest id\n");
    svx_config cfg; setup(&cfg, "8, 1745, 9990", "8+, 1745+, 9990+");
    tg_manager m; tgm_init(&m, &cfg, &CB);
    m.selected = 0;                            /* monitor-only, nothing busy */

    /* Same priority; 9990 keys up first, so it should win despite 1745 being
     * the lower id. The Swift original resolves this by hash order. */
    tgm_on_talker_start(&m, 9990, "ON4CCC");
    for (int i = 0; i < m.n_active; i++)
        if (m.active[i].tg == 9990) m.active[i].start_ms -= 5000;
    tgm_on_talker_start(&m, 1745, "ON4BBB");
    CHECK(tgm_selected(&m) == 9990,
          "the earlier talker should win the tie, on %u", tgm_selected(&m));
}

static void t_mute_removes_from_monitor(void) {
    printf("mute: a muted TG leaves the monitor set and cannot preempt\n");
    svx_config cfg; setup(&cfg, "8, 1745", "8, 1745++");
    tg_manager m; tgm_init(&m, &cfg, &CB);
    tgm_select(&m, 8);
    m.linger_until = 0;

    reset_spy();
    tgm_toggle_mute(&m, 1745);
    CHECK(tgm_is_muted(&m, 1745), "1745 should be muted");
    for (size_t i = 0; i < g_n_monitor; i++)
        CHECK(g_monitor[i] != 1745, "a muted TG must not be in the monitor set");

    tgm_on_talker_start(&m, 1745, "ON4BBB");
    CHECK(tgm_selected(&m) == 8,
          "a muted TG must not preempt, moved to %u", tgm_selected(&m));
}

static void t_idle_drops_to_monitor_only(void) {
    printf("idle: silence everywhere falls back to monitor-only\n");
    svx_config cfg; setup(&cfg, "8", "8");
    cfg.idle_seconds = 1;
    tg_manager m; tgm_init(&m, &cfg, &CB);
    tgm_select(&m, 8);
    m.linger_until = 0;

    reset_spy();
    m.last_traffic = now_ms() - 5000;          /* 5 s of silence */
    tgm_tick(&m, now_ms());
    CHECK(tgm_selected(&m) == 0,
          "should have dropped to monitor-only, still on %u", tgm_selected(&m));
}

static void t_monitor_always_follows_select(void) {
    printf("protocol: every select is followed by a monitor set\n");
    svx_config cfg; setup(&cfg, "8, 1745", "8, 1745");
    tg_manager m; tgm_init(&m, &cfg, &CB);

    /* Selecting resets the server's monitor list, so a select that is not
     * followed by a monitor silently stops all other talkgroups arriving. */
    reset_spy();
    tgm_select(&m, 1745);
    CHECK(g_selected == 1745, "select should have been emitted");
    CHECK(g_n_monitor > 0, "a monitor set MUST follow every select");
}

static void t_arrows_wrap(void) {
    printf("keys: left and right wrap around the switchable list\n");
    svx_config cfg; setup(&cfg, "8, 1745, 8000", "8, 1745, 8000");
    tg_manager m; tgm_init(&m, &cfg, &CB);
    tgm_select(&m, 8);

    tgm_next(&m); CHECK(tgm_selected(&m) == 1745, "next -> 1745, got %u", tgm_selected(&m));
    tgm_next(&m); CHECK(tgm_selected(&m) == 8000, "next -> 8000, got %u", tgm_selected(&m));
    tgm_next(&m); CHECK(tgm_selected(&m) == 8,    "next should wrap to 8, got %u", tgm_selected(&m));
    tgm_prev(&m); CHECK(tgm_selected(&m) == 8000, "prev should wrap to 8000, got %u", tgm_selected(&m));
}

int main(void) {
    log_set_level(LOG_ERR);      /* keep the fixtures quiet */

    printf("\ntalkgroup manager fixtures\n\n");

    t_priority_preempts_idle();
    t_prio0_cannot_take_busy();
    t_higher_prio_takes_busy();
    t_equal_prio_no_steal();
    t_linger_protects_the_gap();
    t_linger_yields_to_higher_priority();
    t_lock_blocks_everything();
    t_stop_matches_callsign_only();
    t_ssid_is_stripped();
    t_tiebreak_is_deterministic();
    t_mute_removes_from_monitor();
    t_idle_drops_to_monitor_only();
    t_monitor_always_follows_select();
    t_arrows_wrap();

    printf("\n%d checks, %d failed\n\n", g_run, g_fail);
    return g_fail ? 1 : 0;
}
