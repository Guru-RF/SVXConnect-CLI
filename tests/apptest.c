/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * Application fixtures: the real app.c, keyed up against a fake audio device
 * and a stub reflector. These are the failures that once needed a restart: a
 * microphone or speaker whose stream "started" and then never ran. Real time,
 * because the watchdog is timed; about 8 s in all.
 */
#include "app.h"
#include "common/config.h"
#include "common/log.h"
#include "common/util.h"
#include "fakes.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

static int g_fail, g_run;

#define CHECK(cond, ...) do {                               \
    g_run++;                                                \
    if (!(cond)) { g_fail++; printf("  FAIL  " __VA_ARGS__);\
                   printf("\n        at %s:%d\n", __FILE__, __LINE__); } \
} while (0)

/* Every line the app logs, by level, so a test can ask "was this said". */
static char g_log[256][200];
static int  g_log_level[256];
static int  g_n_log;

static void sink(int level, const char *line, void *user) {
    (void)user;
    if (g_n_log >= 256) return;
    g_log_level[g_n_log] = level;
    snprintf(g_log[g_n_log++], sizeof(g_log[0]), "%s", line);
}

static int logged(int max_level, const char *needle) {
    for (int i = 0; i < g_n_log; i++)
        if (g_log_level[i] <= max_level && strstr(g_log[i], needle)) return 1;
    return 0;
}

static svx_config g_cfg;

static svx_app *start_app(void) {
    config_defaults(&g_cfg);
    snprintf(g_cfg.callsign, sizeof(g_cfg.callsign), "ON3TST");
    config_set(&g_cfg, "switchable", "8");
    config_set(&g_cfg, "monitored",  "8");
    g_cfg.default_tg     = 8;
    g_cfg.idle_seconds   = 0;
    g_cfg.ctl_fifo[0]    = '\0';
    g_cfg.status_file[0] = '\0';
    g_n_log = 0;
    stub_rc_set_state(RC_CONNECTED);

    svx_app *a = app_new(&g_cfg, 0);
    app_start(a);
    return a;
}

/* Run the main loop and the fake audio thread side by side for `ms`. */
static void run_for(svx_app *a, int ms) {
    uint64_t end = now_ms() + (uint64_t)ms;
    while (now_ms() < end) {
        fake_pump();
        app_service(a, now_ms());
        nanosleep(&(struct timespec){ .tv_nsec = 2 * 1000 * 1000 }, NULL);
    }
}

static void t_dead_microphone_is_reopened(void) {
    printf("TX: a microphone that starts but never delivers is reopened, and the over goes out\n");
    fake_open_dead(1, 1);                         /* the first capture device is dead */
    svx_app *a = start_app();
    int opens = fake_opens(1);

    app_ptt(a, CTL_ON);
    uint64_t sent0 = stub_rc_audio_sent();
    run_for(a, 900);

    CHECK(fake_opens(1) == opens + 1, "the input device should have been reopened once (%d)",
          fake_opens(1) - opens);
    CHECK(app_tx_active(a), "the over should carry on after the reopen");
    CHECK(stub_rc_audio_sent() > sent0 + 10, "audio should flow after the reopen, sent %llu",
          (unsigned long long)(stub_rc_audio_sent() - sent0));
    CHECK(logged(LOG_WARN, "reopening the input device"), "the reopen must be logged as a warning");
    app_ptt(a, CTL_OFF);
    app_free(a);
}

static void t_microphone_stalls_mid_over(void) {
    printf("TX: a microphone that stops in the middle of an over is reopened\n");
    svx_app *a = start_app();
    int opens = fake_opens(1);

    app_ptt(a, CTL_ON);
    run_for(a, 300);
    uint64_t before = stub_rc_audio_sent();
    CHECK(before > 5, "healthy start: frames flow (%llu)", (unsigned long long)before);

    fake_kill(fake_current(1));
    run_for(a, 1000);
    CHECK(fake_opens(1) == opens + 1, "reopened once (%d)", fake_opens(1) - opens);
    CHECK(app_tx_active(a), "still transmitting");
    CHECK(stub_rc_audio_sent() > before + 10, "audio flows again after the reopen");
    CHECK(logged(LOG_WARN, "stopped delivering audio"), "says what happened");
    app_ptt(a, CTL_OFF);
    app_free(a);
}

static void t_reopen_does_not_help(void) {
    printf("TX: when reopening does not help, stop, say so, and raise the banner\n");
    fake_open_dead(1, 2);                         /* the device and its reopen are dead */
    svx_app *a = start_app();

    app_ptt(a, CTL_ON);
    run_for(a, 1500);
    CHECK(!app_tx_active(a), "must not stay keyed transmitting nothing");
    CHECK(app_banner(a) && strstr(app_banner(a), "MIC STALLED"),
          "banner: %s", app_banner(a) ? app_banner(a) : "(none)");
    CHECK(logged(LOG_ERR, "did not help"), "an error line says the reopen did not help");
    CHECK(logged(LOG_WARN, "TX OFF"), "the 0-frame TX OFF is a warning");
    app_free(a);
}

static void t_zero_frame_over_is_not_silent(void) {
    printf("TX: an over that sent nothing is a warning in the log\n");
    fake_open_dead(1, 1);
    svx_app *a = start_app();

    app_ptt(a, CTL_ON);
    run_for(a, 300);                              /* un-key before the watchdog acts */
    app_ptt(a, CTL_OFF);
    CHECK(logged(LOG_WARN, "microphone delivered no audio"),
          "a 300 ms over with 0 frames must be reported");
    app_free(a);
}

static void t_system_stop_reopens_at_once(void) {
    printf("TX: the device saying it was stopped reopens it without waiting\n");
    svx_app *a = start_app();
    int opens = fake_opens(1);

    app_ptt(a, CTL_ON);
    run_for(a, 100);
    fake_notify(fake_current(1), SVX_DEV_STOPPED);
    run_for(a, 50);                               /* well inside the 500 ms stall limit */
    CHECK(fake_opens(1) == opens + 1, "reopened on the notification (%d)", fake_opens(1) - opens);
    CHECK(app_tx_active(a), "still transmitting");
    app_ptt(a, CTL_OFF);
    app_free(a);
}

static void t_stale_idle_event_ignored(void) {
    printf("TX: a notification left over from before the over is not acted on\n");
    svx_app *a = start_app();
    int opens = fake_opens(1);

    fake_notify(fake_current(1), SVX_DEV_STOPPED);   /* while idle */
    app_ptt(a, CTL_ON);
    run_for(a, 300);
    CHECK(fake_opens(1) == opens, "a healthy device must not be reopened (%d)",
          fake_opens(1) - opens);
    app_ptt(a, CTL_OFF);
    app_free(a);
}

static void t_dead_speaker_is_reopened(void) {
    printf("RX: an output device whose callback stops is reopened\n");
    svx_app *a = start_app();
    int opens = fake_opens(0);

    run_for(a, 200);
    fake_kill(fake_current(0));
    run_for(a, 1400);
    CHECK(fake_opens(0) == opens + 1, "the output device should be reopened (%d)",
          fake_opens(0) - opens);
    CHECK(logged(LOG_WARN, "output device stopped playing"), "and it says so");
    CHECK(!app_banner(a), "a reopen that works raises no banner");
    app_free(a);
}

static void t_dead_speaker_gives_up_with_banner(void) {
    printf("RX: an output device that stays dead raises the banner\n");
    svx_app *a = start_app();

    run_for(a, 200);
    fake_open_dead(0, 1);                         /* its reopen is dead too */
    fake_kill(fake_current(0));
    run_for(a, 2600);
    CHECK(app_banner(a) && strstr(app_banner(a), "SPEAKER STALLED"),
          "banner: %s", app_banner(a) ? app_banner(a) : "(none)");
    CHECK(logged(LOG_ERR, "reopening it did not help"), "an error line says so");
    app_free(a);
}

static void t_beep_while_idle_plays(void) {
    printf("RX: a beep while nothing is received plays now, not before the next over\n");
    svx_app *a = start_app();
    run_for(a, 50);

    stub_rc_set_state(RC_IDLE);
    app_ptt(a, CTL_ON);                           /* refused: 3 beeps */
    CHECK(fake_gate(fake_current(0)) == 1, "the output gate must open for the beep");
    run_for(a, 800);
    CHECK(app_jitter_ms(a) == 0, "the beep should have played out, %u ms still queued",
          app_jitter_ms(a));
    app_free(a);
}

int main(void) {
    log_set_level(LOG_INFO);
    log_set_sink(sink, NULL);
    printf("\napplication fixtures\n\n");

    t_dead_microphone_is_reopened();
    t_microphone_stalls_mid_over();
    t_reopen_does_not_help();
    t_zero_frame_over_is_not_silent();
    t_system_stop_reopens_at_once();
    t_stale_idle_event_ignored();
    t_dead_speaker_is_reopened();
    t_dead_speaker_gives_up_with_banner();
    t_beep_while_idle_plays();

    printf("\n%d checks, %d failed\n\n", g_run, g_fail);
    return g_fail ? 1 : 0;
}
