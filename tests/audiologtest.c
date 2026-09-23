/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * miniaudio's own log reaches ours. When a device stops delivering, the
 * callbacks just go quiet; whatever miniaudio said about it is the only trace
 * of why, and it used to go nowhere. This initialises the real audio context
 * (no device is opened, so it needs no sound card: backend probing logs
 * whether it succeeds or not) and looks for miniaudio's lines in the sink.
 */
#include "audio/dev.h"
#include "common/log.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

static int g_fail, g_run;

#define CHECK(cond, ...) do {                               \
    g_run++;                                                \
    if (!(cond)) { g_fail++; printf("  FAIL  " __VA_ARGS__);\
                   printf("\n        at %s:%d\n", __FILE__, __LINE__); } \
} while (0)

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static int  g_lines, g_newlines, g_probe, g_level_ok = 1;
static char g_first[256];

/* Called from whichever thread miniaudio posts on. */
static void sink(int level, const char *line, void *user) {
    (void)user;
    if (strncmp(line, "miniaudio ", 10) != 0) return;
    pthread_mutex_lock(&g_mu);
    if (!g_lines++) snprintf(g_first, sizeof(g_first), "%s", line);
    if (strchr(line, '\n')) g_newlines++;
    if (strstr(line, "Attempting to initialize")) g_probe++;
    if (level != LOG_DBG) g_level_ok = 0;
    pthread_mutex_unlock(&g_mu);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    log_set_sink(sink, NULL);

    printf("audio: miniaudio's log is forwarded at debug level\n");
    log_set_level(LOG_DBG);
    int rc = svx_audio_init();
    printf("        context %s, backend %s\n", rc == 0 ? "up" : "failed", svx_audio_backend_name());
    svx_audio_term();
    pthread_mutex_lock(&g_mu);
    CHECK(g_lines > 0, "no miniaudio line reached the log");
    CHECK(g_probe > 0, "backend selection inside ma_context_init was not captured");
    CHECK(g_newlines == 0, "%d line(s) kept miniaudio's trailing newline", g_newlines);
    CHECK(g_level_ok, "a miniaudio line came through above debug level");
    if (g_lines) printf("        e.g. %s\n", g_first);
    g_lines = 0;
    pthread_mutex_unlock(&g_mu);

    printf("audio: and stays out of the log when debug logging is off\n");
    log_set_level(LOG_INFO);
    svx_audio_init();
    svx_audio_term();
    pthread_mutex_lock(&g_mu);
    CHECK(g_lines == 0, "%d miniaudio line(s) at info level", g_lines);
    pthread_mutex_unlock(&g_mu);

    log_set_sink(NULL, NULL);
    printf("\n%d checks, %d failed\n", g_run, g_fail);
    return g_fail ? 1 : 0;
}
