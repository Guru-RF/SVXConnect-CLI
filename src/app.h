/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * The application core: everything except how it is presented.
 *
 * The reflector connection, the audio in both directions, the talkgroup
 * manager, PTT and the control FIFO all live here. Two front ends drive it —
 * headless.c, which prints log lines, and ui/ui.c, which draws with ncurses —
 * and neither contains any logic of its own beyond rendering and keys.
 *
 * Everything below runs on the main thread. The only other threads in the
 * program are the audio device's realtime callbacks (which touch nothing but
 * a lock-free ring and a few atomics — see audio/dev.h) and the transient
 * connect worker inside reflector/client.c.
 */
#ifndef SVX_APP_H
#define SVX_APP_H

#include <stdint.h>
#include <stddef.h>
#include <poll.h>

#include "audio/codec.h"
#include "audio/dev.h"
#include "audio/jitter.h"
#include "common/config.h"
#include "common/ring.h"
#include "ctl/ctlfifo.h"
#include "reflector/client.h"
#include "tg/tgmanager.h"

typedef struct svx_app svx_app;

/* How many log lines the interface's log pane can scroll back through. */
#define APP_LOG_LINES 512

typedef struct {
    int  level;
    char text[240];
} app_log_line;

svx_app *app_new(const svx_config *cfg, int no_tx);
void     app_free(svx_app *a);

/* Open the audio devices and the control FIFO, then start connecting. */
void     app_start(svx_app *a);

/* poll() integration. app_service() must be called every time round the loop
 * even when poll() returned nothing, because it also drives the timers. */
int      app_poll_fds(svx_app *a, struct pollfd *p, int max);
int      app_next_timeout_ms(svx_app *a, uint64_t now);
void     app_service(svx_app *a, uint64_t now);

/* ---- actions ---- */
void     app_ptt(svx_app *a, ctl_tristate v);
void     app_tg_next(svx_app *a);
void     app_tg_prev(svx_app *a);
void     app_tg_select(svx_app *a, uint32_t tg);
void     app_tg_index(svx_app *a, int idx);      /* the 1..9 keys */
void     app_toggle_lock(svx_app *a);
void     app_toggle_mute(svx_app *a, uint32_t tg);
void     app_volume_delta(svx_app *a, int delta);
void     app_toggle_output_mute(svx_app *a);
void     app_test_tone(svx_app *a);
void     app_reconnect(svx_app *a);
void     app_toggle_connect(svx_app *a);
void     app_quit(svx_app *a);
int      app_should_quit(const svx_app *a);

/* ---- state, for rendering ---- */
const svx_config *app_config(const svx_app *a);
rc_client        *app_rc(svx_app *a);
tg_manager       *app_tgm(svx_app *a);

int          app_tx_active(const svx_app *a);
uint64_t     app_tx_elapsed_ms(const svx_app *a);
int          app_tx_available(const svx_app *a);   /* 0 when --no-tx or denied */
float        app_mic_level(const svx_app *a);
float        app_spk_level(const svx_app *a);
int          app_volume(const svx_app *a);
int          app_output_muted(const svx_app *a);
uint32_t     app_jitter_ms(const svx_app *a);
const char  *app_jitter_state(const svx_app *a);
int          app_audio_ready(const svx_app *a);

/* A banner the interface should show until dismissed; NULL when there is
 * nothing to say. app_dismiss_banner() clears it. */
const char  *app_banner(const svx_app *a);
void         app_dismiss_banner(svx_app *a);

/* Divert logging into the in-memory ring. A front end that owns the terminal
 * MUST call this before drawing, or stray log lines will corrupt the screen. */
void         app_capture_log(svx_app *a);

/* Ring of recent log lines, newest last. Returns how many were written. */
int          app_log_snapshot(const svx_app *a, app_log_line *out, int max);
uint64_t     app_log_serial(const svx_app *a);    /* bumps on every new line */

/* Called whenever something worth redrawing has changed. */
void         app_set_observer(svx_app *a, void (*fn)(void *), void *user);

#endif
