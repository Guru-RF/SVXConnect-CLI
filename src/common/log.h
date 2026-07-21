/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — Copyright (C) 2026 Joeri Van Dooren
 *
 * Logging with a swappable sink. The signatures match SvxBridge's log.h so
 * ported code needs no edits; what changed is where the bytes go.
 *
 * Under the TUI, nothing may ever reach stdout/stderr — a stray fprintf
 * shreds the ncurses screen. So the sink is redirected to a file and/or the
 * in-app log pane, and main() additionally dup2()s the log file over
 * STDERR_FILENO to catch stray writes from OpenSSL, miniaudio and ALSA.
 */
#ifndef SVX_LOG_H
#define SVX_LOG_H

#include <stdarg.h>

enum { LOG_ERR = 0, LOG_WARN = 1, LOG_INFO = 2, LOG_DBG = 3 };

/* Minimum level that is emitted. Default LOG_INFO. */
void log_set_level(int level);
int  log_get_level(void);
int  log_level_from_name(const char *name);   /* err|warn|info|debug, -1 unknown */
const char *log_level_name(int level);

/* Legacy shims kept so lifted code compiles unchanged. */
void log_set_verbose(int v);   /* v != 0 => LOG_DBG, else LOG_INFO */
int  log_is_verbose(void);

/* Open a log file and route the default sink to it. Returns the fd, or -1.
 * The caller may dup2() the returned fd onto STDERR_FILENO. */
int  log_open_file(const char *path);
void log_close_file(void);

/* Replace the sink. `line` is a complete, already-formatted line without a
 * trailing newline. Passing NULL restores the default (stderr or log file). */
typedef void (*log_sink_fn)(int level, const char *line, void *user);
void log_set_sink(log_sink_fn fn, void *user);

void log_err (const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_warn(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_info(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_dbg (const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#endif
