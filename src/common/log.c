/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "log.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>

/* Atomic: the connect worker reads it on every log call. */
static atomic_int   g_level = LOG_INFO;
static FILE        *g_file;
static int          g_file_fd = -1;
static log_sink_fn  g_sink;
static void        *g_sink_user;

/* The connect worker logs from its own thread while the main thread logs too,
 * and a sink (the app's log ring, an embedding GUI's) is rarely safe to enter
 * from two threads at once. One lock around the sink call serialises them,
 * and because log_set_sink() takes it as well, a caller that swaps the sink
 * out knows no thread is still inside the old one when it returns — so the
 * owner of that sink can free it. Recursive, in case a sink itself logs. */
static pthread_mutex_t g_lock;
static pthread_once_t  g_lock_once = PTHREAD_ONCE_INIT;

static void lock_init(void) {
    pthread_mutexattr_t at;
    pthread_mutexattr_init(&at);
    pthread_mutexattr_settype(&at, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g_lock, &at);
    pthread_mutexattr_destroy(&at);
}

static void log_lock(void)   { pthread_once(&g_lock_once, lock_init); pthread_mutex_lock(&g_lock); }
static void log_unlock(void) { pthread_mutex_unlock(&g_lock); }

static const char *const LEVEL_NAME[] = { "err ", "warn", "info", "dbg " };

void log_set_level(int level) { g_level = CLAMP(level, LOG_ERR, LOG_DBG); }
int  log_get_level(void)      { return g_level; }

const char *log_level_name(int level) {
    if (level < LOG_ERR || level > LOG_DBG) return "?";
    return LEVEL_NAME[level];
}

int log_level_from_name(const char *name) {
    if (!name) return -1;
    if (str_ieq(name, "err")   || str_ieq(name, "error")) return LOG_ERR;
    if (str_ieq(name, "warn")  || str_ieq(name, "warning")) return LOG_WARN;
    if (str_ieq(name, "info")) return LOG_INFO;
    if (str_ieq(name, "dbg")   || str_ieq(name, "debug")) return LOG_DBG;
    return -1;
}

void log_set_verbose(int v) { g_level = v ? LOG_DBG : LOG_INFO; }
int  log_is_verbose(void)   { return g_level >= LOG_DBG; }

int log_open_file(const char *path) {
    if (!path || !*path) return -1;

    /* Make sure the directory exists — the default lives under
     * ~/.local/state/svxconnect/ which will not exist on a fresh machine. */
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir) { *slash = '\0'; mkdir_p(dir, 0755); }

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return -1;

    FILE *f = fdopen(fd, "a");
    if (!f) { close(fd); return -1; }
    setvbuf(f, NULL, _IOLBF, 0);   /* line buffered: a crash keeps the tail */

    log_lock();
    if (g_file) fclose(g_file);
    g_file    = f;
    g_file_fd = fd;
    log_unlock();
    return fd;
}

void log_close_file(void) {
    log_lock();
    if (g_file) { fclose(g_file); g_file = NULL; g_file_fd = -1; }
    log_unlock();
}

void log_set_sink(log_sink_fn fn, void *user) {
    log_lock();
    g_sink      = fn;
    g_sink_user = user;
    log_unlock();
}

static void emit(int level, const char *fmt, va_list ap) {
    if (level > g_level) return;

    char body[1024];
    vsnprintf(body, sizeof(body), fmt, ap);

    char ts[32];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%H:%M:%S", &tm);

    log_lock();
    if (g_sink) {
        g_sink(level, body, g_sink_user);
    } else {
        FILE *out = g_file ? g_file : stderr;
        fprintf(out, "%s [%s] %s\n", ts, log_level_name(level), body);
        if (!g_file) fflush(out);
    }
    log_unlock();
}

#define LOG_FN(name, lvl)                        \
    void name(const char *fmt, ...) {            \
        va_list ap; va_start(ap, fmt);           \
        emit((lvl), fmt, ap);                    \
        va_end(ap);                              \
    }

LOG_FN(log_err,  LOG_ERR)
LOG_FN(log_warn, LOG_WARN)
LOG_FN(log_info, LOG_INFO)
LOG_FN(log_dbg,  LOG_DBG)
