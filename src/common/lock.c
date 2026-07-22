/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "lock.h"

#include "log.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>      /* flock */

static int  g_fd = -1;
static char g_path[512];

/* Create the parent directory of `path` (mkdir -p) so open() below succeeds on
 * a fresh install where ~/.local/state/svxconnect does not exist yet. */
static void mkparent(const char *path) {
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir) { *slash = '\0'; mkdir_p(dir, 0755); }
}

int svx_lock_acquire(const char *lock_path, const char *kind) {
    if (!lock_path || !*lock_path) return -2;
    mkparent(lock_path);

    int fd = open(lock_path, O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        log_warn("lock: cannot open %s: %s", lock_path, strerror(errno));
        return -2;
    }

    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        /* Held by someone else — the common, expected case. */
        int held = (errno == EWOULDBLOCK);
        close(fd);
        return held ? -1 : -2;
    }

    /* We own it. Rewrite our identity so a later refused starter can name us.
     * The flock is what actually excludes others; this text is only for the
     * diagnostic. */
    if (ftruncate(fd, 0) != 0) { /* not fatal — the flock still holds */ }
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "pid=%ld kind=%s\n",
                     (long)getpid(), kind ? kind : "?");
    if (n > 0) { ssize_t w = write(fd, buf, (size_t)n); (void)w; }

    g_fd = fd;
    snprintf(g_path, sizeof(g_path), "%s", lock_path);
    return 0;
}

int svx_lock_who(const char *lock_path, char *kind_out, size_t kind_cap, long *pid_out) {
    if (kind_out && kind_cap) kind_out[0] = '\0';
    if (pid_out) *pid_out = 0;
    if (!lock_path || !*lock_path) return -1;

    FILE *f = fopen(lock_path, "r");
    if (!f) return -1;
    char line[128] = {0};
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    fclose(f);

    long pid = 0;
    char kind[32] = {0};
    /* "pid=<n> kind=<name>" — tolerant of either order/spacing. */
    char *p = strstr(line, "pid=");
    if (p) pid = strtol(p + 4, NULL, 10);
    char *k = strstr(line, "kind=");
    if (k) sscanf(k + 5, "%31s", kind);

    if (pid_out) *pid_out = pid;
    if (kind_out && kind_cap && kind[0]) snprintf(kind_out, kind_cap, "%s", kind);
    return (pid || kind[0]) ? 0 : -1;
}

void svx_lock_release(void) {
    if (g_fd < 0) return;
    /* Closing the fd drops the flock. Do NOT unlink: between an unlink and the
     * next process's open() a fresh inode could be created and locked, so
     * unlinking a lock file is a classic race. Leaving the (now unlocked) file
     * in place is harmless — the next acquirer truncates and rewrites it. */
    flock(g_fd, LOCK_UN);
    close(g_fd);
    g_fd = -1;
    g_path[0] = '\0';
}
