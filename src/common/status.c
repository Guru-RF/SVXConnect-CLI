/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "status.h"

#include "util.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Fields that are printed verbatim (callsign, reflector) are already validated
 * config strings — no spaces, no newlines — so no escaping is needed to keep
 * the one-line key=value shape intact. */
int svx_status_format(char *dst, size_t cap, const svx_status *s) {
    return snprintf(dst, cap,
        "owner=%s pid=%ld conn=%s tx=%d tg=%u locked=%d call=%s reflector=%s\n",
        s->owner     ? s->owner     : "?",
        s->pid,
        s->conn      ? s->conn      : "?",
        s->tx ? 1 : 0,
        s->tg,
        s->locked ? 1 : 0,
        s->callsign  ? s->callsign  : "",
        s->reflector ? s->reflector : "");
}

static void mkparent(const char *path) {
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir) { *slash = '\0'; mkdir_p(dir, 0755); }
}

int svx_status_write(const char *status_path, const svx_status *s) {
    if (!status_path || !*status_path) return -1;
    char line[256];
    int n = svx_status_format(line, sizeof(line), s);
    if (n < 0) return -1;
    if (n > (int)sizeof(line)) n = (int)sizeof(line);   /* was truncated */
    mkparent(status_path);
    return write_file_atomic(status_path, line, (size_t)n, 0644);
}

void svx_status_clear(const char *status_path) {
    if (status_path && *status_path) unlink(status_path);
}
