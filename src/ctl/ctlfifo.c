/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "ctlfifo.h"

#include "common/log.h"
#include "common/net.h"
#include "common/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

int ctl_fd(const ctl_fifo *c) { return c ? c->fd : -1; }

int ctl_open(ctl_fifo *c, const char *path, const ctl_callbacks *cb) {
    memset(c, 0, sizeof(*c));
    c->fd = -1;
    c->cb = *cb;

    if (!path || !*path) return 0;      /* explicitly disabled */

    snprintf(c->path, sizeof(c->path), "%s", path);

    /* The directory may not exist on a fresh installation. */
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", c->path);
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir) { *slash = '\0'; mkdir_p(dir, 0755); }

    struct stat st;
    if (lstat(c->path, &st) == 0) {
        if (!S_ISFIFO(st.st_mode)) {
            log_warn("ctl: %s exists and is not a FIFO — external control disabled",
                     c->path);
            c->path[0] = '\0';
            return 0;
        }
    } else {
        if (mkfifo(c->path, 0600) != 0) {
            log_warn("ctl: cannot create %s: %s — external control disabled",
                     c->path, strerror(errno));
            c->path[0] = '\0';
            return 0;
        }
        c->created = 1;
    }

    /* O_RDWR, not O_RDONLY.
     *
     * A read-only FIFO reports EOF the moment the last writer closes, and
     * poll() then returns POLLIN forever with nothing to read — a busy loop
     * that pins a core. Holding a writer open ourselves means the pipe never
     * reaches EOF and poll() stays quiet between commands.
     *
     * O_NOFOLLOW: a symlink planted at the path is refused rather than
     * followed to somebody else's FIFO. */
    c->fd = open(c->path, O_RDWR | O_NONBLOCK | O_NOFOLLOW);
    if (c->fd < 0) {
        log_warn("ctl: cannot open %s: %s — external control disabled",
                 c->path, strerror(errno));
        c->path[0] = '\0';
        c->created = 0;
        return 0;
    }

    /* Whoever can write this FIFO can key the transmitter. A FIFO we did not
     * create — at a configured shared path such as /tmp, say — may belong to
     * another user or be open to everyone, so check what we actually opened:
     * it must be ours, and nobody else may read or write it. */
    if (fstat(c->fd, &st) != 0 || !S_ISFIFO(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 077) != 0) {
        log_warn("ctl: %s is not a private FIFO owned by you (mode %03o) — "
                 "external control disabled; remove it or chmod 600 it",
                 c->path, (unsigned)(st.st_mode & 0777));
        close(c->fd);
        c->fd = -1;
        c->path[0] = '\0';
        c->created = 0;
        return 0;
    }

    log_info("external control: %s", c->path);
    return 0;
}

void ctl_close(ctl_fifo *c) {
    if (!c) return;
    if (c->fd >= 0) { close(c->fd); c->fd = -1; }
    if (c->created && c->path[0]) unlink(c->path);
    c->path[0] = '\0';
    c->created = 0;
}

/* ------------------------------------------------------------ parsing */

static ctl_tristate parse_tristate(const char *arg) {
    if (!arg || !*arg)             return CTL_TOGGLE;
    if (str_ieq(arg, "on")   || str_ieq(arg, "1") ||
        str_ieq(arg, "yes")  || str_ieq(arg, "true"))  return CTL_ON;
    if (str_ieq(arg, "off")  || str_ieq(arg, "0") ||
        str_ieq(arg, "no")   || str_ieq(arg, "false")) return CTL_OFF;
    return CTL_TOGGLE;
}

static void dispatch(ctl_fifo *c, char *line) {
    char *s = str_trim(line);
    if (*s == '\0' || *s == '#') return;

    /* Split into a verb and the rest. */
    char *verb = s;
    char *arg  = s;
    while (*arg && *arg != ' ' && *arg != '\t') arg++;
    if (*arg) { *arg++ = '\0'; arg = str_trim(arg); }

    log_dbg("ctl: %s %s", verb, arg);

    if (str_ieq(verb, "ptt")) {
        if (c->cb.on_ptt) c->cb.on_ptt(c->cb.user, parse_tristate(arg));

    } else if (str_ieq(verb, "tg")) {
        if (!c->cb.on_tg) return;
        if      (str_ieq(arg, "next")) c->cb.on_tg(c->cb.user, CTL_TG_NEXT, 0);
        else if (str_ieq(arg, "prev")) c->cb.on_tg(c->cb.user, CTL_TG_PREV, 0);
        else {
            char *end = NULL;
            unsigned long v = strtoul(arg, &end, 10);
            if (end != arg) c->cb.on_tg(c->cb.user, CTL_TG_ABS, (uint32_t)v);
            else log_warn("ctl: 'tg %s' is not a number", arg);
        }

    } else if (str_ieq(verb, "lock")) {
        if (c->cb.on_lock) c->cb.on_lock(c->cb.user, parse_tristate(arg));

    } else if (str_ieq(verb, "mute") || str_ieq(verb, "unmute")) {
        if (!c->cb.on_mute) return;
        char *end = NULL;
        unsigned long v = strtoul(arg, &end, 10);
        if (end != arg) c->cb.on_mute(c->cb.user, (uint32_t)v, str_ieq(verb, "mute"));
        else log_warn("ctl: '%s %s' is not a number", verb, arg);

    } else if (str_ieq(verb, "volume") || str_ieq(verb, "vol")) {
        if (!c->cb.on_volume) return;
        char *end = NULL;
        long v = strtol(arg, &end, 10);
        if (end != arg) c->cb.on_volume(c->cb.user, (int)CLAMP(v, 0, 200));
        else log_warn("ctl: 'volume %s' is not a number", arg);

    } else if (str_ieq(verb, "status")) {
        if (c->cb.on_status) c->cb.on_status(c->cb.user);

    } else if (str_ieq(verb, "quit") || str_ieq(verb, "exit")) {
        if (c->cb.on_quit) c->cb.on_quit(c->cb.user);

    } else {
        log_warn("ctl: unknown command '%s'", verb);
    }
}

void ctl_drain(ctl_fifo *c) {
    if (!c || c->fd < 0) return;

    for (;;) {
        if (c->len >= sizeof(c->buf) - 1) {
            /* A writer sent an absurdly long line with no newline. Discard it
             * rather than grow without bound. */
            log_warn("ctl: over-long command discarded");
            c->len = 0;
        }

        ssize_t n = read(c->fd, c->buf + c->len, sizeof(c->buf) - 1 - c->len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return;                       /* EAGAIN: nothing more for now */
        }
        if (n == 0) return;               /* cannot happen while we hold O_RDWR */

        c->len += (size_t)n;
        c->buf[c->len] = '\0';

        /* Consume every complete line in the buffer. */
        for (;;) {
            char *nl = memchr(c->buf, '\n', c->len);
            if (!nl) break;
            *nl = '\0';
            dispatch(c, c->buf);

            size_t consumed = (size_t)(nl - c->buf) + 1;
            memmove(c->buf, c->buf + consumed, c->len - consumed);
            c->len -= consumed;
            c->buf[c->len] = '\0';
        }
    }
}
