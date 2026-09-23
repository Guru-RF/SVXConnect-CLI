/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * Local-interface fixtures: the status file and the control FIFO — the two
 * ways other programs on this machine talk to a running client.
 * Run with `make test`.
 */
#include "common/status.h"
#include "common/log.h"
#include "common/util.h"
#include "ctl/ctlfifo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static int g_fail, g_run;

#define CHECK(cond, ...) do {                               \
    g_run++;                                                \
    if (!(cond)) { g_fail++; printf("  FAIL  " __VA_ARGS__);\
                   printf("\n        at %s:%d\n", __FILE__, __LINE__); } \
} while (0)

/* Count fsync() calls. This definition wins over libc's for the whole
 * program, so it sees the ones made inside util.c too. */
static int g_fsyncs;
int fsync(int fd) { (void)fd; g_fsyncs++; return 0; }

static char g_dir[256];

static void t_status_no_fsync(void) {
    printf("status: the once-a-second status file is not fsync'd\n");
    char path[512];
    snprintf(path, sizeof(path), "%s/status", g_dir);
    svx_status s = { .owner = "cli", .conn = "connected", .callsign = "TEST",
                     .reflector = "example", .tg = 9, .pid = 1 };
    g_fsyncs = 0;
    CHECK(svx_status_write(path, &s) == 0, "write failed");
    CHECK(g_fsyncs == 0, "svx_status_write called fsync %d time(s)", g_fsyncs);

    size_t n = 0;
    char *body = read_file(path, &n);
    CHECK(body && strstr(body, "conn=connected tx=0 tg=9"), "content: '%s'", body ? body : "(none)");
    free(body);
    struct stat st;
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0644, "mode %o", (unsigned)(st.st_mode & 0777));

    g_fsyncs = 0;
    snprintf(path, sizeof(path), "%s/secret", g_dir);
    CHECK(write_file_atomic(path, "k", 1, 0600) == 0, "write_file_atomic failed");
    CHECK(g_fsyncs == 1, "write_file_atomic must still fsync (keys, certificates)");
}

static int g_ptts;
static void on_ptt(void *u, ctl_tristate v) { (void)u; (void)v; g_ptts++; }

static void t_ctl_fifo_modes(void) {
    ctl_callbacks cb = { .on_ptt = on_ptt };
    ctl_fifo c;
    char path[512];

    printf("ctl: a FIFO we create is private and works\n");
    snprintf(path, sizeof(path), "%s/ctl-new", g_dir);
    ctl_open(&c, path, &cb);
    CHECK(ctl_fd(&c) >= 0, "own FIFO refused");
    g_ptts = 0;
    FILE *w = fopen(path, "w");
    if (w) { fputs("ptt on\n", w); fclose(w); }
    ctl_drain(&c);
    CHECK(g_ptts == 1, "command not delivered");
    ctl_close(&c);

    printf("ctl: a pre-existing FIFO that others may write is refused\n");
    snprintf(path, sizeof(path), "%s/ctl-open", g_dir);
    CHECK(mkfifo(path, 0600) == 0, "mkfifo");
    chmod(path, 0666);
    ctl_open(&c, path, &cb);
    CHECK(ctl_fd(&c) < 0, "a world-writable FIFO was accepted");
    ctl_close(&c);
    CHECK(access(path, F_OK) == 0, "someone else's FIFO must not be removed");

    printf("ctl: a pre-existing private FIFO is accepted\n");
    chmod(path, 0600);
    ctl_open(&c, path, &cb);
    CHECK(ctl_fd(&c) >= 0, "a private FIFO of ours was refused");
    ctl_close(&c);

    printf("ctl: a symlink to a FIFO is refused\n");
    char link[512];
    snprintf(link, sizeof(link), "%s/ctl-link", g_dir);
    CHECK(symlink(path, link) == 0, "symlink");
    ctl_open(&c, link, &cb);
    CHECK(ctl_fd(&c) < 0, "followed a symlink");
    ctl_close(&c);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    log_set_level(LOG_ERR);
    snprintf(g_dir, sizeof(g_dir), "/tmp/svxconnect-local-XXXXXX");
    if (!mkdtemp(g_dir)) { perror("mkdtemp"); return 1; }

    t_status_no_fsync();
    t_ctl_fifo_modes();

    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) { /* a leftover temp dir is harmless */ }

    printf("\n%d checks, %d failed\n", g_run, g_fail);
    return g_fail ? 1 : 0;
}
