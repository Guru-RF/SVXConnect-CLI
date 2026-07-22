/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * Status export.
 *
 * A compact snapshot of the running client, written atomically to <status_file>
 * so a companion process — the wf-panel-pi widget in SVXConnect-PIOS — can show
 * connection / talkgroup / PTT state without touching the reflector itself. This
 * is the outbound half of the same split the macOS app uses (StatusBroadcaster
 * out, URL scheme in); the inbound half here is the existing control FIFO.
 *
 * The format is one line of space-separated key=value pairs, e.g.
 *
 *     owner=gui pid=1234 conn=connected tx=0 tg=8 locked=0 call=ON6URE reflector=be.svx.link
 *
 * Any owner (TUI, headless, GUI) writes it. Liveness is the file's presence and
 * mtime: an owner refreshes it at least once a second and removes it on clean
 * exit, so a stale or missing file means "no client running".
 */
#ifndef SVX_STATUS_H
#define SVX_STATUS_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    const char *owner;      /* "cli" | "headless" | "gui"                 */
    const char *conn;       /* rc_state_name(): "connected", "idle", ...  */
    const char *callsign;
    const char *reflector;
    uint32_t    tg;         /* selected talkgroup, 0 = monitor-only       */
    int         locked;
    int         tx;         /* 1 while transmitting                       */
    long        pid;
} svx_status;

/* Format the snapshot into dst (one line, no trailing newline is added by the
 * caller — this includes the '\n'). Returns the length written. */
int  svx_status_format(char *dst, size_t cap, const svx_status *s);

/* Format and write the snapshot to `status_path` atomically (its parent
 * directory is created if needed). Returns 0 on success, -1 on error. */
int  svx_status_write(const char *status_path, const svx_status *s);

/* Remove the status file (clean shutdown, so a reader greys out at once). */
void svx_status_clear(const char *status_path);

#endif
