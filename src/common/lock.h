/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * Single-owner run lock.
 *
 * Exactly one process may hold the reflector connection at a time — the same
 * client certificate and node id cannot be used twice at once. The ncurses TUI,
 * `--headless`, and the GTK desktop GUI (SVXConnect-PIOS, which links this core)
 * all take this advisory lock before connecting; whoever gets it owns the
 * connection and the others must refuse to start and say who is in the way.
 *
 * The wf-panel-pi widget is a controller/monitor, not an owner, and never takes
 * this lock.
 *
 * The lock is an flock() on <lock_file>, held for the life of the process via an
 * open fd — so it is released automatically on exit or crash. While held, the
 * file contains "pid=<n> kind=<name>\n" so a refused starter can name the holder.
 */
#ifndef SVX_LOCK_H
#define SVX_LOCK_H

#include <stddef.h>

/* Try to take the lock at `lock_path` (its parent directory is created if
 * needed) and record `kind` ("cli" | "headless" | "gui") in it.
 *   0   acquired — an fd is kept open until svx_lock_release() or exit
 *  -1   another process holds it (use svx_lock_who to report the holder)
 *  -2   a real error (could not create/open the file) */
int  svx_lock_acquire(const char *lock_path, const char *kind);

/* Read the current holder into kind_out / *pid_out. Best-effort: returns 0 if
 * anything was read, -1 otherwise. Meant to be called only after acquire failed,
 * when a live holder has certainly written its identity. */
int  svx_lock_who(const char *lock_path, char *kind_out, size_t kind_cap, long *pid_out);

/* Release the lock if this process holds it. Idempotent. Does not unlink the
 * file (that would race a concurrent acquirer); closing the fd drops the flock. */
void svx_lock_release(void);

#endif
