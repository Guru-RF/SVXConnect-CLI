/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * The ncurses front end.
 *
 * It owns the terminal for as long as it runs — initscr() on the way in,
 * endwin() on every way out, including the error paths — and it owns the main
 * loop, which is poll()-driven so that the reflector sockets, the control FIFO
 * and the keyboard all wake it. It contains no logic of its own: every key
 * turns into exactly one app_*() call, and everything drawn is read back out
 * of app.h. See ui.c for why the loop is built the way it is.
 */
#ifndef SVX_UI_H
#define SVX_UI_H

#include "app.h"

/* Run the interface until the user quits or the application asks to stop.
 * Returns a process exit code. */
int ui_run(svx_app *app);

#endif
