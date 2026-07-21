/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — Copyright (C) 2026 Joeri Van Dooren
 *
 * The control FIFO — a named pipe carrying one command per line.
 *
 * This is how real push-to-talk hardware works with SVXConnect. A terminal
 * cannot see a key being released (see docs/PTT.md), so the keyboard gives you
 * a toggle; anything that genuinely knows about press and release — a foot
 * switch on a GPIO pin, a window-manager hotkey bound to both edges, another
 * program — drives PTT through here instead:
 *
 *     echo "ptt on"  > ~/.local/state/svxconnect/ctl
 *     echo "ptt off" > ~/.local/state/svxconnect/ctl
 *
 * It also makes the whole client scriptable, and it is what let transmit be
 * tested before the interface existed.
 *
 * Vocabulary:
 *     ptt on | ptt off | ptt toggle
 *     tg <n> | tg next | tg prev
 *     lock on | lock off | lock toggle
 *     mute <n> | unmute <n>
 *     volume <0-100>
 *     status
 *     quit
 */
#ifndef SVX_CTLFIFO_H
#define SVX_CTLFIFO_H

#include <stdint.h>
#include <stddef.h>

typedef enum { CTL_OFF = 0, CTL_ON = 1, CTL_TOGGLE = 2 } ctl_tristate;
typedef enum { CTL_TG_ABS = 0, CTL_TG_NEXT, CTL_TG_PREV } ctl_tg_kind;

typedef struct {
    void *user;
    void (*on_ptt)   (void *u, ctl_tristate v);
    void (*on_tg)    (void *u, ctl_tg_kind kind, uint32_t tg);
    void (*on_lock)  (void *u, ctl_tristate v);
    void (*on_mute)  (void *u, uint32_t tg, int mute);
    void (*on_volume)(void *u, int pct);
    void (*on_status)(void *u);
    void (*on_quit)  (void *u);
} ctl_callbacks;

typedef struct {
    int           fd;
    char          path[512];
    int           created;        /* we made the fifo, so we remove it */
    char          buf[512];
    size_t        len;
    ctl_callbacks cb;
} ctl_fifo;

/* Create (if needed) and open the FIFO. An empty path disables it, which is
 * not an error. Returns 0 on success or when disabled. */
int  ctl_open(ctl_fifo *c, const char *path, const ctl_callbacks *cb);

/* The descriptor to poll, or -1 when disabled. */
int  ctl_fd(const ctl_fifo *c);

/* Read and dispatch whatever is pending. Never blocks. */
void ctl_drain(ctl_fifo *c);

void ctl_close(ctl_fifo *c);

#endif
