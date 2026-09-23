/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * The talkgroup manager: which talkgroup you are on, and when that changes
 * by itself.
 *
 * Three ideas interact here, and it is worth being precise about them because
 * the interaction is the whole point:
 *
 *   PRIORITY   Each talkgroup has a priority from its config suffix — 8 is 0,
 *              8+ is 1, 8++ is 2. When someone keys up on a talkgroup with a
 *              higher priority than the one you are on, you are moved to it.
 *              Priority 0 never takes a busy channel away from you, even from
 *              another priority-0 talkgroup.
 *
 *   LINGER     After an over ends on your talkgroup, it is protected for
 *              linger_seconds. This is what stops a busy high-priority
 *              talkgroup from yanking you away in the gap between two overs
 *              of the QSO you are actually having.
 *
 *   LOCK       You pressed the up arrow. Nothing moves you at all, and the
 *              monitor set is emptied so no other talkgroup is even audible.
 *
 * The algorithm is ported from the macOS app's TalkGroupManager, with three
 * deliberate corrections noted at their implementations.
 */
#ifndef SVX_TGMANAGER_H
#define SVX_TGMANAGER_H

#include <stdint.h>
#include <stddef.h>

#include "common/config.h"

#define TGM_MAX_ACTIVE 32
#define TGM_MAX_RECENT 16

/* Two spellings of the callsign, and the distinction matters.
 *
 * `call` is the SSID-stripped base — ON6URE-TPAD becomes ON6URE — and it is
 * what MATCHING uses: the reflector may report a stop with a different SSID
 * than the start, and roger-beep self-suppression has to recognise your own
 * transmission coming back regardless of which of your nodes sent it.
 *
 * `full` is exactly what arrived on the wire, and it is what a user interface
 * must SHOW. Stripping it for display loses real information: ON6URE-TPAD and
 * ON6URE-PI are different stations belonging to the same operator, and a list
 * that renders both as "ON6URE" cannot tell you which one is talking. */
typedef struct {
    uint32_t tg;
    char     call[32];       /* SSID stripped — for matching only */
    char     full[32];       /* as received — for display         */
    uint64_t start_ms;
} tgm_talker;

typedef struct {
    uint32_t tg;
    char     call[32];       /* SSID stripped — for matching only */
    char     full[32];       /* as received — for display         */
    uint64_t stop_ms;
    uint32_t duration_s;
} tgm_recent;

typedef struct {
    void *user;

    /* Emit MsgSelectTG followed by MsgTgMonitor. `gate` means this is a real
     * change of channel, so the caller should also drop whatever audio is
     * buffered — it belongs to the talkgroup being left. */
    void (*select_tg)(void *u, uint32_t tg, int gate);
    void (*set_monitor)(void *u, const uint32_t *ids, size_t n);

    /* 1 = roger, 2 = channel busy, 3 = no link or no talkgroup. */
    void (*beep)(void *u, int count);

    /* Something a UI would want to redraw for. */
    void (*changed)(void *u);

    /* An over just ended on the selected talkgroup; trim the squelch tail. */
    void (*tail_trim)(void *u, int ms);
} tgm_callbacks;

typedef struct {
    const svx_config *cfg;
    tgm_callbacks     cb;

    uint32_t   selected;                 /* 0 = monitor only */
    int        locked;
    uint32_t   muted[SVX_MAX_TG];
    int        n_muted;

    uint64_t   linger_until;
    uint64_t   last_traffic;
    uint32_t   preempted_from;           /* 0 when the last change was manual */
    uint64_t   preempt_banner_until;

    tgm_talker active[TGM_MAX_ACTIVE];   /* kept sorted by tg, see fix (1) */
    int        n_active;

    tgm_recent recent[TGM_MAX_RECENT];   /* newest first */
    int        n_recent;

    uint64_t   last_heard[SVX_MAX_TG];   /* indexed alongside the watched list */
} tg_manager;

void tgm_init(tg_manager *m, const svx_config *cfg, const tgm_callbacks *cb);

/* Re-assert our talkgroup state after (re)connecting. */
void tgm_after_connect(tg_manager *m);

/* Reflector events. */
void tgm_on_talker_start(tg_manager *m, uint32_t tg, const char *call);
void tgm_on_talker_stop (tg_manager *m, uint32_t tg, const char *call);

/* We are transmitting: that counts as traffic for the idle drop, whether or not
 * the reflector has echoed our talker start. */
void tgm_note_local_tx(tg_manager *m, uint64_t now);

/* Once a second or so: expires linger, drops to monitor-only when idle, and
 * prunes talkers the server never told us had stopped. */
void tgm_tick(tg_manager *m, uint64_t now);

/* User actions. */
void tgm_select(tg_manager *m, uint32_t tg);   /* manual; arms the linger window */
void tgm_next(tg_manager *m);
void tgm_prev(tg_manager *m);
void tgm_select_index(tg_manager *m, int idx); /* the 1..9 keys */
void tgm_toggle_lock(tg_manager *m);
void tgm_set_lock(tg_manager *m, int locked);
void tgm_toggle_mute(tg_manager *m, uint32_t tg);
int  tgm_is_muted(const tg_manager *m, uint32_t tg);

/* Queries for the interface. */
uint32_t          tgm_selected(const tg_manager *m);
int               tgm_locked(const tg_manager *m);
int               tgm_priority(const tg_manager *m, uint32_t tg);
const tgm_talker *tgm_talker_on(const tg_manager *m, uint32_t tg);
uint64_t          tgm_last_heard(const tg_manager *m, uint32_t tg);
/* Non-zero while the "moved from TG n" banner should still be shown. */
uint32_t          tgm_preempt_banner(const tg_manager *m, uint64_t now);

#endif
