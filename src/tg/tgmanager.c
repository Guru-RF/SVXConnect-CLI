/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "tgmanager.h"

#include "common/log.h"
#include "common/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A talker the server never told us stopped is dropped after this long.
 * SvxLink's own transmit timeout is minutes, so anything shorter would delete
 * people who are genuinely still talking. */
#define TGM_PRUNE_MS       300000

/* How long the "moved from TG n" banner stays up. */
#define TGM_BANNER_MS        5000

/* ---------------------------------------------------------- the watched set */

static int is_watched(const tg_manager *m, uint32_t tg) {
    return config_tg_is_watched(m->cfg, tg);
}

int tgm_priority(const tg_manager *m, uint32_t tg) {
    int p = config_tg_priority(m->cfg, tg);
    return p < 0 ? 0 : p;
}

int tgm_is_muted(const tg_manager *m, uint32_t tg) {
    for (int i = 0; i < m->n_muted; i++) if (m->muted[i] == tg) return 1;
    return 0;
}

static int cmp_u32(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

/* The set to send in MsgTgMonitor.
 *
 * While locked this is EMPTY. MsgTgMonitor subscribes to audio as well as to
 * status, so a non-empty set would leak other talkgroups into your ears —
 * which is precisely what locking is supposed to prevent. The selected
 * talkgroup stays audible on its own account. */
static size_t monitor_set(const tg_manager *m, uint32_t *out, size_t cap) {
    if (m->locked) return 0;

    size_t n = 0;
    for (int i = 0; i < m->cfg->n_monitored && n < cap; i++) {
        uint32_t id = m->cfg->monitored[i].id;
        if (id == m->selected || tgm_is_muted(m, id)) continue;
        out[n++] = id;
    }
    for (int i = 0; i < m->cfg->n_switchable && n < cap; i++) {
        uint32_t id = m->cfg->switchable[i].id;
        if (id == m->selected || tgm_is_muted(m, id)) continue;
        int dup = 0;
        for (size_t j = 0; j < n; j++) if (out[j] == id) { dup = 1; break; }
        if (!dup) out[n++] = id;
    }
    if (n > 1) qsort(out, n, sizeof(uint32_t), cmp_u32);
    return n;
}

static void push_monitor(tg_manager *m) {
    uint32_t set[SVX_MAX_TG * 2];
    size_t   n = monitor_set(m, set, sizeof(set) / sizeof(set[0]));
    if (m->cb.set_monitor) m->cb.set_monitor(m->cb.user, set, n);
}

/* The ONLY place MsgSelectTG is emitted. Selecting resets the server's monitor
 * list, so the monitor set is always re-sent immediately afterwards — on every
 * path, without exception. */
static void wire_select(tg_manager *m, uint32_t tg, int gate) {
    if (m->cb.select_tg) m->cb.select_tg(m->cb.user, tg, gate);
    push_monitor(m);
    if (m->cb.changed) m->cb.changed(m->cb.user);
}

/* ------------------------------------------------------------- talkers */

static int active_find_tg(const tg_manager *m, uint32_t tg) {
    for (int i = 0; i < m->n_active; i++) if (m->active[i].tg == tg) return i;
    return -1;
}

static int active_find_call(const tg_manager *m, const char *base) {
    /* active[].call is already the stripped base, so compare it directly.
     * Re-stripping here was harmless but implied the stored value might still
     * carry an SSID, which it never does. */
    for (int i = 0; i < m->n_active; i++)
        if (strcmp(m->active[i].call, base) == 0) return i;
    return -1;
}

static void active_erase(tg_manager *m, int idx) {
    if (idx < 0 || idx >= m->n_active) return;
    memmove(&m->active[idx], &m->active[idx + 1],
            (size_t)(m->n_active - idx - 1) * sizeof(m->active[0]));
    m->n_active--;
}

/* Keep active[] sorted by talkgroup id so preemption is reproducible. */
static void active_upsert(tg_manager *m, uint32_t tg, const char *base,
                          const char *full, uint64_t now) {
    int idx = active_find_tg(m, tg);
    if (idx >= 0) {
        snprintf(m->active[idx].call, sizeof(m->active[idx].call), "%s", base);
        snprintf(m->active[idx].full, sizeof(m->active[idx].full), "%s", full);
        return;                      /* keep the ORIGINAL start time */
    }
    if (m->n_active >= TGM_MAX_ACTIVE) return;

    int pos = 0;
    while (pos < m->n_active && m->active[pos].tg < tg) pos++;
    memmove(&m->active[pos + 1], &m->active[pos],
            (size_t)(m->n_active - pos) * sizeof(m->active[0]));
    m->active[pos].tg       = tg;
    m->active[pos].start_ms = now;
    snprintf(m->active[pos].call, sizeof(m->active[pos].call), "%s", base);
    snprintf(m->active[pos].full, sizeof(m->active[pos].full), "%s", full);
    m->n_active++;
}

static void recent_push(tg_manager *m, uint32_t tg, const char *base,
                        const char *full, uint64_t stop_ms, uint32_t dur_s) {
    if (m->n_recent < TGM_MAX_RECENT) m->n_recent++;
    memmove(&m->recent[1], &m->recent[0],
            (size_t)(m->n_recent - 1) * sizeof(m->recent[0]));
    m->recent[0].tg         = tg;
    m->recent[0].stop_ms    = stop_ms;
    m->recent[0].duration_s = dur_s;
    snprintf(m->recent[0].call, sizeof(m->recent[0].call), "%s", base);
    snprintf(m->recent[0].full, sizeof(m->recent[0].full), "%s", full);
}

static void note_heard(tg_manager *m, uint32_t tg, uint64_t now) {
    for (int i = 0; i < m->cfg->n_monitored; i++)
        if (m->cfg->monitored[i].id == tg) { m->last_heard[i] = now; return; }
    /* Switchable-only talkgroups share the tail of the array. */
    for (int i = 0; i < m->cfg->n_switchable; i++)
        if (m->cfg->switchable[i].id == tg) {
            int slot = m->cfg->n_monitored + i;
            if (slot < SVX_MAX_TG) m->last_heard[slot] = now;
            return;
        }
}

uint64_t tgm_last_heard(const tg_manager *m, uint32_t tg) {
    for (int i = 0; i < m->cfg->n_monitored; i++)
        if (m->cfg->monitored[i].id == tg) return m->last_heard[i];
    for (int i = 0; i < m->cfg->n_switchable; i++)
        if (m->cfg->switchable[i].id == tg) {
            int slot = m->cfg->n_monitored + i;
            return slot < SVX_MAX_TG ? m->last_heard[slot] : 0;
        }
    return 0;
}

const tgm_talker *tgm_talker_on(const tg_manager *m, uint32_t tg) {
    int i = active_find_tg(m, tg);
    return i >= 0 ? &m->active[i] : NULL;
}

/* -------------------------------------------------------- preemption */

static void evaluate_preemption(tg_manager *m, uint64_t now) {
    if (m->locked) return;

    int      in_linger    = m->linger_until != 0 && now < m->linger_until;
    int      current_busy = (m->selected != 0 && active_find_tg(m, m->selected) >= 0)
                            || in_linger;
    int      current_prio = m->selected ? tgm_priority(m, m->selected) : -1;

    /* Best candidate: highest priority, then earliest start, then lowest id.
     *
     * Fix (1). The Swift original scans an unordered Dictionary with a bare
     * `if p > bestPriority`, so ties resolve by hash order and the same set of
     * talkers can produce different outcomes on different runs. active[] is
     * sorted by id here and the tiebreak is explicit, so this is reproducible. */
    uint32_t best       = 0;
    int      best_prio  = -1;
    uint64_t best_start = UINT64_MAX;

    for (int i = 0; i < m->n_active; i++) {
        uint32_t tg = m->active[i].tg;
        if (!is_watched(m, tg))  continue;
        if (tgm_is_muted(m, tg)) continue;

        int      p  = tgm_priority(m, tg);
        uint64_t st = m->active[i].start_ms;

        if (p > best_prio ||
            (p == best_prio && st <  best_start) ||
            (p == best_prio && st == best_start && tg < best)) {
            best = tg; best_prio = p; best_start = st;
        }
    }

    if (best == 0 || best == m->selected) return;

    /* While the current talkgroup is busy or lingering, only a STRICTLY higher
     * priority that is itself at least 1 may take over. The `best_prio > 0`
     * clause is what stops two priority-0 talkgroups from fighting over you. */
    int should = current_busy ? (best_prio > current_prio && best_prio > 0) : 1;
    if (!should) return;

    uint32_t from = m->selected;
    m->selected             = best;
    m->preempted_from       = from;
    m->preempt_banner_until = now + TGM_BANNER_MS;
    m->linger_until         = 0;

    log_info("TG %u <- moved from TG %u (%s is talking, priority %d)",
             best, from, m->active[active_find_tg(m, best)].call, best_prio);

    wire_select(m, best, 1);
}

/* ---------------------------------------------------------------- API */

void tgm_init(tg_manager *m, const svx_config *cfg, const tgm_callbacks *cb) {
    memset(m, 0, sizeof(*m));
    m->cfg    = cfg;
    m->cb     = *cb;
    m->locked = cfg->lock_on_start;

    m->selected = (uint32_t)cfg->default_tg;
    if (m->selected == 0 && cfg->n_switchable > 0)
        m->selected = cfg->switchable[0].id;

    m->last_traffic = now_ms();
}

void tgm_after_connect(tg_manager *m) {
    m->linger_until   = 0;
    m->preempted_from = 0;
    m->n_active       = 0;
    m->last_traffic   = now_ms();
    /* No gate: there is nothing buffered to discard, and gating would swallow
     * the first moments of audio on a talkgroup that is already busy. */
    wire_select(m, m->selected, 0);
}

void tgm_on_talker_start(tg_manager *m, uint32_t tg, const char *call) {
    uint64_t now = now_ms();
    char     base[32];
    call_strip_ssid(base, sizeof(base), call);

    /* Store both: the base for matching, the wire form for display. */
    active_upsert(m, tg, base, call ? call : base, now);
    note_heard(m, tg, now);
    m->last_traffic = now;

    evaluate_preemption(m, now);
    if (m->cb.changed) m->cb.changed(m->cb.user);
}

void tgm_on_talker_stop(tg_manager *m, uint32_t tg, const char *call) {
    (void)tg;
    uint64_t now = now_ms();
    char     base[32];
    call_strip_ssid(base, sizeof(base), call);

    /* Fix (2): match on the CALLSIGN ONLY.
     *
     * The talkgroup the server reports on stop can differ from the one it
     * reported on start. Filtering on both leaves an entry in active[] that
     * nothing ever removes, so the interface shows a talker whose timer counts
     * up forever and preemption keeps treating that talkgroup as busy. */
    int idx = active_find_call(m, base);
    if (idx < 0) return;

    uint32_t was_tg   = m->active[idx].tg;
    uint64_t started  = m->active[idx].start_ms;
    uint32_t dur_s    = (uint32_t)((now - started) / 1000);
    int      was_mine = (was_tg == m->selected);

    /* Carry the START's full callsign into the history, not the stop's: the
     * two can differ in SSID (that is exactly why matching uses the base),
     * and the entry being closed is the one that opened. */
    char was_full[32];
    snprintf(was_full, sizeof(was_full), "%s", m->active[idx].full);

    active_erase(m, idx);
    recent_push(m, was_tg, base, was_full, now, dur_s);
    note_heard(m, was_tg, now);
    m->last_traffic = now;

    if (was_mine) {
        /* Protect the gap between overs so a busy higher-priority talkgroup
         * cannot interrupt the QSO you are in the middle of. */
        m->linger_until = now + (uint64_t)m->cfg->linger_seconds * 1000;

        if (m->cfg->tail_trim_ms > 0 && m->cb.tail_trim)
            m->cb.tail_trim(m->cb.user, m->cfg->tail_trim_ms);

        /* Do not beep at yourself when your own transmission comes back. */
        char mine[32];
        call_strip_ssid(mine, sizeof(mine), m->cfg->callsign);
        if (m->cfg->roger_beep && dur_s >= (uint32_t)m->cfg->roger_beep_min_sec &&
            strcmp(mine, base) != 0 && m->cb.beep) {
            m->cb.beep(m->cb.user, 1);
        }
    }

    evaluate_preemption(m, now);
    if (m->cb.changed) m->cb.changed(m->cb.user);
}

void tgm_tick(tg_manager *m, uint64_t now) {
    /* Timestamps here are set from now_ms(); guard every elapsed-time
     * subtraction against a `now` that is somehow behind one of them, so an
     * unsigned underflow can never turn "0 ms ago" into ~49 days and fire the
     * prune or the idle-drop by accident. */
    #define TGM_SINCE(ts) ((now >= (ts)) ? now - (ts) : 0)

    /* Drop talkers the server never told us had stopped. */
    for (int i = m->n_active - 1; i >= 0; i--) {
        if (TGM_SINCE(m->active[i].start_ms) > TGM_PRUNE_MS) {
            log_dbg("pruning stale talker %s on TG %u", m->active[i].call, m->active[i].tg);
            active_erase(m, i);
        }
    }

    if (m->linger_until && now >= m->linger_until) {
        m->linger_until = 0;
        evaluate_preemption(m, now);
    }

    if (m->locked || m->selected == 0 || m->n_active > 0) return;
    if (m->cfg->idle_seconds <= 0) return;
    if (TGM_SINCE(m->last_traffic) < (uint64_t)m->cfg->idle_seconds * 1000) return;

    #undef TGM_SINCE

    /* Nothing anywhere for idle_seconds: fall back to monitor-only so we are
     * not sitting on a talkgroup we are not using. */
    log_info("idle for %ds — monitoring only", m->cfg->idle_seconds);
    m->selected       = 0;
    m->preempted_from = 0;
    m->linger_until   = 0;
    wire_select(m, 0, 1);
}

void tgm_select(tg_manager *m, uint32_t tg) {
    if (tg == m->selected) return;

    /* Log every manual change, and say so loudly when it deselects entirely.
     * Dropping to monitor-only means you silently stop being on a talkgroup,
     * which looks identical to a bug if it was not deliberate — so leave a
     * trace naming this path, distinct from the idle timeout's own message. */
    if (tg == 0) log_info("deselected TG %u — monitoring only", m->selected);
    else         log_info("TG %u", tg);

    m->selected       = tg;
    m->preempted_from = 0;
    /* Arm the linger window on a manual choice too, or a busy high-priority
     * talkgroup would drag you straight back off the one you just picked. */
    m->linger_until = tg ? now_ms() + (uint64_t)m->cfg->linger_seconds * 1000 : 0;

    wire_select(m, tg, 1);
}

static void step(tg_manager *m, int dir) {
    const svx_config *cfg = m->cfg;
    if (cfg->n_switchable == 0) return;

    int idx = -1;
    for (int i = 0; i < cfg->n_switchable; i++)
        if (cfg->switchable[i].id == m->selected) { idx = i; break; }

    idx = (idx < 0) ? (dir > 0 ? 0 : cfg->n_switchable - 1)
                    : (idx + dir + cfg->n_switchable) % cfg->n_switchable;
    tgm_select(m, cfg->switchable[idx].id);
}

void tgm_next(tg_manager *m) { step(m,  1); }
void tgm_prev(tg_manager *m) { step(m, -1); }

void tgm_select_index(tg_manager *m, int idx) {
    if (idx < 0 || idx >= m->cfg->n_switchable) return;
    tgm_select(m, m->cfg->switchable[idx].id);
}

void tgm_set_lock(tg_manager *m, int locked) {
    if (m->locked == locked) return;
    m->locked         = locked;
    m->linger_until   = 0;
    m->preempted_from = 0;

    log_info("talkgroup %s", locked ? "LOCKED" : "unlocked");

    /* Re-assert with NO gate: this is not a change of channel, and gating
     * would needlessly eat the audio of whoever is talking right now. The
     * order still matters — select first, then monitor. */
    wire_select(m, m->selected, 0);

    /* Unlocking can move you immediately, which is the point of unlocking. */
    if (!locked) evaluate_preemption(m, now_ms());
}

void tgm_toggle_lock(tg_manager *m) { tgm_set_lock(m, !m->locked); }

void tgm_toggle_mute(tg_manager *m, uint32_t tg) {
    if (tg == 0) return;

    int found = -1;
    for (int i = 0; i < m->n_muted; i++) if (m->muted[i] == tg) { found = i; break; }

    if (found >= 0) {
        memmove(&m->muted[found], &m->muted[found + 1],
                (size_t)(m->n_muted - found - 1) * sizeof(uint32_t));
        m->n_muted--;
        log_info("TG %u unmuted", tg);
    } else {
        if (m->n_muted >= SVX_MAX_TG) return;
        m->muted[m->n_muted++] = tg;
        log_info("TG %u muted", tg);
    }

    if (tg == m->selected) {
        /* You cannot be sitting on a talkgroup you have muted. */
        m->selected     = 0;
        m->linger_until = 0;
        wire_select(m, 0, 1);
    } else {
        push_monitor(m);
        if (m->cb.changed) m->cb.changed(m->cb.user);
    }
}

uint32_t tgm_selected(const tg_manager *m) { return m->selected; }
int      tgm_locked  (const tg_manager *m) { return m->locked; }

uint32_t tgm_preempt_banner(const tg_manager *m, uint64_t now) {
    if (m->preempt_banner_until && now < m->preempt_banner_until)
        return m->preempted_from;
    return 0;
}
