/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — Copyright (C) 2026 Joeri Van Dooren
 *
 * The ncurses front end.
 *
 * Three decisions shape this file and are worth stating up front, because each
 * of them is a trap that a normal curses program falls into:
 *
 *   poll() owns the timing, not curses.  The reflector sockets, the audio
 *   timers and the control FIFO all have to be serviced on schedule, so the
 *   loop blocks in poll() over app_poll_fds() plus stdin and never in getch().
 *   That is why the terminal is set nodelay() and why halfdelay() — which is
 *   how a curses program usually paces itself — must not be used: it would put
 *   the wait back inside getch(), where the sockets are invisible.
 *
 *   Resize arrives as a signal, not as a key.  Because we block in poll() and
 *   not in getch(), ncurses never gets the chance to synthesise KEY_RESIZE, so
 *   SIGWINCH is caught ourselves and turned into a flag that the loop notices.
 *   The handler does nothing but set the flag; the terminal is reinitialised on
 *   the main thread where it is safe to allocate.
 *
 *   Nothing here may write to stdout or stderr.  A single printf() would land
 *   in the middle of the screen. Diagnostics go through log_*(), which app.c
 *   has already routed into the ring we render in the log pane.
 *
 * Drawing is dirty-flag driven and double-buffered: every pane paints into
 * stdscr and a single doupdate() at the end pushes the difference, so the
 * screen never flickers and an idle client costs nothing.
 */
#include "ui.h"

#include "app.h"
#include "audio/dev.h"
#include "common/config.h"
#include "common/log.h"
#include "common/util.h"
#include "reflector/client.h"
#include "tg/tgmanager.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <ncurses.h>

/* ------------------------------------------------------------------ glyphs */

enum {
    G_HL, G_VL, G_TL, G_TR, G_BL, G_BR,
    G_TD, G_TU, G_TE_L, G_TE_R,
    G_BLOCK, G_SHADE, G_EDGE, G_DOT,
    G_LARR, G_RARR, G_UARR,
    G_N
};

/* One table, two rows, indexed by cfg->unicode. Everything else in the file
 * composes plain ASCII and drops a glyph in by column, so a terminal without
 * UTF-8 loses decoration and nothing else. */
static const char *const GLYPHS[2][G_N] = {
    { "-", "|", "+", "+", "+", "+",
      "+", "+", "+", "+",
      "#", ".", "|", "*",
      "<", ">", "^" },
    { "─", "│", "┌", "┐", "└", "┘",
      "┬", "┴", "┤", "├",
      "█", "░", "▌", "●",
      "←", "→", "↑" }
};

/* ------------------------------------------------------------------ colours */

enum { CP_OK = 1, CP_WARN, CP_BAD, CP_HEAD };

#define UI_MIN_COLS   80
#define UI_MIN_ROWS   24
#define UI_TICK_MS    66      /* ~15 Hz, the cap for the meters */
#define UI_SLOW_MS   500      /* nothing is moving: just keep the clock honest */
#define UI_QUIT_MS  2000      /* window for the second q that forces the exit */
#define UI_MAX_ROWS   64      /* talkgroup rows we are prepared to lay out */
#define UI_MAX_DEVS   32

/* ------------------------------------------------------------------ signals */

/* The only mutable state outside ui_state, because a handler may touch nothing
 * else. poll() is left interruptible on purpose (no SA_RESTART) so that a
 * signal is noticed within one pass of the loop rather than one timeout. */
static volatile sig_atomic_t g_winch;
static volatile sig_atomic_t g_intr;
static volatile sig_atomic_t g_term;

static void on_winch(int sig) { (void)sig; g_winch = 1; }
static void on_intr (int sig) { (void)sig; g_intr  = 1; }
static void on_term (int sig) { (void)sig; g_term  = 1; }

/* ------------------------------------------------------------------- state */

typedef enum { FOCUS_TG = 0, FOCUS_ACTIVE, FOCUS_RECENT, FOCUS_N } ui_focus;
typedef enum { MODAL_NONE = 0, MODAL_HELP, MODAL_DEV } ui_modal;
typedef enum { SORT_NUMERIC = 0, SORT_LASTHEARD } ui_sort;

typedef struct {
    uint32_t tg;
    int      prio;
    int      mon_only;      /* watched but not switchable: shown, never dialled */
} tg_row;

typedef struct {
    int rows, cols;
    int left_w, div_x;
    int body_top, body_bot;
    int tg_top, tg_bot;
    int meter_sep_y, mic_y, spk_y, vol_y;
    int right_x, right_w, right_top, right_bot;
    int log_sep_y, log_top;          /* -1 when the log pane is hidden */
    int sep_y, ptt_y, keys_y;
} ui_layout;

typedef struct {
    svx_app *app;

    const char *const *g;
    int      color;
    int      dirty;
    int      done;
    uint64_t last_draw;

    ui_layout lay;

    ui_focus focus;
    int      cur[FOCUS_N];
    int      shown[FOCUS_N];         /* rows actually drawn, for clamping */
    ui_sort  sort;
    int      show_log;
    ui_modal modal;

    tg_row   tg[UI_MAX_ROWS];
    int      n_tg;

    /* Log pane. The snapshot is only refetched when the serial moves, so an
     * idle client copies nothing at all. */
    app_log_line *log;
    int           n_log;
    uint64_t      log_serial;

    /* Device modal: enumerated once when it opens, display-only. */
    svx_devinfo dev_in[UI_MAX_DEVS], dev_out[UI_MAX_DEVS];
    int         n_in, n_out;
    int         dev_side;            /* 0 = input, 1 = output */
    int         dev_cur[2];
    int         dev_sel[2];          /* what the configuration resolves to */

    uint64_t quit_armed_ms;
    char     hint[96];
    uint64_t hint_until;
} ui_state;

/* --------------------------------------------------------------- utilities */

static chtype ink(const ui_state *st, int pair) {
    return st->color ? COLOR_PAIR(pair) : (chtype)0;
}

/* Columns, not bytes. Every glyph we draw is single-width, so a column is any
 * byte that is not a UTF-8 continuation byte — enough to keep a log line or a
 * device name from being cut in half and wrapping the rest of the row. */
static int disp_cols(const char *s) {
    int n = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        if ((*p & 0xC0) != 0x80) n++;
    return n;
}

static int clip_cols(const char *s, int cols) {
    const unsigned char *p = (const unsigned char *)s;
    int used = 0;

    while (*p) {
        if ((*p & 0xC0) != 0x80) {         /* the first byte of a new column */
            if (used == cols) break;
            used++;
        }
        p++;
    }
    return (int)((const char *)p - s);
}

static void put(const ui_state *st, int y, int x, int w, const char *s) {
    if (w <= 0 || y < 0 || y >= st->lay.rows || x < 0 || x >= st->lay.cols) return;
    if (x + w > st->lay.cols) w = st->lay.cols - x;
    mvaddnstr(y, x, s, clip_cols(s, w));
}

static void put_attr(const ui_state *st, int y, int x, int w, chtype a, const char *s) {
    attron(a);
    put(st, y, x, w, s);
    attroff(a);
}

static void put_glyph(const ui_state *st, int y, int x, int g) {
    if (y < 0 || y >= st->lay.rows || x < 0 || x >= st->lay.cols) return;
    mvaddstr(y, x, st->g[g]);
}

static void put_run(const ui_state *st, int y, int x0, int x1, int g) {
    for (int x = x0; x <= x1; x++) put_glyph(st, y, x, g);
}

static void put_center(const ui_state *st, int y, int x0, int w, chtype a, const char *s) {
    int x = x0 + (w - disp_cols(s)) / 2;
    if (x < x0) x = x0;
    put_attr(st, y, x, w - (x - x0), a, s);
}

static void hint(ui_state *st, const char *msg) {
    snprintf(st->hint, sizeof(st->hint), "%s", msg);
    st->hint_until = now_ms() + 2500;
    st->dirty = 1;
}

/* --------------------------------------------------------------- talkgroups */

/* The switchable list first and in config order, because that is the order the
 * 1..9 keys and app_tg_next()/app_tg_prev() walk; monitored-only talkgroups are
 * appended so their traffic is at least visible. */
static void build_tg_rows(ui_state *st) {
    const svx_config *cfg = app_config(st->app);
    st->n_tg = 0;

    for (int i = 0; i < cfg->n_switchable && st->n_tg < UI_MAX_ROWS; i++) {
        tg_row *r = &st->tg[st->n_tg++];
        r->tg = cfg->switchable[i].id;
        r->prio = cfg->switchable[i].priority;
        r->mon_only = 0;
    }
    for (int i = 0; i < cfg->n_monitored && st->n_tg < UI_MAX_ROWS; i++) {
        uint32_t id = cfg->monitored[i].id;
        int seen = 0;
        for (int j = 0; j < st->n_tg; j++) if (st->tg[j].tg == id) { seen = 1; break; }
        if (seen) continue;
        tg_row *r = &st->tg[st->n_tg++];
        r->tg = id;
        r->prio = cfg->monitored[i].priority;
        r->mon_only = 1;
    }

    if (st->sort != SORT_LASTHEARD) return;

    /* Insertion sort, most recently heard first, never heard last. Stable, so
     * config order survives inside a group of equals. */
    const tg_manager *m = app_tgm(st->app);
    for (int i = 1; i < st->n_tg; i++) {
        tg_row key = st->tg[i];
        uint64_t kh = tgm_last_heard(m, key.tg);
        int j = i - 1;
        while (j >= 0 && tgm_last_heard(m, st->tg[j].tg) < kh) {
            st->tg[j + 1] = st->tg[j];
            j--;
        }
        st->tg[j + 1] = key;
    }
}

/* The talkgroup the user is pointing at, whichever pane has focus. */
static uint32_t highlighted_tg(const ui_state *st) {
    const tg_manager *m = app_tgm(st->app);

    if (st->focus == FOCUS_ACTIVE && st->cur[FOCUS_ACTIVE] < m->n_active)
        return m->active[st->cur[FOCUS_ACTIVE]].tg;
    if (st->focus == FOCUS_RECENT && st->cur[FOCUS_RECENT] < m->n_recent)
        return m->recent[st->cur[FOCUS_RECENT]].tg;
    if (st->n_tg > 0 && st->cur[FOCUS_TG] < st->n_tg)
        return st->tg[st->cur[FOCUS_TG]].tg;
    return tgm_selected(m);
}

/* ------------------------------------------------------------------ layout */

static void compute_layout(ui_state *st) {
    ui_layout *L = &st->lay;
    getmaxyx(stdscr, L->rows, L->cols);

    if (L->rows < UI_MIN_ROWS || L->cols < UI_MIN_COLS) return;

    L->left_w = CLAMP(L->cols / 4, 16, 22);
    L->div_x  = 1 + L->left_w;

    L->keys_y  = L->rows - 2;
    L->sep_y   = L->rows - 3;
    L->ptt_y   = L->rows - 4;
    L->body_top = 3;
    L->body_bot = L->rows - 5 - 1;

    /* The meters live at the foot of the left column, under their own rule. */
    L->meter_sep_y = L->body_bot - 3;
    L->mic_y = L->body_bot - 2;
    L->spk_y = L->body_bot - 1;
    L->vol_y = L->body_bot;
    L->tg_top = L->body_top;
    L->tg_bot = L->meter_sep_y - 1;

    L->right_x   = L->div_x + 1;
    L->right_w   = L->cols - 1 - L->right_x;
    L->right_top = L->body_top;
    L->right_bot = L->body_bot;

    L->log_sep_y = L->log_top = -1;
    if (st->show_log && L->body_bot - L->body_top >= 11) {
        L->log_sep_y = L->body_bot - 8;
        L->log_top   = L->body_bot - 7;
        L->right_bot = L->log_sep_y - 1;
    }
}

/* ------------------------------------------------------------------- frame */

static void draw_frame(const ui_state *st) {
    const ui_layout *L = &st->lay;
    int right = L->cols - 1, bottom = L->rows - 1;

    /* Uprights first, rules second: every rule ends in a tee that has to win
     * over the upright it crosses. */
    for (int y = 1; y <= bottom - 1; y++) {
        put_glyph(st, y, 0, G_VL);
        put_glyph(st, y, right, G_VL);
        if (y >= L->body_top && y <= L->body_bot) put_glyph(st, y, L->div_x, G_VL);
    }

    put_run(st, 0, 1, right - 1, G_HL);
    put_glyph(st, 0, 0, G_TL);
    put_glyph(st, 0, right, G_TR);

    put_run(st, 2, 1, right - 1, G_HL);
    put_glyph(st, 2, 0, G_TE_R);
    put_glyph(st, 2, L->div_x, G_TD);
    put_glyph(st, 2, right, G_TE_L);

    put_run(st, L->meter_sep_y, 1, L->div_x - 1, G_HL);
    put_glyph(st, L->meter_sep_y, 0, G_TE_R);
    put_glyph(st, L->meter_sep_y, L->div_x, G_TE_L);

    if (L->log_sep_y > 0) {
        put_run(st, L->log_sep_y, L->right_x, right - 1, G_HL);
        put_glyph(st, L->log_sep_y, L->div_x, G_TE_R);
        put_glyph(st, L->log_sep_y, right, G_TE_L);
    }

    put_run(st, L->ptt_y - 1, 1, right - 1, G_HL);
    put_glyph(st, L->ptt_y - 1, 0, G_TE_R);
    put_glyph(st, L->ptt_y - 1, L->div_x, G_TU);
    put_glyph(st, L->ptt_y - 1, right, G_TE_L);

    put_run(st, L->sep_y, 1, right - 1, G_HL);
    put_glyph(st, L->sep_y, 0, G_TE_R);
    put_glyph(st, L->sep_y, right, G_TE_L);

    put_run(st, bottom, 1, right - 1, G_HL);
    put_glyph(st, bottom, 0, G_BL);
    put_glyph(st, bottom, right, G_BR);
}

static void draw_title(const ui_state *st) {
    const svx_config *cfg = app_config(st->app);
    rc_client *rc = app_rc(st->app);
    char buf[160];

    time_t     t  = time(NULL);
    struct tm  tmv;
    localtime_r(&t, &tmv);

    snprintf(buf, sizeof(buf), " %02d:%02d:%02d ", tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    int clock_x = st->lay.cols - 1 - (int)strlen(buf);
    put_attr(st, 0, clock_x, (int)strlen(buf), A_BOLD, buf);

    char info[160];
    snprintf(info, sizeof(info), " %s:%u  ID %u  nodes %d ",
             rc_host(rc), (unsigned)rc_port(rc),
             (unsigned)rc_client_id(rc), rc_node_count(rc));

    char title[96];
    snprintf(title, sizeof(title), " SVXConnect  %s ", cfg->callsign);

    int info_x = clock_x - 2 - (int)strlen(info);
    if (info_x > 2 + (int)strlen(title))
        put(st, 0, info_x, (int)strlen(info), info);

    put_attr(st, 0, 2, clock_x - 2, A_BOLD, title);
}

static void draw_status(const ui_state *st) {
    rc_client *rc = app_rc(st->app);
    rc_state   s  = rc_get_state(rc);
    rc_stats   sx;
    rc_get_stats(rc, &sx);

    const char *label;
    int pair;
    switch (s) {
    case RC_CONNECTED:  label = "Connected";  pair = CP_OK;   break;
    case RC_CONNECTING: label = "Connecting"; pair = CP_WARN; break;
    case RC_BACKOFF:    label = "Retrying";   pair = CP_WARN; break;
    default:            label = "Offline";    pair = CP_BAD;  break;
    }

    attron(ink(st, pair) | A_BOLD);
    put_glyph(st, 1, 2, G_DOT);
    attroff(ink(st, pair) | A_BOLD);
    put_attr(st, 1, 4, 12, ink(st, pair) | A_BOLD, label);

    int x = 18;
    int w = st->lay.cols - 1 - x;
    if (w <= 0) return;

    const char *banner = app_banner(st->app);
    if (banner && *banner) {
        char msg[240];
        snprintf(msg, sizeof(msg), "%s   (x dismisses)", banner);
        put_attr(st, 1, x, w, ink(st, CP_WARN) | A_BOLD, msg);
        return;
    }

    char buf[200];
    snprintf(buf, sizeof(buf),
             "RX %3d p/s   TX %3d p/s   loss %.1f%%   buf %ums%s%s",
             sx.rx_pps, sx.tx_pps, sx.loss_pct, (unsigned)app_jitter_ms(st->app),
             app_output_muted(st->app) ? "   SPK MUTED" : "",
             app_tx_available(st->app) ? "" : "   NO-TX");
    put(st, 1, x, w, buf);
}

/* ---------------------------------------------------------- talkgroup pane */

/* The left column is inset by one on each side; LEFT_X / LEFT_W are that inset
 * so nothing has to repeat the arithmetic. */
#define LEFT_X          2
#define LEFT_W(L)       ((L)->left_w - 2)

static void draw_tg_header(const ui_state *st, uint64_t now) {
    const tg_manager *m = app_tgm(st->app);
    int w = LEFT_W(&st->lay);
    char buf[96];

    uint32_t from = tgm_preempt_banner(m, now);
    if (from) {
        /* "TG 1745  <- 9990" rather than spelling out "from TG": two five-digit
         * talkgroup ids plus the long form overflows a 22-column pane and gets
         * truncated mid-number, which reads as a wrong id rather than a clipped
         * one. The lock indicator is displaced for the few seconds this shows;
         * that is fine, lock state has not changed. */
        snprintf(buf, sizeof(buf), "TG %u  <- %u",
                 (unsigned)tgm_selected(m), (unsigned)from);
        put_attr(st, st->lay.tg_top, LEFT_X, w, ink(st, CP_WARN) | A_BOLD, buf);
        return;
    }

    uint32_t sel = tgm_selected(m);
    if (sel) snprintf(buf, sizeof(buf), "TG %u", (unsigned)sel);
    else     snprintf(buf, sizeof(buf), "MONITOR");
    put_attr(st, st->lay.tg_top, LEFT_X, w - 5, A_BOLD, buf);

    if (tgm_locked(m))
        put_attr(st, st->lay.tg_top, LEFT_X + w - 4, 4,
                 ink(st, CP_WARN) | A_BOLD, "LOCK");
}

static void draw_tg_pane(ui_state *st, uint64_t now) {
    const tg_manager *m   = app_tgm(st->app);
    const ui_layout  *L   = &st->lay;
    uint32_t          sel = tgm_selected(m);
    int x0 = LEFT_X, w = LEFT_W(L);

    draw_tg_header(st, now);

    int y     = L->tg_top + 2;
    int x_age = x0 + w - 5;
    int x_pri = x0 + 8;
    int x_flg = x0 + 11;

    int shown = 0;
    for (int i = 0; i < st->n_tg && y <= L->tg_bot; i++, y++, shown++) {
        const tg_row *r = &st->tg[i];
        const tgm_talker *tk = tgm_talker_on(m, r->tg);
        int muted = tgm_is_muted(m, r->tg);
        int here  = (r->tg == sel);

        chtype row = 0;
        if (st->focus == FOCUS_TG && i == st->cur[FOCUS_TG]) row |= A_REVERSE;
        else if (here) row |= A_BOLD;
        if (muted || r->mon_only) row |= A_DIM;

        char buf[64];
        snprintf(buf, sizeof(buf), "%c %-6u", here ? '>' : ' ', (unsigned)r->tg);
        attron(row);
        put(st, y, x0, w, buf);

        if (x_pri + 3 < x_age && r->prio > 0) {
            snprintf(buf, sizeof(buf), "%s", r->prio >= 2 ? "++" : "+");
            put(st, y, x_pri, 3, buf);
        }
        if (x_flg + 2 <= x_age) {
            if (tk) {
                attron(ink(st, CP_OK) | A_BOLD);
                put_glyph(st, y, x_flg, G_DOT);
                attroff(ink(st, CP_OK) | A_BOLD);
                attron(row);
            }
            if (muted) put(st, y, x_flg + 1, 1, "M");
        }

        uint64_t lh = tgm_last_heard(m, r->tg);
        char age[16];
        fmt_age(age, sizeof(age), lh ? now - lh : 0);
        snprintf(buf, sizeof(buf), "%5s", age);
        put(st, y, x_age, 5, buf);
        attroff(row);
    }
    st->shown[FOCUS_TG] = shown;
}

/* ------------------------------------------------------------------ meters */

static void draw_bar(const ui_state *st, int y, int x, int w, float level,
                     int edges, chtype a) {
    int inner = edges ? w - 2 : w;
    if (inner < 1) return;
    int filled = (int)(CLAMP(level, 0.0f, 1.0f) * (float)inner + 0.5f);

    attron(a);
    if (edges) put_glyph(st, y, x, G_EDGE);
    for (int i = 0; i < inner; i++)
        put_glyph(st, y, x + (edges ? 1 : 0) + i, i < filled ? G_BLOCK : G_SHADE);
    if (edges) put_glyph(st, y, x + w - 1, G_EDGE);
    attroff(a);
}

static void draw_meters(const ui_state *st) {
    const ui_layout *L = &st->lay;
    int x0 = LEFT_X, w = LEFT_W(L);
    int bar_x = x0 + 4, bar_w = w - 4;

    float mic  = app_mic_level(st->app);
    int   mute = app_output_muted(st->app);

    put(st, L->mic_y, x0, 3, "MIC");
    draw_bar(st, L->mic_y, bar_x, bar_w, mic, 1,
             ink(st, mic > 0.92f ? CP_BAD : CP_OK));

    put(st, L->spk_y, x0, 3, "SPK");
    draw_bar(st, L->spk_y, bar_x, bar_w, mute ? 0.0f : app_spk_level(st->app), 1,
             ink(st, CP_HEAD));

    int vol = app_volume(st->app);
    put(st, L->vol_y, x0, 3, "VOL");
    draw_bar(st, L->vol_y, bar_x, bar_w - 6, (float)vol / 100.0f, 0,
             mute ? A_DIM : 0);

    char buf[16];
    if (mute) snprintf(buf, sizeof(buf), "MUTE");
    else      snprintf(buf, sizeof(buf), "%3d%%", vol);
    put_attr(st, L->vol_y, x0 + w - 4, 4, mute ? ink(st, CP_BAD) | A_BOLD : 0, buf);
}

/* ------------------------------------------------- active / recent talkers */

static void draw_talker_panes(ui_state *st, uint64_t now) {
    const tg_manager *m = app_tgm(st->app);
    const ui_layout  *L = &st->lay;
    int x = L->right_x + 1, w = L->right_w - 1;
    char buf[200], age[16], dur[16];

    /* Half the pane each, so a busy reflector cannot push RECENT off-screen. */
    int avail  = L->right_bot - L->right_top + 1;
    int budget = (avail - 3) / 2;
    if (budget < 1) budget = 1;

    int callw = CLAMP(w - 26, 10, 24);

    put_attr(st, L->right_top, x, w, ink(st, CP_HEAD) | A_BOLD, "ACTIVE");

    int y = L->right_top + 1, shown = 0;
    for (int i = 0; i < m->n_active && shown < budget && y <= L->right_bot; i++, y++, shown++) {
        const tgm_talker *tk = &m->active[i];
        chtype row = (st->focus == FOCUS_ACTIVE && i == st->cur[FOCUS_ACTIVE])
                   ? A_REVERSE : ink(st, CP_OK);
        fmt_age(age, sizeof(age), now > tk->start_ms ? now - tk->start_ms : 1);
        snprintf(buf, sizeof(buf), " %-7u %-*s %5s",
                 (unsigned)tk->tg, callw, tk->call, age);
        put_attr(st, y, x, w, row, buf);
    }
    st->shown[FOCUS_ACTIVE] = shown;
    if (shown == 0) put_attr(st, y++, x, w, A_DIM, " (nobody is talking)");

    y++;
    if (y > L->right_bot) { st->shown[FOCUS_RECENT] = 0; return; }

    put_attr(st, y++, x, w, ink(st, CP_HEAD) | A_BOLD, "RECENT");

    shown = 0;
    for (int i = 0; i < m->n_recent && y <= L->right_bot; i++, y++, shown++) {
        const tgm_recent *rc = &m->recent[i];
        chtype row = (st->focus == FOCUS_RECENT && i == st->cur[FOCUS_RECENT])
                   ? A_REVERSE : 0;
        fmt_age(age, sizeof(age), now > rc->stop_ms ? now - rc->stop_ms : 1);
        fmt_duration(dur, sizeof(dur), rc->duration_s);
        snprintf(buf, sizeof(buf), " %-7u %-*s %5s ago %7s",
                 (unsigned)rc->tg, callw, rc->call, age, dur);
        put_attr(st, y, x, w, row, buf);
    }
    st->shown[FOCUS_RECENT] = shown;
    if (shown == 0) put_attr(st, y, x, w, A_DIM, " (nothing yet)");
}

/* --------------------------------------------------------------- log pane */

static void refresh_log(ui_state *st) {
    uint64_t serial = app_log_serial(st->app);
    if (serial == st->log_serial) return;
    st->log_serial = serial;
    st->n_log = app_log_snapshot(st->app, st->log, APP_LOG_LINES);
}

static void draw_log_pane(ui_state *st) {
    const ui_layout *L = &st->lay;
    if (L->log_top < 0) return;

    refresh_log(st);

    int x = L->right_x + 1, w = L->right_w - 1;
    int h = L->body_bot - L->log_top + 1;
    int first = st->n_log > h ? st->n_log - h : 0;

    for (int i = 0; i < h; i++) {
        int idx = first + i;
        if (idx >= st->n_log) break;
        const app_log_line *ln = &st->log[idx];
        chtype a = ln->level == LOG_ERR  ? ink(st, CP_BAD)
                 : ln->level == LOG_WARN ? ink(st, CP_WARN)
                 : ln->level == LOG_DBG  ? A_DIM : 0;
        put_attr(st, L->log_top + i, x, w, a, ln->text);
    }
}

/* ------------------------------------------------------------- ptt and keys */

static void draw_ptt(const ui_state *st) {
    const ui_layout *L = &st->lay;
    const svx_config *cfg = app_config(st->app);
    int x = 1, w = L->cols - 2;
    char buf[200], dur[16];

    if (app_tx_active(st->app)) {
        uint64_t el = app_tx_elapsed_ms(st->app) / 1000;
        fmt_duration(dur, sizeof(dur), el);

        char tail[64] = "";
        if (cfg->tx_timeout_sec > 0) {
            long left = (long)cfg->tx_timeout_sec - (long)el;
            if (left <= 15) snprintf(tail, sizeof(tail), "  TIMEOUT IN %lds",
                                     left > 0 ? left : 0);
        }
        snprintf(buf, sizeof(buf), "### T R A N S M I T T I N G   TG %u   %s%s ###",
                 (unsigned)tgm_selected(app_tgm(st->app)), dur, tail);

        chtype a = ink(st, CP_BAD) | A_REVERSE | A_BOLD;
        attron(a);
        for (int i = 0; i < w; i++) put(st, L->ptt_y, x + i, 1, " ");
        attroff(a);
        put_center(st, L->ptt_y, x, w, a, buf);
        return;
    }

    const char *statev;
    if (!app_tx_available(st->app))                          statev = "receive only";
    else if (rc_get_state(app_rc(st->app)) != RC_CONNECTED)  statev = "offline";
    else                                                     statev = "idle";

    snprintf(buf, sizeof(buf), "%s  SPACE = TRANSMIT  %s   %s",
             st->g[G_EDGE], st->g[G_EDGE], statev);
    put_center(st, L->ptt_y, x, w, A_BOLD, buf);
}

static void draw_keys(const ui_state *st) {
    char buf[240];

    if (st->hint_until > now_ms()) {
        put_center(st, st->lay.keys_y, 1, st->lay.cols - 2,
                   ink(st, CP_WARN) | A_BOLD, st->hint);
        return;
    }

    /* Two lists, because the full one does not fit on an 80-column terminal and
     * a hint that is cut off mid-word is worse than a shorter hint. */
    if (st->lay.cols >= 92)
        snprintf(buf, sizeof(buf),
                 "%s/%s tg  %s lock  SPACE ptt  m mute  Enter goto  d dev  l log  "
                 "r reconn  ? help  q quit",
                 st->g[G_LARR], st->g[G_RARR], st->g[G_UARR]);
    else
        snprintf(buf, sizeof(buf),
                 "%s/%s tg  %s lock  SPACE ptt  m mute  d dev  l log  ? help  q quit",
                 st->g[G_LARR], st->g[G_RARR], st->g[G_UARR]);

    put_attr(st, st->lay.keys_y, 2, st->lay.cols - 3, A_DIM, buf);
}

/* ------------------------------------------------------------------ modals */

static void draw_box(const ui_state *st, int y0, int x0, int h, int w, const char *title) {
    for (int y = y0; y < y0 + h; y++)
        for (int x = x0; x < x0 + w; x++) put(st, y, x, 1, " ");

    put_run(st, y0, x0 + 1, x0 + w - 2, G_HL);
    put_run(st, y0 + h - 1, x0 + 1, x0 + w - 2, G_HL);
    put_glyph(st, y0, x0, G_TL);
    put_glyph(st, y0, x0 + w - 1, G_TR);
    put_glyph(st, y0 + h - 1, x0, G_BL);
    put_glyph(st, y0 + h - 1, x0 + w - 1, G_BR);
    for (int y = y0 + 1; y < y0 + h - 1; y++) {
        put_glyph(st, y, x0, G_VL);
        put_glyph(st, y, x0 + w - 1, G_VL);
    }
    put_attr(st, y0, x0 + 2, w - 4, A_BOLD, title);
}

static void draw_help(const ui_state *st) {
    static const char *const LINES[] = {
        "left / right   previous / next talkgroup",
        "up             lock the talkgroup (nothing may move you)",
        "down           monitor only, no talkgroup selected",
        "1 .. 9         jump to the n-th configured talkgroup",
        "SPACE          transmit (toggle; a terminal has no key-up)",
        "ESC            stop transmitting, close this window",
        "Tab / S-Tab    move between the talkgroup, active and recent panes",
        "j / k          move the cursor inside the focused pane",
        "Enter          go to the talkgroup under the cursor",
        "m              mute / unmute the talkgroup under the cursor",
        "+ / -          output volume        0   mute the speaker",
        "t              test tone            s   sort numeric / last heard",
        "d              audio devices        l   show or hide the log",
        "c              connect / disconnect r   reconnect now",
        "x              dismiss the banner   Ctrl-L  redraw",
        "q              quit (refused while transmitting)",
        NULL
    };

    int n = 0;
    while (LINES[n]) n++;

    int w = 70, h = n + 4;
    if (w > st->lay.cols - 4) w = st->lay.cols - 4;
    if (h > st->lay.rows - 2) h = st->lay.rows - 2;
    int y0 = (st->lay.rows - h) / 2, x0 = (st->lay.cols - w) / 2;

    draw_box(st, y0, x0, h, w, " Keys ");
    for (int i = 0; i < n && y0 + 2 + i < y0 + h - 1; i++)
        put(st, y0 + 2 + i, x0 + 2, w - 4, LINES[i]);
}

static void draw_dev_modal(const ui_state *st) {
    const svx_config *cfg = app_config(st->app);

    int w = st->lay.cols - 8, h = st->lay.rows - 6;
    if (w > 88) w = 88;
    if (h > 20) h = 20;
    int y0 = (st->lay.rows - h) / 2, x0 = (st->lay.cols - w) / 2;
    int colw = (w - 5) / 2;

    draw_box(st, y0, x0, h, w, " Audio devices ");

    put_attr(st, y0 + 2, x0 + 2, colw, ink(st, CP_HEAD) | A_BOLD, "INPUT");
    put_attr(st, y0 + 2, x0 + 3 + colw, colw, ink(st, CP_HEAD) | A_BOLD, "OUTPUT");

    int list_h = h - 6;
    for (int side = 0; side < 2; side++) {
        const svx_devinfo *v = side ? st->dev_out : st->dev_in;
        int n = side ? st->n_out : st->n_in;
        int x = side ? x0 + 3 + colw : x0 + 2;

        if (n <= 0) {
            put_attr(st, y0 + 3, x, colw, A_DIM, "(none found)");
            continue;
        }
        for (int i = 0; i < n && i < list_h; i++) {
            chtype a = (st->dev_side == side && i == st->dev_cur[side]) ? A_REVERSE : 0;
            char buf[300];
            snprintf(buf, sizeof(buf), "%c %s%s",
                     i == st->dev_sel[side] ? '*' : ' ',
                     v[i].name, v[i].is_default ? "  (system default)" : "");
            put_attr(st, y0 + 3 + i, x, colw, a, buf);
        }
    }

    char buf[300];
    snprintf(buf, sizeof(buf), "in: %s    out: %s",
             cfg->input_device[0]  ? cfg->input_device  : "(default)",
             cfg->output_device[0] ? cfg->output_device : "(default)");
    put(st, y0 + h - 3, x0 + 2, w - 4, buf);
    put_attr(st, y0 + h - 2, x0 + 2, w - 4, A_DIM,
             "* = in use.  arrows browse, ESC closes.  Live switching: not yet.");
}

/* -------------------------------------------------------------------- draw */

static void clamp_cursor(ui_state *st);

static void draw_too_small(const ui_state *st) {
    char msg[64];
    snprintf(msg, sizeof(msg), "terminal too small %s need %dx%d",
             st->g[G_HL], UI_MIN_COLS, UI_MIN_ROWS);
    put_center(st, st->lay.rows / 2, 0, st->lay.cols, A_BOLD, msg);
}

static void draw(ui_state *st) {
    uint64_t now = now_ms();

    erase();
    compute_layout(st);

    if (st->lay.rows < UI_MIN_ROWS || st->lay.cols < UI_MIN_COLS) {
        draw_too_small(st);
    } else {
        build_tg_rows(st);
        clamp_cursor(st);
        draw_frame(st);
        draw_title(st);
        draw_status(st);
        draw_tg_pane(st, now);
        draw_meters(st);
        draw_talker_panes(st, now);
        draw_log_pane(st);
        draw_ptt(st);
        draw_keys(st);

        if (st->modal == MODAL_HELP) draw_help(st);
        else if (st->modal == MODAL_DEV) draw_dev_modal(st);
    }

    /* One deferred update for the whole screen: panes that refresh themselves
     * are what makes a curses interface flicker. */
    wnoutrefresh(stdscr);
    doupdate();

    st->dirty = 0;
    st->last_draw = now;
}

/* -------------------------------------------------------------------- keys */

static void clamp_cursor(ui_state *st) {
    for (int i = 0; i < FOCUS_N; i++) {
        int n = st->shown[i];
        if (st->cur[i] >= n) st->cur[i] = n > 0 ? n - 1 : 0;
        if (st->cur[i] < 0)  st->cur[i] = 0;
    }
}

static void cursor_step(ui_state *st, int delta) {
    int n = st->shown[st->focus];
    if (n <= 0) return;
    st->cur[st->focus] = CLAMP(st->cur[st->focus] + delta, 0, n - 1);
}

static void focus_step(ui_state *st, int delta) {
    st->focus = (ui_focus)(((int)st->focus + delta + FOCUS_N) % FOCUS_N);
    clamp_cursor(st);
}

static void activate_row(ui_state *st) {
    const tg_manager *m = app_tgm(st->app);

    if (st->focus == FOCUS_TG) {
        if (st->cur[FOCUS_TG] < st->n_tg)
            app_tg_select(st->app, st->tg[st->cur[FOCUS_TG]].tg);
        return;
    }
    if (st->focus == FOCUS_ACTIVE && st->cur[FOCUS_ACTIVE] < m->n_active)
        app_tg_select(st->app, m->active[st->cur[FOCUS_ACTIVE]].tg);
    else if (st->focus == FOCUS_RECENT && st->cur[FOCUS_RECENT] < m->n_recent)
        app_tg_select(st->app, m->recent[st->cur[FOCUS_RECENT]].tg);
}

/* Quitting mid-over would leave the reflector waiting for a flush that never
 * comes, so the first q only warns; the second within two seconds gives in. */
static void request_quit(ui_state *st) {
    uint64_t now = now_ms();

    if (!app_tx_active(st->app)) {
        app_quit(st->app);
        st->done = 1;
        return;
    }
    if (st->quit_armed_ms && now - st->quit_armed_ms <= UI_QUIT_MS) {
        app_ptt(st->app, CTL_OFF);
        app_quit(st->app);
        st->done = 1;
        return;
    }
    st->quit_armed_ms = now;
    hint(st, "transmitting: press q again to quit");
}

/* Enumerated once, when the window opens: listing devices talks to the audio
 * backend, which is far too expensive to do on every frame. */
static void open_dev_modal(ui_state *st) {
    const svx_config *cfg = app_config(st->app);

    st->n_in  = svx_audio_list(1, st->dev_in,  UI_MAX_DEVS);
    st->n_out = svx_audio_list(0, st->dev_out, UI_MAX_DEVS);
    if (st->n_in  < 0) st->n_in  = 0;
    if (st->n_out < 0) st->n_out = 0;

    for (int side = 0; side < 2; side++) {
        const svx_devinfo *v = side ? st->dev_out : st->dev_in;
        int n = side ? st->n_out : st->n_in;
        svx_devinfo chosen;

        st->dev_sel[side] = -1;
        svx_audio_resolve(!side, side ? cfg->output_device : cfg->input_device, &chosen);
        for (int i = 0; i < n; i++)
            if (strcmp(v[i].id, chosen.id) == 0) { st->dev_sel[side] = i; break; }

        st->dev_cur[side] = st->dev_sel[side] > 0 ? st->dev_sel[side] : 0;
    }

    st->dev_side = 0;
    st->modal = MODAL_DEV;
}

/* The modal keeps arrow keys and Enter to itself; everything else falls
 * through so PTT and ESC never stop working. */
static int modal_key(ui_state *st, int ch) {
    if (st->modal == MODAL_NONE) return 0;

    switch (ch) {
    case 27:
        st->modal = MODAL_NONE;
        return 0;                        /* ESC also stops transmitting */
    case KEY_LEFT:  if (st->modal == MODAL_DEV) st->dev_side = 0; return 1;
    case KEY_RIGHT: if (st->modal == MODAL_DEV) st->dev_side = 1; return 1;
    case KEY_UP:
    case 'k':
        if (st->modal == MODAL_DEV && st->dev_cur[st->dev_side] > 0)
            st->dev_cur[st->dev_side]--;
        return 1;
    case KEY_DOWN:
    case 'j': {
        if (st->modal != MODAL_DEV) return 1;
        int n = st->dev_side ? st->n_out : st->n_in;
        if (st->dev_cur[st->dev_side] < n - 1) st->dev_cur[st->dev_side]++;
        return 1;
    }
    case '\r': case '\n': case KEY_ENTER:
        if (st->modal == MODAL_DEV)
            hint(st, "set input_device / output_device in the config for now");
        return 1;
    case '?': case KEY_F(1): case 'q':
        st->modal = MODAL_NONE;
        return 1;
    default:
        return 0;
    }
}

static void handle_key(ui_state *st, int ch) {
    st->dirty = 1;

    if (ch == KEY_RESIZE) { g_winch = 1; return; }
    if (modal_key(st, ch)) return;

    switch (ch) {
    case KEY_LEFT:   app_tg_prev(st->app); break;
    case KEY_RIGHT:  app_tg_next(st->app); break;
    case KEY_UP:     app_toggle_lock(st->app); break;
    case KEY_DOWN:   app_tg_select(st->app, 0); break;

    case ' ':        app_ptt(st->app, CTL_TOGGLE); break;
    case 27:         app_ptt(st->app, CTL_OFF); break;

    case '\t':       focus_step(st, 1); break;
    case KEY_BTAB:   focus_step(st, -1); break;
    case 'j':        cursor_step(st, 1); break;
    case 'k':        cursor_step(st, -1); break;

    case '\r': case '\n': case KEY_ENTER: activate_row(st); break;

    case 'm':        app_toggle_mute(st->app, highlighted_tg(st)); break;
    case '+': case '=': app_volume_delta(st->app,  5); break;
    case '-': case '_': app_volume_delta(st->app, -5); break;
    case '0':        app_toggle_output_mute(st->app); break;
    case 't':        app_test_tone(st->app); break;

    case 'd':        open_dev_modal(st); break;
    case 'l':        st->show_log = !st->show_log; break;
    case 'c':        app_toggle_connect(st->app); break;
    case 'r':        app_reconnect(st->app); break;
    case 's':        st->sort = st->sort == SORT_NUMERIC ? SORT_LASTHEARD
                                                         : SORT_NUMERIC; break;
    case 'x':        app_dismiss_banner(st->app); break;

    case '?': case KEY_F(1): st->modal = MODAL_HELP; break;

    case 12:         clearok(stdscr, TRUE); break;      /* Ctrl-L */
    case 3:                                             /* Ctrl-C, if delivered */
    case 'q':        request_quit(st); break;

    default:
        if (ch >= '1' && ch <= '9') app_tg_index(st->app, ch - '1');
        break;
    }
}

/* -------------------------------------------------------------------- loop */

static void on_app_change(void *user) {
    ((ui_state *)user)->dirty = 1;
}

/* Only the things that genuinely animate justify redrawing at 15 Hz; an idle
 * client falls back to twice a second, which is enough for the clock. */
static int tick_interval(const ui_state *st) {
    const tg_manager *m = app_tgm(st->app);
    if (app_tx_active(st->app) || m->n_active > 0) return UI_TICK_MS;
    if (app_mic_level(st->app) > 0.01f || app_spk_level(st->app) > 0.01f)
        return UI_TICK_MS;
    return UI_SLOW_MS;
}

static void install_signals(struct sigaction *old_winch,
                            struct sigaction *old_int,
                            struct sigaction *old_term) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = on_winch;
    sigaction(SIGWINCH, &sa, old_winch);
    sa.sa_handler = on_intr;
    sigaction(SIGINT, &sa, old_int);
    sa.sa_handler = on_term;
    sigaction(SIGTERM, &sa, old_term);
}

static void init_colors(ui_state *st) {
    st->color = has_colors();
    if (!st->color) return;

    /* start_color() first: use_default_colors() only means anything once the
     * palette exists, and -1 is what keeps the user's own background. */
    start_color();
    use_default_colors();
    init_pair(CP_OK,   COLOR_GREEN,   -1);
    init_pair(CP_WARN, COLOR_YELLOW,  -1);
    init_pair(CP_BAD,  COLOR_RED,     -1);
    init_pair(CP_HEAD, COLOR_CYAN,    -1);
}

/* A resize cannot be handled from the signal handler, so it is done here:
 * tear the screen down, let ncurses re-read the size, and lay out again. */
static void handle_resize(ui_state *st) {
    g_winch = 0;
    endwin();
    refresh();
    clear();
    compute_layout(st);
    st->dirty = 1;
}

int ui_run(svx_app *app) {
    ui_state *st = calloc(1, sizeof(*st));
    if (!st) return 1;

    st->app = app;
    st->log = calloc(APP_LOG_LINES, sizeof(*st->log));
    if (!st->log) { free(st); return 1; }

    const svx_config *cfg = app_config(app);
    st->g          = GLYPHS[cfg->unicode ? 1 : 0];
    st->show_log   = cfg->show_log_pane;
    st->sort       = str_ieq(cfg->tg_order, "lastheard") ? SORT_LASTHEARD : SORT_NUMERIC;
    st->log_serial = ~(uint64_t)0;        /* forces the first snapshot */
    st->dirty      = 1;

    initscr();
    cbreak();
    noecho();
    nonl();
    curs_set(0);
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);                /* poll() waits, getch() never does */
#if defined(NCURSES_VERSION)
    /* Even with nodelay(), a lone ESC parks inside getch() for ESCDELAY while
     * curses decides whether an escape sequence is coming — a whole second on
     * macOS, during which the reflector and the audio are not serviced. 25 ms
     * is longer than any arrow key needs and short enough not to be felt. */
    set_escdelay(25);
#endif
    init_colors(st);

    struct sigaction old_winch, old_int, old_term;
    install_signals(&old_winch, &old_int, &old_term);

    /* Divert logging into the app's ring BEFORE anything can log. We now own
     * the terminal, and a single line written to stdout would tear a hole in
     * the screen. The log pane renders the ring instead. */
    app_capture_log(app);

    app_set_observer(app, on_app_change, st);

    /* Open the audio devices and the control FIFO, then start connecting.
     * This has to happen after initscr() so that anything it logs — device
     * names, the microphone permission result — lands in the ring rather than
     * on the screen we are about to draw. */
    app_start(app);

    compute_layout(st);
    draw(st);

    while (!st->done && !app_should_quit(app)) {
        struct pollfd p[16];
        int n = app_poll_fds(app, p, (int)(sizeof(p) / sizeof(p[0])) - 1);
        if (n < 0) n = 0;
        p[n].fd = STDIN_FILENO;
        p[n].events = POLLIN;
        p[n].revents = 0;
        n++;

        uint64_t now = now_ms();
        int wait_ms  = app_next_timeout_ms(app, now);
        if (wait_ms < 0 || wait_ms > 100) wait_ms = 100;

        /* Never sleep past the next frame, or the meters would stutter. */
        int due = tick_interval(st) - (int)(now - st->last_draw);
        if (due < 0) due = 0;
        if (due < wait_ms) wait_ms = due;

        if (poll(p, (nfds_t)n, wait_ms) < 0 && errno != EINTR) break;

        if (g_term) { app_quit(app); break; }
        if (g_intr) { g_intr = 0; request_quit(st); }
        if (g_winch) handle_resize(st);

        /* Drain regardless of what poll() said: a signal can cut poll() short
         * with keystrokes already sitting in the buffer. */
        for (int ch = getch(); ch != ERR; ch = getch()) handle_key(st, ch);

        app_service(app, now_ms());

        now = now_ms();
        if ((st->dirty || (int)(now - st->last_draw) >= tick_interval(st))
            && (int)(now - st->last_draw) >= UI_TICK_MS)
            draw(st);
    }

    app_set_observer(app, NULL, NULL);
    sigaction(SIGWINCH, &old_winch, NULL);
    sigaction(SIGINT,   &old_int,   NULL);
    sigaction(SIGTERM,  &old_term,  NULL);

    curs_set(1);
    endwin();

    free(st->log);
    free(st);
    return 0;
}
