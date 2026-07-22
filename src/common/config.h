/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * Configuration.
 *
 * One parser, one set of rules — SvxBridge grew three parsers with three
 * different comment/quoting conventions, which is a live footgun. Here:
 *
 *   - `#` or `;` starts a comment anywhere on the line; `\#` is a literal '#'
 *   - values may be wrapped in one layer of matched " or '
 *   - keys are case-insensitive; booleans are on/off, yes/no, true/false, 1/0
 *   - `~/` expands to $HOME in every path-typed value
 *
 * Every key is described once in a table (config.c), which drives parsing,
 * range validation and `--dump-config` alike. Adding a key means adding one
 * table row, not touching three functions.
 */
#ifndef SVX_CONFIG_H
#define SVX_CONFIG_H

#include <stdint.h>
#include <stddef.h>

#define SVX_MAX_TG      64
#define SVX_MAX_PRIO     3    /* "8+++" — three '+' is as deep as it goes */

/* A talkgroup as declared in the config: an id plus a priority given by the
 * number of trailing '+' characters.  8 => prio 0,  8+ => 1,  8++ => 2. */
typedef struct {
    uint32_t id;
    int      priority;
} svx_tg_entry;

typedef struct {
    /* ---- identity ---- */
    char     callsign[32];
    char     email[128];
    char     reflector[256];
    int      port;
    char     pki_dir[512];
    double   latitude;
    double   longitude;
    char     location[64];

    /* ---- talkgroups ---- */
    svx_tg_entry switchable[SVX_MAX_TG];
    int          n_switchable;
    svx_tg_entry monitored[SVX_MAX_TG];
    int          n_monitored;
    int      default_tg;
    int      lock_on_start;
    int      linger_seconds;
    int      idle_seconds;
    char     tg_order[16];        /* numeric | lastheard */

    /* ---- audio ---- */
    char     input_device[256];
    char     output_device[256];
    int      output_volume_pct;
    int      mic_agc;
    int      mic_agc_target_pct;
    int      mic_gain;            /* fixed input boost in dB, applied before AGC */
    int      jitter_ms;
    int      tail_trim_ms;
    int      roger_beep;
    int      roger_beep_min_sec;
    int      auto_duck;
    int      auto_duck_quiet_pct;

    /* ---- ptt ----
     * PTT is toggle-only by design: a terminal delivers characters, not key
     * events, so there is no key-release to hang hold-to-talk on. See
     * docs/PTT.md. Real push-to-talk hardware goes through ctl_fifo. */
    int      tx_timeout_sec;      /* hard un-key after this long; 0 disables */
    char     ctl_fifo[512];       /* external PTT / scripting; "" disables */

    /* ---- ui ---- */
    int      unicode;
    int      show_log_pane;
    char     log_file[512];
    char     log_level[16];

    /* ---- runtime coordination ----
     * The run lock excludes a second connected client (the CLI and the desktop
     * GUI share it); the status file is a snapshot a panel widget reads. Both
     * default under the state dir; "" disables the status export. */
    char     lock_file[512];
    char     status_file[512];
} svx_config;

/* Populate with defaults. Never fails. */
void config_defaults(svx_config *cfg);

/* Parse `path` over the top of whatever is already in *cfg.
 * Returns 0 on success, -1 if the file could not be opened. Bad values inside
 * the file are logged and skipped, they do not fail the load — a typo in one
 * key should not stop you getting on the air. */
int  config_load(svx_config *cfg, const char *path);

/* Set a single key as if it had appeared in the file. Used by --set and by
 * the runtime state file. Returns 0 on success, -1 on unknown key or bad
 * value (the reason is logged). */
int  config_set(svx_config *cfg, const char *key, const char *value);

/* Cross-field validation: callsign present, TG lists sane, etc.
 * Returns 0 if usable. Logs every problem found. `for_enroll` relaxes the
 * checks that only matter once you are actually connecting. */
int  config_validate(const svx_config *cfg, int for_enroll);

/* Print every key and its resolved value to `out` (--dump-config). */
void config_dump(const svx_config *cfg, void *out /* FILE* */);

/* Resolve the config file path: $SVXCONNECT_CONF, then
 * ~/.config/svxconnect/svxconnect.conf, then /etc/svxconnect/svxconnect.conf.
 * Writes the first that exists, or the preferred one if none do. */
void config_default_path(char *dst, size_t cap);

/* Directory for runtime state (state.conf, log, ctl fifo):
 * $XDG_STATE_HOME/svxconnect, else ~/.local/state/svxconnect. */
void config_state_dir(char *dst, size_t cap);

/* ---- talkgroup list helpers ---- */

/* Parse "8++, 1745+, 8000" into `out`. Returns the count, or -1 on a
 * malformed entry. Duplicate ids keep the highest priority seen. */
int  tglist_parse(const char *s, svx_tg_entry *out, int max);

/* Format back to "8++, 1745+, 8000". */
void tglist_format(char *dst, size_t cap, const svx_tg_entry *v, int n);

/* Priority of `id`: the monitored list wins, then switchable, else 0.
 * Returns -1 if `id` is in neither list (i.e. not watched at all). */
int  config_tg_priority(const svx_config *cfg, uint32_t id);

/* Is `id` in either list? */
int  config_tg_is_watched(const svx_config *cfg, uint32_t id);

#endif
