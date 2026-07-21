/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — Copyright (C) 2026 Joeri Van Dooren
 */
#include "config.h"
#include "log.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>

/* ------------------------------------------------------------------ table */

typedef enum {
    CT_STR,      /* plain string                                   */
    CT_PATH,     /* string with ~/ expansion                       */
    CT_CALL,     /* string, upper-cased                            */
    CT_INT,      /* int, range-checked against lo..hi              */
    CT_BOOL,     /* int 0/1                                        */
    CT_DOUBLE,   /* double, range-checked                          */
    CT_ENUM,     /* string, must be one of `choices` (|-separated) */
    CT_TGLIST    /* svx_tg_entry[] + int count at aux              */
} cfg_type;

typedef struct {
    const char *key;
    cfg_type    type;
    size_t      off;       /* offsetof(svx_config, field)            */
    size_t      len;       /* sizeof for strings, capacity for lists */
    size_t      aux;       /* CT_TGLIST: offsetof of the int count   */
    double      lo, hi;    /* CT_INT / CT_DOUBLE range               */
    const char *choices;   /* CT_ENUM                                */
} cfg_desc;

#define F(field)  offsetof(svx_config, field), sizeof(((svx_config *)0)->field)
#define A(field)  offsetof(svx_config, field)

static const cfg_desc DESC[] = {
    /* key                   type       field                 aux                  lo      hi     choices */
    { "callsign",            CT_CALL,   F(callsign),          0,                   0, 0,          NULL },
    { "email",               CT_STR,    F(email),             0,                   0, 0,          NULL },
    { "reflector",           CT_STR,    F(reflector),         0,                   0, 0,          NULL },
    { "port",                CT_INT,    F(port),              0,                   1, 65535,      NULL },
    { "pki_dir",             CT_PATH,   F(pki_dir),           0,                   0, 0,          NULL },
    { "latitude",            CT_DOUBLE, F(latitude),          0,                 -90, 90,         NULL },
    { "longitude",           CT_DOUBLE, F(longitude),         0,                -180, 180,        NULL },
    { "location",            CT_STR,    F(location),          0,                   0, 0,          NULL },

    { "switchable",          CT_TGLIST, F(switchable),        A(n_switchable),     0, 0,          NULL },
    { "monitored",           CT_TGLIST, F(monitored),         A(n_monitored),      0, 0,          NULL },
    { "default_tg",          CT_INT,    F(default_tg),        0,                   0, 4294967295, NULL },
    { "lock_on_start",       CT_BOOL,   F(lock_on_start),     0,                   0, 0,          NULL },
    { "linger_seconds",      CT_INT,    F(linger_seconds),    0,                  10, 300,        NULL },
    { "idle_seconds",        CT_INT,    F(idle_seconds),      0,                   0, 3600,       NULL },
    { "tg_order",            CT_ENUM,   F(tg_order),          0,                   0, 0,          "numeric|lastheard" },

    { "input_device",        CT_STR,    F(input_device),      0,                   0, 0,          NULL },
    { "output_device",       CT_STR,    F(output_device),     0,                   0, 0,          NULL },
    { "output_volume_pct",   CT_INT,    F(output_volume_pct), 0,                   0, 100,        NULL },
    { "mic_agc",             CT_BOOL,   F(mic_agc),           0,                   0, 0,          NULL },
    { "mic_agc_target_pct",  CT_INT,    F(mic_agc_target_pct),0,                   5, 95,         NULL },
    { "jitter_ms",           CT_INT,    F(jitter_ms),         0,                  40, 300,        NULL },
    { "tail_trim_ms",        CT_INT,    F(tail_trim_ms),      0,                   0, 1000,       NULL },
    { "roger_beep",          CT_BOOL,   F(roger_beep),        0,                   0, 0,          NULL },
    { "roger_beep_min_sec",  CT_INT,    F(roger_beep_min_sec),0,                   0, 60,         NULL },
    { "auto_duck",           CT_BOOL,   F(auto_duck),         0,                   0, 0,          NULL },
    { "auto_duck_quiet_pct", CT_INT,    F(auto_duck_quiet_pct),0,                  0, 50,         NULL },

    { "tx_timeout_sec",      CT_INT,    F(tx_timeout_sec),    0,                   0, 3600,       NULL },
    { "ctl_fifo",            CT_PATH,   F(ctl_fifo),          0,                   0, 0,          NULL },

    { "unicode",             CT_BOOL,   F(unicode),           0,                   0, 0,          NULL },
    { "show_log_pane",       CT_BOOL,   F(show_log_pane),     0,                   0, 0,          NULL },
    { "log_file",            CT_PATH,   F(log_file),          0,                   0, 0,          NULL },
    { "log_level",           CT_ENUM,   F(log_level),         0,                   0, 0,          "err|warn|info|debug" },
};

#define N_DESC ((int)(sizeof(DESC) / sizeof(DESC[0])))

static const cfg_desc *find_desc(const char *key) {
    for (int i = 0; i < N_DESC; i++) {
        if (str_ieq(DESC[i].key, key)) return &DESC[i];
    }
    return NULL;
}

/* --------------------------------------------------------------- defaults */

void config_defaults(svx_config *cfg) {
    memset(cfg, 0, sizeof(*cfg));

    char state[512];
    config_state_dir(state, sizeof(state));

    const char *home = getenv("HOME");

    snprintf(cfg->reflector, sizeof(cfg->reflector), "%s", "");
    cfg->port = 5300;
    if (home && *home)
        snprintf(cfg->pki_dir, sizeof(cfg->pki_dir), "%s/.config/svxconnect/pki", home);
    else
        snprintf(cfg->pki_dir, sizeof(cfg->pki_dir), "./pki");

    cfg->default_tg          = 0;
    cfg->lock_on_start       = 0;
    cfg->linger_seconds      = 30;
    cfg->idle_seconds        = 60;
    snprintf(cfg->tg_order, sizeof(cfg->tg_order), "numeric");

    snprintf(cfg->input_device,  sizeof(cfg->input_device),  "default");
    snprintf(cfg->output_device, sizeof(cfg->output_device), "default");
    cfg->output_volume_pct   = 100;
    cfg->mic_agc             = 1;
    cfg->mic_agc_target_pct  = 30;
    cfg->jitter_ms           = 80;
    cfg->tail_trim_ms        = 0;
    cfg->roger_beep          = 1;
    cfg->roger_beep_min_sec  = 3;
    cfg->auto_duck           = 0;
    cfg->auto_duck_quiet_pct = 5;

    cfg->tx_timeout_sec      = 120;
    snprintf(cfg->ctl_fifo, sizeof(cfg->ctl_fifo), "%s/ctl", state);

    cfg->unicode             = 1;
    cfg->show_log_pane       = 0;
    snprintf(cfg->log_file, sizeof(cfg->log_file), "%s/svxconnect.log", state);
    snprintf(cfg->log_level, sizeof(cfg->log_level), "info");
}

/* ------------------------------------------------------------------ paths */

void config_state_dir(char *dst, size_t cap) {
    const char *xdg = getenv("XDG_STATE_HOME");
    if (xdg && *xdg) { snprintf(dst, cap, "%s/svxconnect", xdg); return; }
    const char *home = getenv("HOME");
    if (home && *home) { snprintf(dst, cap, "%s/.local/state/svxconnect", home); return; }
    snprintf(dst, cap, "./.svxconnect");
}

void config_default_path(char *dst, size_t cap) {
    const char *env = getenv("SVXCONNECT_CONF");
    if (env && *env) { snprintf(dst, cap, "%s", env); return; }

    const char *home = getenv("HOME");
    char user[512];
    user[0] = '\0';
    if (home && *home) {
        const char *xdg = getenv("XDG_CONFIG_HOME");
        if (xdg && *xdg) snprintf(user, sizeof(user), "%s/svxconnect/svxconnect.conf", xdg);
        else             snprintf(user, sizeof(user), "%s/.config/svxconnect/svxconnect.conf", home);
        if (access(user, R_OK) == 0) { snprintf(dst, cap, "%s", user); return; }
    }
    if (access("/etc/svxconnect/svxconnect.conf", R_OK) == 0) {
        snprintf(dst, cap, "%s", "/etc/svxconnect/svxconnect.conf");
        return;
    }
    /* Nothing exists yet — name the one we would like the user to create. */
    snprintf(dst, cap, "%s", user[0] ? user : "./svxconnect.conf");
}

/* ------------------------------------------------------------ talkgroups */

int tglist_parse(const char *s, svx_tg_entry *out, int max) {
    int n = 0;
    if (!s) return 0;

    const char *p = s;
    while (*p) {
        while (*p && (isspace((unsigned char)*p) || *p == ',')) p++;
        if (!*p) break;

        if (!isdigit((unsigned char)*p)) {
            log_warn("config: talkgroup list: unexpected '%c' in \"%s\"", *p, s);
            return -1;
        }
        char *end = NULL;
        unsigned long id = strtoul(p, &end, 10);
        if (id > 0xFFFFFFFFUL) {
            log_warn("config: talkgroup %lu out of range", id);
            return -1;
        }
        p = end;

        int prio = 0;
        while (*p == '+') { prio++; p++; }
        if (prio > SVX_MAX_PRIO) {
            log_warn("config: talkgroup %lu: %d '+' is more than the %d supported",
                     id, prio, SVX_MAX_PRIO);
            prio = SVX_MAX_PRIO;
        }

        while (*p && isspace((unsigned char)*p)) p++;
        if (*p && *p != ',') {
            log_warn("config: talkgroup list: unexpected '%c' after %lu", *p, id);
            return -1;
        }

        /* Duplicate ids collapse, keeping the highest priority seen. */
        int dup = -1;
        for (int i = 0; i < n; i++) if (out[i].id == (uint32_t)id) { dup = i; break; }
        if (dup >= 0) {
            if (prio > out[dup].priority) out[dup].priority = prio;
            continue;
        }
        if (n >= max) {
            log_warn("config: more than %d talkgroups in a list, ignoring the rest", max);
            break;
        }
        out[n].id       = (uint32_t)id;
        out[n].priority = prio;
        n++;
    }
    return n;
}

void tglist_format(char *dst, size_t cap, const svx_tg_entry *v, int n) {
    if (cap == 0) return;
    dst[0] = '\0';
    size_t used = 0;
    for (int i = 0; i < n; i++) {
        char item[32];
        char plus[SVX_MAX_PRIO + 1];
        int  k = 0;
        for (; k < v[i].priority && k < SVX_MAX_PRIO; k++) plus[k] = '+';
        plus[k] = '\0';
        int m = snprintf(item, sizeof(item), "%s%u%s",
                         i ? ", " : "", v[i].id, plus);
        if (m < 0 || used + (size_t)m >= cap) break;
        memcpy(dst + used, item, (size_t)m + 1);
        used += (size_t)m;
    }
}

int config_tg_priority(const svx_config *cfg, uint32_t id) {
    for (int i = 0; i < cfg->n_monitored; i++)
        if (cfg->monitored[i].id == id) return cfg->monitored[i].priority;
    for (int i = 0; i < cfg->n_switchable; i++)
        if (cfg->switchable[i].id == id) return cfg->switchable[i].priority;
    return -1;
}

int config_tg_is_watched(const svx_config *cfg, uint32_t id) {
    return config_tg_priority(cfg, id) >= 0;
}

/* ------------------------------------------------------------- set a key */

static int parse_bool(const char *v, int *out) {
    if (str_ieq(v, "on")  || str_ieq(v, "yes") || str_ieq(v, "true")  || strcmp(v, "1") == 0) { *out = 1; return 0; }
    if (str_ieq(v, "off") || str_ieq(v, "no")  || str_ieq(v, "false") || strcmp(v, "0") == 0) { *out = 0; return 0; }
    return -1;
}

static int enum_ok(const char *choices, const char *v) {
    const char *p = choices;
    while (*p) {
        const char *bar = strchr(p, '|');
        size_t n = bar ? (size_t)(bar - p) : strlen(p);
        if (strlen(v) == n && strncasecmp(p, v, n) == 0) return 1;
        if (!bar) break;
        p = bar + 1;
    }
    return 0;
}

int config_set(svx_config *cfg, const char *key, const char *value) {
    const cfg_desc *d = find_desc(key);
    if (!d) {
        log_warn("config: unknown key '%s' (ignored)", key);
        return -1;
    }
    char  *base = (char *)cfg;
    void  *slot = base + d->off;

    switch (d->type) {
    case CT_STR:
        snprintf((char *)slot, d->len, "%s", value);
        return 0;

    case CT_CALL:
        snprintf((char *)slot, d->len, "%s", value);
        str_upper((char *)slot);
        return 0;

    case CT_PATH:
        path_expand((char *)slot, d->len, value);
        return 0;

    case CT_ENUM:
        if (!enum_ok(d->choices, value)) {
            log_warn("config: %s = '%s' is not one of {%s} (ignored)",
                     d->key, value, d->choices);
            return -1;
        }
        snprintf((char *)slot, d->len, "%s", value);
        return 0;

    case CT_BOOL: {
        int b;
        if (parse_bool(value, &b) != 0) {
            log_warn("config: %s = '%s' is not a boolean (ignored)", d->key, value);
            return -1;
        }
        *(int *)slot = b;
        return 0;
    }

    case CT_INT: {
        char *end = NULL;
        errno = 0;
        long long n = strtoll(value, &end, 10);
        if (end == value || (end && *str_trim(end) != '\0') || errno == ERANGE) {
            log_warn("config: %s = '%s' is not a number (ignored)", d->key, value);
            return -1;
        }
        if ((double)n < d->lo || (double)n > d->hi) {
            log_warn("config: %s = %lld is outside %.0f..%.0f (clamped)",
                     d->key, n, d->lo, d->hi);
            n = (long long)CLAMP((double)n, d->lo, d->hi);
        }
        *(int *)slot = (int)n;
        return 0;
    }

    case CT_DOUBLE: {
        char *end = NULL;
        errno = 0;
        double x = strtod(value, &end);
        if (end == value || (end && *str_trim(end) != '\0')) {
            /* A comma decimal separator is the classic trap here: LC_NUMERIC
             * is forced to "C" in main() precisely so this stays an error. */
            log_warn("config: %s = '%s' is not a number — use '.' as the decimal "
                     "separator (ignored)", d->key, value);
            return -1;
        }
        if (x < d->lo || x > d->hi) {
            log_warn("config: %s = %g is outside %g..%g (ignored)", d->key, x, d->lo, d->hi);
            return -1;
        }
        *(double *)slot = x;
        return 0;
    }

    case CT_TGLIST: {
        svx_tg_entry tmp[SVX_MAX_TG];
        int n = tglist_parse(value, tmp, SVX_MAX_TG);
        if (n < 0) {
            log_warn("config: %s: list not applied", d->key);
            return -1;
        }
        memcpy(slot, tmp, sizeof(svx_tg_entry) * (size_t)n);
        *(int *)(base + d->aux) = n;
        return 0;
    }
    }
    return -1;
}

/* ------------------------------------------------------------------ load */

/* Strip a comment introduced by an unescaped '#' or ';'. Rewrites "\#" to
 * "#" in place. Quoting does not protect a '#' — keeping one rule beats a
 * clever one nobody remembers. */
static void strip_comment(char *s) {
    char *r = s, *w = s;
    while (*r) {
        if (*r == '\\' && (r[1] == '#' || r[1] == ';')) { *w++ = r[1]; r += 2; continue; }
        if (*r == '#' || *r == ';') break;
        *w++ = *r++;
    }
    *w = '\0';
}

static char *strip_quotes(char *v) {
    size_t n = strlen(v);
    if (n >= 2 && ((v[0] == '"' && v[n - 1] == '"') || (v[0] == '\'' && v[n - 1] == '\''))) {
        v[n - 1] = '\0';
        return v + 1;
    }
    return v;
}

int config_load(svx_config *cfg, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        log_err("config: cannot open %s: %s", path, strerror(errno));
        return -1;
    }
    char line[2048];
    int  lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        strip_comment(line);
        char *p = str_trim(line);
        if (*p == '\0') continue;

        char *eq = strchr(p, '=');
        if (!eq) {
            log_warn("config: %s:%d: no '=' (ignored)", path, lineno);
            continue;
        }
        *eq = '\0';
        char *key = str_trim(p);
        char *val = strip_quotes(str_trim(eq + 1));
        if (*key == '\0') continue;
        config_set(cfg, key, val);
    }
    fclose(f);
    return 0;
}

/* -------------------------------------------------------------- validate */

int config_validate(const svx_config *cfg, int for_enroll) {
    int bad = 0;

    if (cfg->callsign[0] == '\0') {
        log_err("config: 'callsign' is required");
        bad++;
    }
    if (cfg->reflector[0] == '\0') {
        log_err("config: 'reflector' is required (e.g. reflector = be.svx.link)");
        bad++;
    }
    if (for_enroll && cfg->email[0] == '\0') {
        log_err("config: 'email' is required to enrol — it becomes the CSR's "
                "subjectAltName so the sysop can reach you");
        bad++;
    }
    if (cfg->pki_dir[0] == '\0') {
        log_err("config: 'pki_dir' is required");
        bad++;
    }

    if (for_enroll) return bad ? -1 : 0;

    if (cfg->n_switchable == 0 && cfg->n_monitored == 0) {
        log_err("config: no talkgroups — set 'switchable' and/or 'monitored'");
        bad++;
    }
    if (cfg->default_tg != 0 && !config_tg_is_watched(cfg, (uint32_t)cfg->default_tg)) {
        log_warn("config: default_tg = %d is in neither 'switchable' nor "
                 "'monitored'; it will be selected but not watched",
                 cfg->default_tg);
    }
    /* Every switchable TG should also be heard, otherwise arrowing onto it
     * gives you a TG the server never reports activity for. We fold them in
     * automatically at runtime, so this is advice, not an error. */
    for (int i = 0; i < cfg->n_switchable; i++) {
        int found = 0;
        for (int j = 0; j < cfg->n_monitored; j++)
            if (cfg->monitored[j].id == cfg->switchable[i].id) { found = 1; break; }
        if (!found) {
            log_dbg("config: switchable TG %u is not in 'monitored'; it is watched "
                    "anyway while selected", cfg->switchable[i].id);
        }
    }
    if ((cfg->latitude == 0.0) != (cfg->longitude == 0.0)) {
        log_warn("config: only one of latitude/longitude is set — publishing no "
                 "position. Set both or neither.");
    }
    return bad ? -1 : 0;
}

/* ------------------------------------------------------------------ dump */

void config_dump(const svx_config *cfg, void *out) {
    FILE *f = (FILE *)out;
    const char *base = (const char *)cfg;

    for (int i = 0; i < N_DESC; i++) {
        const cfg_desc *d = &DESC[i];
        const void *slot = base + d->off;
        char buf[1024];

        switch (d->type) {
        case CT_STR: case CT_CALL: case CT_PATH: case CT_ENUM:
            fprintf(f, "%-20s = %s\n", d->key, (const char *)slot);
            break;
        case CT_BOOL:
            fprintf(f, "%-20s = %s\n", d->key, *(const int *)slot ? "on" : "off");
            break;
        case CT_INT:
            fprintf(f, "%-20s = %d\n", d->key, *(const int *)slot);
            break;
        case CT_DOUBLE:
            fprintf(f, "%-20s = %.6f\n", d->key, *(const double *)slot);
            break;
        case CT_TGLIST: {
            int n = *(const int *)(base + d->aux);
            tglist_format(buf, sizeof(buf), (const svx_tg_entry *)slot, n);
            fprintf(f, "%-20s = %s\n", d->key, buf);
            break;
        }
        }
    }
}
