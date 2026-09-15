/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "conftemplate.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ------------------------------------------------------------ growing buf */

typedef struct {
    char   *buf;
    size_t  len, cap;
    int     oom;
} sbuf;

static void sb_put(sbuf *b, const char *s, size_t n) {
    if (b->oom) return;
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 4096;
        while (b->len + n + 1 > cap) cap *= 2;
        char *nb = realloc(b->buf, cap);
        if (!nb) { b->oom = 1; return; }
        b->buf = nb;
        b->cap = cap;
    }
    memcpy(b->buf + b->len, s, n);
    b->len += n;
    b->buf[b->len] = '\0';
}

static void sb_puts(sbuf *b, const char *s) { sb_put(b, s, strlen(s)); }

/* Characters since the last newline — where the next byte will land. */
static size_t sb_column(const sbuf *b) {
    size_t i = b->len;
    while (i > 0 && b->buf[i - 1] != '\n') i--;
    return b->len - i;
}

/* ------------------------------------------------------------------ rules */

static const char *const IDENTITY[] = { "callsign", "email", "reflector" };
static const char *const POSITION[] = { "latitude", "longitude", "location" };

static int key_in(const char *key, size_t klen, const char *const *list, int n) {
    for (int i = 0; i < n; i++)
        if (strlen(list[i]) == klen && strncasecmp(list[i], key, klen) == 0) return 1;
    return 0;
}

static int find_kv(const char *key, size_t klen, const conftpl_kv *kv, int n) {
    /* The LAST match wins, the way a repeated key does in config_load(). */
    for (int i = n - 1; i >= 0; i--)
        if (kv[i].key && strlen(kv[i].key) == klen && strncasecmp(kv[i].key, key, klen) == 0)
            return i;
    return -1;
}

/* A value as the parser will read it back: config_load() cuts a comment at an
 * unescaped '#' or ';', so those are escaped, and one layer of quotes is
 * stripped, so a value with surrounding whitespace is quoted to keep it. */
static void put_value(sbuf *b, const char *v) {
    size_t n = strlen(v);
    int quote = n > 0 && (isspace((unsigned char)v[0]) || isspace((unsigned char)v[n - 1]));
    if (quote) sb_put(b, "\"", 1);
    for (size_t i = 0; i < n; i++) {
        if (v[i] == '#' || v[i] == ';') sb_put(b, "\\", 1);
        sb_put(b, v + i, 1);
    }
    if (quote) sb_put(b, "\"", 1);
}

static void render_line(sbuf *out, const char *line, size_t n,
                        const conftpl_kv *kv, int n_kv, unsigned char *used) {
    size_t i = 0;
    while (i < n && (line[i] == ' ' || line[i] == '\t')) i++;

    /* Comments, blank lines and anything that is not `key = value` pass through. */
    size_t ks = i;
    while (i < n && (isalnum((unsigned char)line[i]) || line[i] == '_')) i++;
    size_t klen = i - ks;
    while (i < n && (line[i] == ' ' || line[i] == '\t')) i++;
    if (klen == 0 || i >= n || line[i] != '=') {
        sb_put(out, line, n);
        return;
    }

    size_t vs = i + 1;                       /* just past '=' */
    while (vs < n && (line[vs] == ' ' || line[vs] == '\t')) vs++;

    size_t cs = n;                           /* comment start, if any */
    for (size_t j = vs; j < n; j++) {
        if ((line[j] == '#' || line[j] == ';') && (j == 0 || line[j - 1] != '\\')) {
            cs = j;
            break;
        }
    }

    const char *key = line + ks;
    int idx = find_kv(key, klen, kv, n_kv);
    const char *value;

    if (idx >= 0) {
        used[idx] = 1;
        value = kv[idx].value ? kv[idx].value : "";
    } else if (key_in(key, klen, IDENTITY, 3)) {
        value = "";
    } else if (key_in(key, klen, POSITION, 3)) {
        sb_put(out, "# ", 2);
        sb_put(out, line, n);
        return;
    } else {
        sb_put(out, line, n);
        return;
    }

    if (*value == '\0' && cs == n) {
        /* Empty and uncommented: end the line at '=' with no trailing space. */
        size_t eq = vs;
        while (eq > 0 && line[eq - 1] != '=') eq--;
        sb_put(out, line, eq);
        return;
    }

    sb_put(out, line, vs);
    put_value(out, value);

    if (cs < n) {
        /* Keep the comment in its original column, so a block of aligned
         * comments stays aligned whatever length the new value has. */
        size_t col = sb_column(out);
        if (col < cs) {
            while (col++ < cs) sb_put(out, " ", 1);
        } else {
            sb_put(out, " ", 1);
        }
        sb_put(out, line + cs, n - cs);
    }
}

/* ----------------------------------------------------------------- render */

char *conftpl_render(const char *tpl, const char *header,
                     const conftpl_kv *kv, int n_kv) {
    sbuf out = { 0 };
    unsigned char *used = calloc(n_kv > 0 ? (size_t)n_kv : 1, 1);
    if (!used) return NULL;

    const char *p = tpl ? tpl : "";

    if (header) {
        while (*p == '#') {
            const char *nl = strchr(p, '\n');
            p = nl ? nl + 1 : p + strlen(p);
        }
        sb_puts(&out, header);
    }

    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        render_line(&out, p, n, kv, n_kv, used);
        sb_put(&out, "\n", 1);
        p += n + (nl ? 1 : 0);
    }

    int extra = 0;
    for (int i = 0; i < n_kv; i++) {
        if (used[i] || !kv[i].key) continue;
        if (find_kv(kv[i].key, strlen(kv[i].key), kv, n_kv) != i) continue;   /* shadowed */
        if (!extra) {
            sb_puts(&out, "\n# ------------------------------------------------ set with --init-config\n\n");
            extra = 1;
        }
        sb_puts(&out, kv[i].key);
        sb_puts(&out, " = ");
        put_value(&out, kv[i].value ? kv[i].value : "");
        sb_put(&out, "\n", 1);
    }

    free(used);
    if (out.oom) {
        free(out.buf);
        return NULL;
    }
    if (!out.buf) {
        out.buf = calloc(1, 1);
    }
    return out.buf;
}
