/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * Turning the bundled example.conf into a user's first configuration.
 *
 * `svxconnect --init-config` writes the fully commented example rather than a
 * bare dump of keys, because the comments ARE the documentation: they are the
 * only place a new user learns what linger_seconds protects or why mic_gain is
 * applied before the AGC. But the example is also a real, working
 * configuration for its author, so it cannot be copied verbatim — a user who
 * skipped editing it would enrol, and transmit, as someone else.
 *
 * So the template is rendered line by line:
 *
 *   - a key given in `kv` gets that value, and keeps its trailing comment in
 *     the same column;
 *   - the identity keys (callsign, email, reflector) that were NOT given are
 *     left empty, so config_validate() names each one as required;
 *   - the position keys (latitude, longitude, location) that were NOT given
 *     are commented out — an empty latitude does not parse, and no position
 *     at all is better than the author's;
 *   - everything else is copied byte for byte, and a `kv` key the template
 *     does not mention is appended at the end.
 *
 * Pure string work with no I/O, so tests/conftest.c can check it exactly.
 */
#ifndef SVX_CONFTEMPLATE_H
#define SVX_CONFTEMPLATE_H

typedef struct {
    const char *key;
    const char *value;
} conftpl_kv;

/* Render `tpl`. When `header` is not NULL it replaces the template's leading
 * comment block (the example's own "copy me to ..." instructions). Returns a
 * malloc()ed string the caller frees, or NULL when out of memory. */
char *conftpl_render(const char *tpl, const char *header,
                     const conftpl_kv *kv, int n_kv);

#endif
