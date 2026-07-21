/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "nodeinfo.h"
#include "common/util.h"

#include <stdio.h>
#include <string.h>

static void json_escape(const char *in, char *out, size_t cap) {
    size_t o = 0;
    for (size_t i = 0; in && in[i] && o + 2 < cap; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') {
            if (o + 3 >= cap) break;
            out[o++] = '\\';
            out[o++] = (char)c;
        } else if (c < 0x20) {
            /* Control characters would make the server's parser reject the
             * whole document; drop them rather than emit \u escapes. */
            continue;
        } else {
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
}

size_t nodeinfo_build_json(char *out, size_t cap, const svx_config *cfg) {
    char lat_s[32], lon_s[32], grid[8], loc_esc[192], call_esc[64];

    /* No position configured means EMPTY strings, not "0.0".
     *
     * SvxBridge publishes "0.0"/"0.0", which the portal happily plots — in the
     * Gulf of Guinea, off the coast of Ghana. The macOS app sends empty
     * strings for this case and the portal renders no marker, which is what
     * "I did not tell you where I am" should look like. */
    int have_pos = (cfg->latitude != 0.0 || cfg->longitude != 0.0);
    if (have_pos) {
        /* LC_NUMERIC is pinned to "C" in main() so these cannot come out with
         * a comma and take the whole document down with them. */
        snprintf(lat_s, sizeof(lat_s), "%.7f", cfg->latitude);
        snprintf(lon_s, sizeof(lon_s), "%.7f", cfg->longitude);
        maidenhead(grid, sizeof(grid), cfg->latitude, cfg->longitude);
    } else {
        lat_s[0] = '\0';
        lon_s[0] = '\0';
        grid[0]  = '\0';
    }

    json_escape(cfg->location, loc_esc,  sizeof(loc_esc));
    json_escape(cfg->callsign, call_esc, sizeof(call_esc));

    int n = snprintf(out, cap,
        "{\"nodeLocation\":\"%s\",\"hidden\":false,\"sysop\":\"%s\","
        "\"qth\":[{\"name\":\"SVXConnect-CLI\","
        "\"pos\":{\"lat\":\"%s\",\"long\":\"%s\",\"loc\":\"%s\"},"
        "\"rx\":{\"A\":{\"name\":\"Rx1\"}},\"tx\":{\"A\":{\"name\":\"Tx1\"}}}]}",
        loc_esc, call_esc, lat_s, lon_s, grid);

    if (n < 0) { if (cap) out[0] = '\0'; return 0; }
    if ((size_t)n >= cap) return cap - 1;
    return (size_t)n;
}
