/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * `svxconnect --init-config` fixtures.
 *
 * Two properties matter. The generated file must read back through
 * config_load() as exactly the values that were given, with every comment of
 * the example intact. And the example's own identity — a real callsign, a real
 * email domain, a real position — must never survive into someone else's
 * configuration. Run with `make test`.
 */
#include "common/conftemplate.h"
#include "common/config.h"
#include "common/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The real example.conf, embedded by the Makefile exactly as main.c gets it. */
static const char EXAMPLE_CONF[] =
#include "example_conf.inc"
;

static int g_fail;
static int g_run;

#define CHECK(cond, what) do {                                        \
    g_run++;                                                          \
    if (!(cond)) { g_fail++; printf("FAIL  %s\n", what); }            \
    else          printf("ok    %s\n", what);                         \
} while (0)

static void check_eq(const char *got, const char *want, const char *what) {
    int ok = got && strcmp(got, want) == 0;
    CHECK(ok, what);
    if (!ok) printf("      got:\n%s\n      want:\n%s\n", got ? got : "(null)", want);
}

/* Render, write to a temporary file, and load it back. */
static int load_rendered(const char *text, svx_config *cfg) {
    char path[] = "/tmp/svxconftest-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return -1;
    size_t n = strlen(text);
    int ok = write(fd, text, n) == (ssize_t)n;
    close(fd);
    config_defaults(cfg);
    int rc = ok ? config_load(cfg, path) : -1;
    unlink(path);
    return rc;
}

int main(void) {
    log_set_level(LOG_ERR);

    /* ---- line rules, on a small template ---- */
    const char *tpl =
        "# example header\n"
        "#   cp example.conf ~/.config/svxconnect/svxconnect.conf\n"
        "\n"
        "callsign   = ON6URE        # your callsign\n"
        "email      = you@example.com\n"
        "latitude   = 51.0538\n"
        "port       = 5300          # fallback port\n"
        "# jitter_ms = 80\n";

    const conftpl_kv one[] = { { "callsign", "ON0ABC" } };
    char *out = conftpl_render(tpl, "# H\n", one, 1);
    check_eq(out,
        "# H\n"
        "\n"
        "callsign   = ON0ABC        # your callsign\n"
        "email      =\n"
        "# latitude   = 51.0538\n"
        "port       = 5300          # fallback port\n"
        "# jitter_ms = 80\n",
        "given key replaced in place, identity blanked, position commented out");
    free(out);

    const conftpl_kv longer[] = { { "callsign", "ON0ABCDEFGHIJKLMNOP" } };
    out = conftpl_render("callsign = X   # c\n", NULL, longer, 1);
    check_eq(out, "callsign = ON0ABCDEFGHIJKLMNOP # c\n",
             "a value longer than the gap keeps one space before the comment");
    free(out);

    const conftpl_kv hash[] = { { "location", "QTH #2; shack" } };
    out = conftpl_render("location = Gent\n", NULL, hash, 1);
    check_eq(out, "location = QTH \\#2\\; shack\n", "comment characters in a value are escaped");
    free(out);

    const conftpl_kv extra[] = { { "port", "1" }, { "jitter_ms", "120" }, { "jitter_ms", "150" } };
    out = conftpl_render("port = 5300\n", NULL, extra, 3);
    check_eq(out,
        "port = 1\n"
        "\n# ------------------------------------------------ set with --init-config\n\n"
        "jitter_ms = 150\n",
        "a key the template lacks is appended once, last value wins");
    free(out);

    out = conftpl_render(tpl, NULL, NULL, 0);
    CHECK(out && strncmp(out, "# example header\n", 17) == 0, "no header keeps the template's own");
    free(out);

    /* ---- the real example.conf ---- */
    svx_config cfg;

    out = conftpl_render(EXAMPLE_CONF, "# test\n", NULL, 0);
    CHECK(out != NULL, "the bundled example renders");
    CHECK(load_rendered(out, &cfg) == 0, "the rendered example loads");
    CHECK(cfg.callsign[0] == '\0' && cfg.email[0] == '\0' && cfg.reflector[0] == '\0',
          "the example's identity is not carried over");
    CHECK(cfg.latitude == 0.0 && cfg.longitude == 0.0 && cfg.location[0] == '\0',
          "the example's position is not carried over");
    CHECK(config_validate(&cfg, 1) != 0, "an unfilled config fails validation, naming what is missing");
    CHECK(cfg.n_monitored > 0 && cfg.jitter_ms > 0, "the example's non-personal settings survive");
    CHECK(strstr(out, "linger_seconds") && strstr(out, "protects a QSO"),
          "the example's comments survive");
    free(out);

    const conftpl_kv me[] = {
        { "callsign",  "ON0ABC" },
        { "email",     "op@example.org" },
        { "reflector", "reflector.example.org" },
        { "latitude",  "50.85" },
        { "longitude", "4.35" },
    };
    out = conftpl_render(EXAMPLE_CONF, "# test\n", me, 5);
    CHECK(load_rendered(out, &cfg) == 0, "a filled-in example loads");
    CHECK(strcmp(cfg.callsign, "ON0ABC") == 0 && strcmp(cfg.email, "op@example.org") == 0
          && strcmp(cfg.reflector, "reflector.example.org") == 0,
          "the given identity reads back exactly");
    CHECK(cfg.latitude == 50.85 && cfg.longitude == 4.35 && cfg.location[0] == '\0',
          "a given position is written, an omitted location stays out");
    CHECK(config_validate(&cfg, 1) == 0, "a filled-in config is ready to enrol");
    CHECK(strstr(out, "ON6URE") == NULL, "the author's callsign appears nowhere");
    free(out);

    printf("\n%d/%d passed\n", g_run - g_fail, g_run);
    return g_fail ? 1 : 0;
}
