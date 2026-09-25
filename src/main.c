/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — a terminal client for SvxLink reflectors.
 * Copyright (c) 2026 Joeri Van Dooren
 *
 * Released under the MIT License; see LICENSE.
 */
#include "common/config.h"
#include "common/conftemplate.h"
#include "common/lock.h"
#include "common/log.h"
#include "common/pki.h"
#include "common/util.h"
#include "headless.h"
#include "reflector/enroll.h"
#include "audio/audiotest.h"
#include "app.h"
#include "ui/ui.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>

#define SVX_VERSION "0.1.4"

/* example.conf, embedded at build time by the Makefile's example_conf.inc
 * rule, so --init-config needs no data file at a path that differs between
 * Homebrew, Debian and a source build — and can never be out of step with the
 * binary that reads the result. */
static const char EXAMPLE_CONF[] =
#include "example_conf.inc"
;

enum {
    MODE_TUI = 0,
    MODE_HEADLESS,
    MODE_ENROLL,
    MODE_LIST_DEVICES,
    MODE_AUDIO_TEST,
    MODE_DUMP_CONFIG,
    MODE_INIT_CONFIG
};

/* Print, after a validation failure, where the configuration is expected and
 * how to create or fix it. `resolved` is the path we looked at — which, when no
 * file exists, is still the path we would like the user to create (see
 * config_default_path). */
static void config_help(const char *resolved) {
    int exists = (access(resolved, R_OK) == 0);

    if (exists) {
        fprintf(stderr,
            "\nsvxconnect: the configuration at\n"
            "              %s\n"
            "            is incomplete — see the errors above. Edit that file,\n"
            "            or start over with:  svxconnect --init-config --force\n",
            resolved);
        return;
    }

    fprintf(stderr,
        "\nsvxconnect: no configuration file found. Create one with:\n\n"
        "              svxconnect --init-config\n\n"
        "            That writes a fully commented configuration to\n"
        "              %s\n"
        "            and asks for your callsign, email and reflector.\n\n"
        "            Or point at a config explicitly with:  svxconnect -c <file>\n",
        resolved);
}

/* Refuse to enter a connect mode without a certificate.
 *
 * A missing certificate is not something reconnecting can fix — every attempt
 * would fail at the TLS stage and the client would just retry forever. So we
 * check up front and, if there is no cert, say plainly that enrolment is needed
 * and stop, rather than spinning. Returns 0 when enrolled. */
static int require_enrolled(const svx_config *cfg) {
    char key_path[1024], cert_path[1024];
    pki_build_path(key_path,  sizeof(key_path),  cfg->pki_dir, cfg->callsign, "key");
    pki_build_path(cert_path, sizeof(cert_path), cfg->pki_dir, cfg->callsign, "crt");
    if (pki_file_exists(key_path) && pki_file_exists(cert_path))
        return 0;

    fprintf(stderr,
        "\nsvxconnect: %s is not enrolled — there is no certificate in\n"
        "              %s\n\n"
        "            Run:  svxconnect --enroll\n"
        "            That sends a signing request to %s and waits for the\n"
        "            reflector operator to approve it; then start svxconnect again.\n",
        cfg->callsign, cfg->pki_dir, cfg->reflector);
    return 1;
}

/* Take the shared run lock before owning the reflector connection. Only one
 * client — this CLI (TUI or headless) or the desktop GUI — may be connected at
 * once, so if the lock is held we name the holder and refuse rather than fight
 * over the same certificate and node id. --enroll takes it too, but only for
 * the moment it logs in to check a certificate (see enroll.c). Returns 0 when
 * acquired. */
static int acquire_run_lock(const svx_config *cfg, const char *kind) {
    int r = svx_lock_acquire(cfg->lock_file, kind);
    if (r == 0) return 0;

    if (r == -1) {
        char who[16] = "";
        long pid = 0;
        svx_lock_who(cfg->lock_file, who, sizeof(who), &pid);
        fprintf(stderr,
            "\nsvxconnect: already running as '%s' (pid %ld).\n"
            "            Only one client may hold the reflector connection at a time —\n"
            "            the terminal client and the desktop GUI share this lock.\n"
            "            Quit that one first. (lock: %s)\n",
            who[0] ? who : "svxconnect", pid, cfg->lock_file);
    } else {
        fprintf(stderr, "svxconnect: cannot create lock file %s\n", cfg->lock_file);
    }
    return -1;
}

/* ------------------------------------------------------------ --init-config */

/* The file --init-config writes: -c, else $SVXCONNECT_CONF, else the per-user
 * path. Deliberately NOT config_default_path(), which answers with
 * /etc/svxconnect/svxconnect.conf whenever that exists — a user asking for a
 * configuration of their own must not be sent to overwrite the system one. */
static void init_config_path(char *dst, size_t cap, const char *conf_path) {
    const char *env  = getenv("SVXCONNECT_CONF");
    const char *xdg  = getenv("XDG_CONFIG_HOME");
    const char *home = getenv("HOME");

    if (conf_path)          path_expand(dst, cap, conf_path);
    else if (env && *env)   path_expand(dst, cap, env);
    else if (xdg && *xdg)   snprintf(dst, cap, "%s/svxconnect/svxconnect.conf", xdg);
    else if (home && *home) snprintf(dst, cap, "%s/.config/svxconnect/svxconnect.conf", home);
    else                    snprintf(dst, cap, "./svxconnect.conf");
}

static int valid_callsign(const char *s) {
    for (const char *p = s; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '-') {
            printf("    A callsign is letters, digits and '-', e.g. ON4ABC.\n");
            return 0;
        }
    }
    return 1;
}

static int valid_email(const char *s) {
    const char *at = strchr(s, '@');
    if (!at || at == s || !strchr(at, '.') || strchr(s, ' ')) {
        printf("    That does not look like an email address.\n");
        return 0;
    }
    return 1;
}

static int valid_host(const char *s) {
    if (!strchr(s, '.') || strchr(s, ' ') || strchr(s, '/') || strchr(s, ':')) {
        printf("    Give just the host name, e.g. be.svx.link — no port, no URL.\n");
        return 0;
    }
    return 1;
}

/* Ask one question on the terminal. Returns 1 with `out` filled, or 0 when the
 * user pressed Enter (or gave up after three invalid answers) and the key is
 * left for them to fill in by hand. */
static int ask(const char *question, char *out, size_t cap, int (*valid)(const char *)) {
    for (int attempt = 0; attempt < 3; attempt++) {
        printf("  %s: ", question);
        fflush(stdout);
        if (!fgets(out, (int)cap, stdin)) {
            printf("\n");
            out[0] = '\0';
            return 0;
        }
        char *v = str_trim(out);
        memmove(out, v, strlen(v) + 1);
        if (out[0] == '\0') return 0;
        if (valid(out)) return 1;
    }
    out[0] = '\0';
    return 0;
}

static int has_key(const conftpl_kv *kv, int n, const char *key) {
    for (int i = 0; i < n; i++)
        if (str_ieq(kv[i].key, key)) return 1;
    return 0;
}

static int run_init_config(const char *conf_path, const char **sets, int n_sets, int force) {
    char path[1024];
    init_config_path(path, sizeof(path), conf_path);
    const int existed = (access(path, F_OK) == 0);

    if (existed && !force) {
        fprintf(stderr,
            "\nsvxconnect: %s already exists — nothing written.\n"
            "            Edit it, or start over with:  svxconnect --init-config --force\n"
            "            (the current file is then kept as %s.bak)\n",
            path, path);
        return 1;
    }

    /* --set values go through the real parser first, so a typo or an
     * out-of-range number is refused here instead of being written into a file
     * that then fails to load. */
    conftpl_kv kv[64];
    char       keys[64][64];
    char       vals[64][512];
    int        n_kv = 0;
    svx_config scratch;
    config_defaults(&scratch);

    for (int i = 0; i < n_sets && n_kv < 60; i++) {
        char buf[600];
        snprintf(buf, sizeof(buf), "%s", sets[i]);
        char *eq = strchr(buf, '=');
        if (!eq) {
            fprintf(stderr, "svxconnect: --set needs KEY=VALUE, got '%s'\n", sets[i]);
            return 2;
        }
        *eq = '\0';
        const char *k = str_trim(buf);
        const char *v = str_trim(eq + 1);
        if (config_set(&scratch, k, v) != 0) return 2;

        snprintf(keys[n_kv], sizeof(keys[n_kv]), "%s", k);
        snprintf(vals[n_kv], sizeof(vals[n_kv]), "%s", v);
        kv[n_kv].key   = keys[n_kv];
        kv[n_kv].value = vals[n_kv];
        n_kv++;
    }

    /* Ask for the identity that was not given — but only when someone is
     * there to answer. From a script, a package test or a pipe, the keys are
     * simply left empty for the user to fill in. */
    static const struct {
        const char *key;
        const char *question;
        int (*valid)(const char *);
    } ASK[] = {
        { "callsign",  "Callsign",                                   valid_callsign },
        { "email",     "Email address (so the reflector sysop can reach you)", valid_email },
        { "reflector", "Reflector host, e.g. be.svx.link",           valid_host },
    };

    const int interactive = isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
    int asked = 0;
    for (int i = 0; i < 3 && n_kv < 64; i++) {
        if (has_key(kv, n_kv, ASK[i].key) || !interactive) continue;
        if (!asked) {
            printf("Creating %s\nPress Enter to skip a question and fill it in later.\n\n", path);
            asked = 1;
        }
        if (ask(ASK[i].question, vals[n_kv], sizeof(vals[n_kv]), ASK[i].valid)) {
            snprintf(keys[n_kv], sizeof(keys[n_kv]), "%s", ASK[i].key);
            kv[n_kv].key   = keys[n_kv];
            kv[n_kv].value = vals[n_kv];
            n_kv++;
        }
    }

    /* The callsign is also the certificate's file name stem; write it the way
     * config_set() will read it. */
    for (int i = 0; i < n_kv; i++)
        if (str_ieq(kv[i].key, "callsign")) str_upper(vals[i]);

    char header[768];
    snprintf(header, sizeof(header),
        "# SVXConnect configuration\n"
        "#\n"
        "# Written by `svxconnect --init-config` (svxconnect %s) from the bundled\n"
        "# example. Every setting is listed with an explanation. The three you must\n"
        "# fill in are callsign, email and reflector; everything else has a default\n"
        "# that works.\n"
        "#\n"
        "# Shared with the SVXConnect desktop apps: one file, one identity.\n"
        "# `svxconnect --dump-config` prints what the program actually read.\n"
        "#\n"
        "# Syntax: '#' or ';' starts a comment ('\\#' is a literal hash). Keys are\n"
        "# case-insensitive. Booleans: on/off, yes/no, true/false, 1/0.\n",
        SVX_VERSION);

    char *text = conftpl_render(EXAMPLE_CONF, header, kv, n_kv);
    if (!text) {
        fprintf(stderr, "svxconnect: out of memory\n");
        return 1;
    }

    char dir[1024];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir) {
        *slash = '\0';
        if (mkdir_p(dir, 0700) != 0) {
            fprintf(stderr, "svxconnect: cannot create %s: %s\n", dir, strerror(errno));
            free(text);
            return 1;
        }
    }

    /* Written beside the target and renamed into place, so an interrupted
     * write never leaves half a configuration behind; mode 0600 from the
     * start, because the file names an email address. */
    char tmp[1100];
    snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        fprintf(stderr, "svxconnect: cannot write %s: %s\n", tmp, strerror(errno));
        free(text);
        return 1;
    }

    const char *p   = text;
    size_t      len = strlen(text);
    while (len > 0) {
        ssize_t w = write(fd, p, len);
        if (w < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "svxconnect: cannot write %s: %s\n", tmp, strerror(errno));
            close(fd);
            unlink(tmp);
            free(text);
            return 1;
        }
        p   += w;
        len -= (size_t)w;
    }
    fsync(fd);
    close(fd);
    free(text);

    char bak[1100] = "";
    if (existed) {
        snprintf(bak, sizeof(bak), "%s.bak", path);
        if (rename(path, bak) != 0) {
            fprintf(stderr, "svxconnect: cannot keep the old file as %s: %s\n", bak, strerror(errno));
            unlink(tmp);
            return 1;
        }
    }
    if (rename(tmp, path) != 0) {
        fprintf(stderr, "svxconnect: cannot create %s: %s\n", path, strerror(errno));
        unlink(tmp);
        return 1;
    }

    /* Read it back, the way every later run will, to report what is missing. */
    svx_config written;
    config_defaults(&written);
    config_load(&written, path);

    char missing[64] = "";
    if (!written.callsign[0])  strcat(missing, missing[0] ? ", callsign"  : "callsign");
    if (!written.email[0])     strcat(missing, missing[0] ? ", email"     : "email");
    if (!written.reflector[0]) strcat(missing, missing[0] ? ", reflector" : "reflector");

    printf("\nWrote %s\n", path);
    if (bak[0]) printf("The previous file is kept as %s\n", bak);

    if (missing[0]) {
        printf("\nStill to fill in: %s\n"
               "  $EDITOR %s\n"
               "\nThen:\n", missing, path);
    } else {
        printf("\nNext:\n");
    }
    printf("  svxconnect --enroll    # send a signing request; wait for the sysop to approve it\n"
           "  svxconnect             # and you are on the air\n");
    return 0;
}

static void usage(FILE *f) {
    fprintf(f,
"svxconnect " SVX_VERSION " — terminal client for SvxLink reflectors\n"
"\n"
"Usage: svxconnect [options]\n"
"\n"
"Options:\n"
"  -c, --config FILE     configuration file\n"
"                        (default: $SVXCONNECT_CONF, then\n"
"                         ~/.config/svxconnect/svxconnect.conf, then\n"
"                         /etc/svxconnect/svxconnect.conf)\n"
"      --set KEY=VALUE   override one config key; repeatable\n"
"  -v, --verbose         log at debug level\n"
"      --no-tx           receive only; never open the microphone\n"
"      --headless        no TUI, log events to stdout\n"
"      --init-config     write a fully commented configuration, asking for your\n"
"                        callsign, email and reflector; --set fills in any key\n"
"      --force           with --init-config: replace an existing file (kept as .bak)\n"
"      --enroll          get a certificate signed, or check the one you have with\n"
"                        the reflector and replace it if it refuses it\n"
"      --list-devices    list audio input and output devices, then exit\n"
"      --audio-test      loop the microphone back to the speaker, then exit\n"
"      --dump-config     print every setting with its resolved value\n"
"      --ascii           draw the TUI with ASCII only (same as unicode = off)\n"
"  -V, --version         print the version and exit\n"
"  -h, --help            this help\n"
"\n"
"Keys (in the TUI):\n"
"  up/down     switch talkgroup      PageDown  lock/unlock talkgroup\n"
"  left/right  output volume         space     transmit (toggle)\n"
"  ESC stop tx   m mute   d devices   l log   r reconnect   ? help   q quit\n"
"\n"
"Report bugs at https://github.com/Guru-RF/SVXConnect-CLI\n");
}

int main(int argc, char **argv) {
    /* UTF-8 for the TUI, but LC_NUMERIC stays "C": in a comma-decimal locale
     * printf("%f", 51.05) yields "51,050000", which the reflector's JSON
     * parser rejects — taking the whole MsgNodeInfo down with it. */
    setlocale(LC_ALL, "");
    setlocale(LC_NUMERIC, "C");

    /* A reflector that drops the TCP connection must not kill us. */
    signal(SIGPIPE, SIG_IGN);

    int  mode        = MODE_TUI;
    int  verbose     = 0;
    int  no_tx       = 0;
    int  force_ascii = 0;
    int  force       = 0;
    const char *conf_path = NULL;

    /* --set overrides are collected and applied after the file, so the command
     * line always wins regardless of argument order. */
    const char *sets[32];
    int         n_sets = 0;

    static const struct option LONG[] = {
        { "config",       required_argument, 0, 'c' },
        { "set",          required_argument, 0,  1  },
        { "verbose",      no_argument,       0, 'v' },
        { "no-tx",        no_argument,       0,  2  },
        { "headless",     no_argument,       0,  3  },
        { "enroll",       no_argument,       0,  4  },
        { "list-devices", no_argument,       0,  5  },
        { "audio-test",   no_argument,       0,  6  },
        { "dump-config",  no_argument,       0,  7  },
        { "ascii",        no_argument,       0,  8  },
        { "init-config",  no_argument,       0,  9  },
        { "force",        no_argument,       0, 10  },
        { "version",      no_argument,       0, 'V' },
        { "help",         no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };

    for (;;) {
        int c = getopt_long(argc, argv, "c:vVh", LONG, NULL);
        if (c == -1) break;
        switch (c) {
        case 'c': conf_path = optarg; break;
        case 'v': verbose = 1; break;
        case  1:
            if (n_sets < (int)(sizeof(sets) / sizeof(sets[0]))) sets[n_sets++] = optarg;
            else { fprintf(stderr, "svxconnect: too many --set overrides\n"); return 2; }
            break;
        case  2: no_tx = 1; break;
        case  3: mode = MODE_HEADLESS; break;
        case  4: mode = MODE_ENROLL; break;
        case  5: mode = MODE_LIST_DEVICES; break;
        case  6: mode = MODE_AUDIO_TEST; break;
        case  7: mode = MODE_DUMP_CONFIG; break;
        case  8: force_ascii = 1; break;
        case  9: mode = MODE_INIT_CONFIG; break;
        case 10: force = 1; break;
        case 'V': printf("svxconnect %s\n", SVX_VERSION); return 0;
        case 'h': usage(stdout); return 0;
        default:  usage(stderr); return 2;
        }
    }
    if (optind < argc) {
        fprintf(stderr, "svxconnect: unexpected argument '%s'\n", argv[optind]);
        usage(stderr);
        return 2;
    }
    if (force && mode != MODE_INIT_CONFIG) {
        fprintf(stderr, "svxconnect: --force only applies to --init-config\n");
        return 2;
    }

    if (verbose) log_set_level(LOG_DBG);

    /* Before any configuration is loaded: there usually is none yet, and an
     * explicit -c naming a file that does not exist is exactly the point. */
    if (mode == MODE_INIT_CONFIG)
        return run_init_config(conf_path, sets, n_sets, force);

    /* ---- configuration ---- */
    svx_config cfg;
    config_defaults(&cfg);

    char resolved[1024];
    if (conf_path) {
        path_expand(resolved, sizeof(resolved), conf_path);
    } else {
        config_default_path(resolved, sizeof(resolved));
    }

    if (access(resolved, R_OK) == 0) {
        if (config_load(&cfg, resolved) != 0) return 1;
        log_dbg("config: loaded %s", resolved);
    } else if (conf_path) {
        /* An explicitly named file that is not there is an error. A missing
         * default is not — --list-devices and --help must work on a fresh box. */
        log_err("config: %s does not exist", resolved);
        return 1;
    } else {
        log_dbg("config: no file at %s, using defaults", resolved);
    }

    for (int i = 0; i < n_sets; i++) {
        char kv[512];
        snprintf(kv, sizeof(kv), "%s", sets[i]);
        char *eq = strchr(kv, '=');
        if (!eq) {
            fprintf(stderr, "svxconnect: --set needs KEY=VALUE, got '%s'\n", sets[i]);
            return 2;
        }
        *eq = '\0';
        if (config_set(&cfg, str_trim(kv), str_trim(eq + 1)) != 0) return 2;
    }

    /* The command line beats the file for these two. */
    if (force_ascii) cfg.unicode = 0;
    if (!verbose) {
        int lvl = log_level_from_name(cfg.log_level);
        if (lvl >= 0) log_set_level(lvl);
    }

    switch (mode) {
    case MODE_DUMP_CONFIG:
        printf("# svxconnect %s — resolved configuration\n", SVX_VERSION);
        printf("# source: %s\n\n", access(resolved, R_OK) == 0 ? resolved : "(defaults only)");
        config_dump(&cfg, stdout);
        return 0;

    case MODE_ENROLL: {
        if (config_validate(&cfg, 1) != 0) { config_help(resolved); return 1; }
        int rc = enroll_run(&cfg, 30);
        return rc == 0 ? 0 : (rc > 0 ? 1 : 2);
    }

    case MODE_LIST_DEVICES:
        return audio_list_devices(&cfg);

    case MODE_AUDIO_TEST:
        return audio_run_test(&cfg);

    case MODE_HEADLESS:
        if (config_validate(&cfg, 0) != 0) {
            config_help(resolved);
            return 1;
        }
        if (require_enrolled(&cfg) != 0) return 4;
        if (acquire_run_lock(&cfg, "headless") != 0) return 5;
        {
            int rc = run_headless(&cfg, no_tx);
            svx_lock_release();
            return rc;
        }

    case MODE_TUI:
    default:
        if (config_validate(&cfg, 0) != 0) {
            config_help(resolved);
            return 1;
        }
        if (require_enrolled(&cfg) != 0) return 4;
        if (acquire_run_lock(&cfg, "cli") != 0) return 5;
        {
            svx_app *app = app_new(&cfg, no_tx);
            if (!app) { svx_lock_release(); fprintf(stderr, "svxconnect: out of memory\n"); return 1; }
            app_set_owner_kind(app, "cli");
            int rc = ui_run(app);
            app_free(app);
            svx_lock_release();
            return rc;
        }
    }
}
