/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — a terminal client for SvxLink reflectors.
 * Copyright (C) 2026 Joeri Van Dooren
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version. See LICENSE.
 */
#include "common/config.h"
#include "common/log.h"
#include "common/util.h"
#include "headless.h"
#include "reflector/enroll.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>

#define SVX_VERSION "0.1.0-dev"

enum {
    MODE_TUI = 0,
    MODE_HEADLESS,
    MODE_ENROLL,
    MODE_LIST_DEVICES,
    MODE_AUDIO_TEST,
    MODE_DUMP_CONFIG
};

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
"      --enroll          generate a CSR and wait for the sysop to sign it\n"
"      --list-devices    list audio input and output devices, then exit\n"
"      --audio-test      loop the microphone back to the speaker, then exit\n"
"      --dump-config     print every setting with its resolved value\n"
"      --ascii           draw the TUI with ASCII only (same as unicode = off)\n"
"  -V, --version         print the version and exit\n"
"  -h, --help            this help\n"
"\n"
"Keys (in the TUI):\n"
"  left/right  switch talkgroup      up     lock/unlock talkgroup\n"
"  space       transmit (toggle)     ESC    stop transmitting\n"
"  m mute   d devices   l log   r reconnect   ? help   q quit\n"
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

    if (verbose) log_set_level(LOG_DBG);

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
        if (config_validate(&cfg, 1) != 0) return 1;
        int rc = enroll_run(&cfg, 30);
        return rc == 0 ? 0 : (rc > 0 ? 1 : 2);
    }

    case MODE_LIST_DEVICES:
    case MODE_AUDIO_TEST:
        fprintf(stderr, "svxconnect: audio is not implemented yet (milestone M3)\n");
        return 69;

    case MODE_HEADLESS:
        if (config_validate(&cfg, 0) != 0) {
            fprintf(stderr, "\nsvxconnect: fix the configuration and try again.\n"
                            "            Start from the example: %s\n",
                    "https://github.com/Guru-RF/SVXConnect-CLI/blob/main/example.conf");
            return 1;
        }
        return run_headless(&cfg, no_tx);

    case MODE_TUI:
    default:
        if (config_validate(&cfg, 0) != 0) {
            fprintf(stderr, "\nsvxconnect: fix the configuration and try again.\n"
                            "            Start from the example: %s\n",
                    "https://github.com/Guru-RF/SVXConnect-CLI/blob/main/example.conf");
            return 1;
        }
        fprintf(stderr, "svxconnect: the interface is not implemented yet "
                        "(milestone M7). Use --headless for now.\n");
        return 69;
    }
}
