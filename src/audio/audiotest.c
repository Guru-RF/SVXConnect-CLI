/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — Copyright (C) 2026 Joeri Van Dooren
 */
#include "audiotest.h"
#include "dev.h"

#include "common/log.h"
#include "common/ring.h"
#include "common/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop;
static void on_signal(int s) { (void)s; g_stop = 1; }

/* ------------------------------------------------------ list-devices */

static void print_list(int capture, const char *want) {
    svx_devinfo devs[64];
    int n = svx_audio_list(capture, devs, 64);

    printf("%s devices:\n", capture ? "Input (microphone)" : "Output (speaker)");
    if (n <= 0) {
        printf("  (none found)\n\n");
        return;
    }

    svx_devinfo chosen;
    int exact = svx_audio_resolve(capture, want, &chosen);

    /* Exactly one row gets the marker. The backend can report isDefault on
     * more than one device (CoreAudio does, when several are plausible
     * defaults), and marking them all would suggest we open all of them. */
    int chosen_idx = -1;
    if (exact) {
        for (int i = 0; i < n; i++)
            if (strcmp(devs[i].id, chosen.id) == 0) { chosen_idx = i; break; }
    }
    if (chosen_idx < 0) {
        for (int i = 0; i < n; i++) if (devs[i].is_default) { chosen_idx = i; break; }
    }
    if (chosen_idx < 0) chosen_idx = 0;

    for (int i = 0; i < n; i++) {
        printf("  %s %-40s %s\n",
               i == chosen_idx ? "*" : " ",
               devs[i].name,
               devs[i].is_default ? "[default]" : "");
        if (devs[i].id[0]) printf("      id: %s\n", devs[i].id);
    }
    printf("\n  * = what this configuration selects (%s = %s)\n\n",
           capture ? "input_device" : "output_device",
           (want && *want) ? want : "default");
}

int audio_list_devices(const svx_config *cfg) {
    if (svx_audio_init() != 0) return 1;

    printf("Audio backend: %s\n\n", svx_audio_backend_name());
    print_list(1, cfg->input_device);
    print_list(0, cfg->output_device);

#if defined(__APPLE__)
    svx_mic_state m = svx_mic_status();
    printf("Microphone permission: %s\n",
           m == SVX_MIC_GRANTED ? "granted"
         : m == SVX_MIC_DENIED  ? "DENIED — see docs/TCC.md"
                                : "not yet requested");
#endif

    svx_audio_term();
    return 0;
}

/* -------------------------------------------------------- audio-test */

static void draw_meter(const char *label, float level) {
    /* 0.0 .. 1.0 mapped over a 30-column bar. */
    int filled = (int)(level * 30.0f + 0.5f);
    if (filled > 30) filled = 30;
    if (filled < 0)  filled = 0;

    char bar[64];
    for (int i = 0; i < 30; i++) bar[i] = i < filled ? '#' : '.';
    bar[30] = '\0';
    printf("  %s [%s] %5.1f%%", label, bar, (double)(level * 100.0f));
}

int audio_run_test(const svx_config *cfg) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (svx_audio_init() != 0) return 1;

#if defined(__APPLE__)
    /* Ask before anything else, so the system dialog and our explanation of
     * it are both plainly visible on a normal terminal. */
    svx_mic_state m = svx_mic_status();
    if (m == SVX_MIC_UNDETERMINED) {
        printf("macOS is about to ask your terminal for microphone access.\n"
               "The dialog will name your terminal application, not SVXConnect.\n"
               "That is normal — see docs/TCC.md.\n\n");
        fflush(stdout);
        m = svx_mic_request(60000);
    }
    if (m == SVX_MIC_DENIED) {
        fprintf(stderr,
            "svxconnect: microphone access denied.\n"
            "  Open:  System Settings > Privacy & Security > Microphone\n"
            "  and enable your terminal application.\n"
            "  Shortcut: open \"x-apple.systempreferences:"
            "com.apple.preference.security?Privacy_Microphone\"\n"
            "  Re-prompt: tccutil reset Microphone com.apple.Terminal\n"
            "  Microphone capture is not available over SSH.\n");
        svx_audio_term();
        return 3;
    }
#endif

    /* One ring, written by the capture thread and read by the playback thread.
     * That is two different realtime threads, but still exactly one producer
     * and one consumer, which is what the ring requires. */
    svx_ring loop;
    if (svx_ring_init(&loop, 16384) != 0) { svx_audio_term(); return 1; }

    _Atomic float mic_peak = 0.0f, spk_peak = 0.0f;

    svx_devinfo in_dev, out_dev;
    svx_audio_resolve(1, cfg->input_device,  &in_dev);
    svx_audio_resolve(0, cfg->output_device, &out_dev);

    svx_dev *cap = svx_dev_open_capture (in_dev.id,  &loop, &mic_peak);
    svx_dev *pb  = svx_dev_open_playback(out_dev.id, &loop, &spk_peak);
    if (!cap || !pb) {
        svx_dev_close(cap); svx_dev_close(pb);
        svx_ring_free(&loop); svx_audio_term();
        return 1;
    }

    printf("Loopback test — you should hear yourself with a short delay.\n");
    printf("  input:  %s\n", svx_dev_name(cap));
    printf("  output: %s\n", svx_dev_name(pb));
    printf("  backend: %s, %d Hz mono\n\n", svx_audio_backend_name(), SVX_RATE);
    printf("Speak into the microphone. Ctrl-C to stop.\n\n");
    fflush(stdout);

    /* Pre-load the ring with silence so playback has something to chew on and
     * the delay is deliberate rather than a permanent underrun. */
    {
        int16_t zeros[3200];              /* 200 ms */
        memset(zeros, 0, sizeof(zeros));
        svx_ring_write(&loop, zeros, 3200);
    }

    svx_dev_reset_silence(cap);
    if (svx_dev_start(cap) != 0 || svx_dev_start(pb) != 0) {
        svx_dev_close(cap); svx_dev_close(pb);
        svx_ring_free(&loop); svx_audio_term();
        return 1;
    }

    uint64_t start        = now_ms();
    int      warned_quiet = 0;
    /* Redrawing in place needs a terminal. Piped to a file or a pipe, the
     * carriage returns would produce one enormous line, so slow right down
     * and print discrete rows instead. */
    int      tty          = isatty(STDOUT_FILENO);
    uint64_t last_line    = 0;

    while (!g_stop) {
        msleep(66);                        /* ~15 Hz refresh */

        float mp = atomic_load_explicit(&mic_peak, memory_order_relaxed);
        float sp = atomic_load_explicit(&spk_peak, memory_order_relaxed);

        if (tty || now_ms() - last_line >= 1000) {
            last_line = now_ms();
            printf("\r");
            draw_meter("MIC", mp);
            draw_meter("  SPK", sp);
            printf("   buf %4u ms  ", svx_ring_avail(&loop) * 1000 / SVX_RATE);
            if (!tty) printf("\n");
            fflush(stdout);
        }

        /* The silent-microphone trap. A real one always dithers by at least a
         * least-significant bit; perfect zeros for two seconds means the OS is
         * feeding us silence and not saying so. */
        if (!warned_quiet && now_ms() - start > 2000 && !svx_dev_saw_nonsilence(cap)) {
            warned_quiet = 1;
            printf("\n\n");
#if defined(__APPLE__)
            printf("!! The microphone has delivered nothing but digital silence for 2 s.\n"
                   "   macOS does this when your terminal application was denied\n"
                   "   microphone access — with no error and no prompt.\n"
                   "   Fix: System Settings > Privacy & Security > Microphone,\n"
                   "        enable your terminal, then run this again.\n"
                   "   See docs/TCC.md.\n\n");
#else
            printf("!! The microphone has delivered nothing but digital silence for 2 s.\n"
                   "   Check that the right input device is selected and not muted\n"
                   "   (svxconnect --list-devices).\n\n");
#endif
            fflush(stdout);
        }

        svx_dev_event ev = svx_dev_poll_event(cap);
        if (ev == SVX_DEV_LOST || ev == SVX_DEV_STOPPED) {
            printf("\n\nThe input device went away.\n");
            break;
        }
    }

    printf("\n\n");
    printf("stopped after %llu s — capture overruns %u, playback underruns %u\n",
           (unsigned long long)((now_ms() - start) / 1000),
           svx_dev_overruns(cap), svx_dev_underruns(pb));

    svx_dev_close(cap);
    svx_dev_close(pb);
    svx_ring_free(&loop);
    svx_audio_term();
    return 0;
}
