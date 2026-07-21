/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#ifndef SVX_HEADLESS_H
#define SVX_HEADLESS_H

#include "common/config.h"

/* Run the reflector client with no user interface, logging every event to
 * stdout. This is the mode that makes the protocol layer testable on its own,
 * and it is also what a systemd unit runs. Returns a process exit code. */
int run_headless(const svx_config *cfg, int no_tx);

#endif
