/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — Copyright (C) 2026 Joeri Van Dooren
 */
#ifndef SVX_ENROLL_H
#define SVX_ENROLL_H

#include "common/config.h"

/* Obtain a signed client certificate from the reflector.
 *
 * Generates an RSA-2048 key and a CSR (reusing them if they already exist —
 * never regenerate, or the sysop ends up looking at a different request than
 * the one they were about to sign), sends the CSR, and waits.
 *
 * Signing is a human action: the reflector sysop has to look at the request
 * and approve it. That can take minutes or days, so this retries every
 * `retry_seconds` and is safe to interrupt and re-run — progress is on disk.
 *
 * Returns 0 once the certificate is stored, 1 if interrupted while still
 * waiting, and -1 on an unrecoverable error. */
int enroll_run(const svx_config *cfg, int retry_seconds);

#endif
