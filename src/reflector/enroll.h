/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#ifndef SVX_ENROLL_H
#define SVX_ENROLL_H

#include <time.h>

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

/* 1 when the pki directory already holds a certificate that can log in: it
 * matches our key and has not expired. An expired one is NOT usable — it
 * needs a new request, made with the same key. */
int enroll_have_usable_cert(const svx_config *cfg, time_t now);

#endif
