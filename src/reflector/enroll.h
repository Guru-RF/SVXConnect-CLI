/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#ifndef SVX_ENROLL_H
#define SVX_ENROLL_H

#include <time.h>

#include "common/config.h"

/* Obtain a signed client certificate from the reflector, or check the one we
 * have.
 *
 * With no usable certificate (none yet, or an expired one) it generates an
 * RSA-2048 key and a CSR — reusing both if they exist: never regenerate, or the
 * sysop ends up looking at a different request than the one they were about to
 * sign — sends the CSR, and waits.
 *
 * With a certificate that is valid here it first asks the reflector, logging
 * in with it under the shared run lock (another client holding the lock is
 * left to do that itself). Accepted: done. Refused in the TLS handshake: a new
 * request with the same key, as above, never offering the refused certificate
 * again. No answer: nothing changes, and the log says it could not check.
 *
 * Signing is a human action: the reflector sysop has to look at the request
 * and approve it. That can take minutes or days, so this retries every
 * `retry_seconds` and is safe to interrupt and re-run — progress is on disk.
 *
 * Returns 0 when a certificate is in place — stored, accepted by the
 * reflector, or valid here and not checkable (unreachable, or another client
 * is connected); 1 if interrupted first, or when the reflector turned the
 * login away with an error; -1 on an unrecoverable error. */
int enroll_run(const svx_config *cfg, int retry_seconds);

/* 1 when the pki directory already holds a certificate that can log in: it
 * matches our key and has not expired. An expired one is NOT usable — it
 * needs a new request, made with the same key. */
int enroll_have_usable_cert(const svx_config *cfg, time_t now);

#endif
