/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * The client certificate's lifecycle, as the connection sees it.
 *
 * svxreflector renews certificates by itself: once one is past 2/3 of its
 * lifetime it re-signs it and pushes the result as MsgClientCert to a client
 * that has stayed connected for about ten minutes — and then ignores
 * everything else on that session, so the client has to reconnect to carry
 * on. A certificate that has already expired cannot log in at all; the way
 * back is to connect WITHOUT one, answer the reflector's MsgClientCsrRequest
 * with a request made from the SAME key, and wait for the sysop to sign it.
 *
 * The login handshake, the live session and --enroll all go through here, so
 * they check, accept and report a certificate in exactly the same way.
 */
#ifndef SVX_CERT_H
#define SVX_CERT_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "common/config.h"
#include "common/pki.h"

typedef struct {
    pki_cert_status_t status;
    pki_cert_info_t   info;
    char              cert_path[1024];
    char              key_path[1024];
    char              csr_path[1024];
} cert_state;

/* Read our certificate from the pki directory and classify it. With `log`
 * set, also write one line saying how long it is valid and what happens next
 * — the handshake does that once per login. */
void cert_assess(const svx_config *cfg, time_t now, cert_state *out, int log);

/* Handle a MsgClientCert frame (`body` is the message after the length
 * prefix): validate the certificate and store it if it is good, logging the
 * outcome. Returns what happened. */
pki_push_result cert_handle_push(const svx_config *cfg,
                                 const uint8_t *body, size_t len, time_t now);

/* The banner to show for a certificate in this state, with the exact thing
 * to do about it. Returns 1 and fills `out` when there is something to say,
 * 0 when the certificate needs no attention. */
int cert_banner_text(const svx_config *cfg, const cert_state *st, time_t now,
                     char *out, size_t cap);

#endif
