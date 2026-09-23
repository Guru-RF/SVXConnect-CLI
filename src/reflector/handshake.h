/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * The reflector connect + login sequence.
 *
 * This runs BLOCKING, on a worker thread. That is deliberate. The sequence is
 * strictly ordered request/response with three nested wait loops, and it is
 * the single place where a subtle reordering produces a connection that looks
 * fine and then silently carries no audio. Rewriting it as a non-blocking
 * state machine would buy nothing but risk, so instead the blocking version is
 * kept close to the shape that is known to work and the cost — a thread that
 * lives for a second or two — is paid without complaint.
 */
#ifndef SVX_HANDSHAKE_H
#define SVX_HANDSHAKE_H

#include <stdint.h>
#include <stdatomic.h>
#include <netinet/in.h>

#include "common/config.h"
#include "common/tls.h"
#include "common/crypto.h"

typedef struct {
    int                 tcp_fd;
    tls_conn_t          tls;
    SSL_CTX            *ssl_ctx;
    int                 udp_fd;
    struct sockaddr_in  udp_remote;
    crypto_ctx_t        crypto;

    uint16_t            client_id;
    int                 node_count;
    int                 have_opus;

    char                host[256];    /* what we actually connected to */
    uint16_t            port;

    char                err[256];     /* human-readable failure reason */
} handshake_result;

/* Resolve, connect, negotiate TLS, authenticate, set up UDP encryption.
 *
 * Returns 0 on success, with every field of *out populated and owned by the
 * caller. On failure returns -1, out->err explains why, and nothing needs
 * freeing. Set *abort_flag from another thread to give up early: every wait
 * after name resolution notices it within about 100 ms.
 */
int handshake_run(const svx_config *cfg, handshake_result *out,
                  const atomic_int *abort_flag);

/* Release everything a successful handshake_run() produced. */
void handshake_release(handshake_result *r);

#endif
