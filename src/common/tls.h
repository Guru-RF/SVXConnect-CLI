/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * Non-blocking TLS for the reflector control channel.
 *
 * SvxBridge's version blocks and busy-spins on WANT_READ/WANT_WRITE, which is
 * fine for a daemon whose only job is the reflector but would stall a UI and
 * an audio pipeline. This version buffers in both directions and never blocks
 * after the handshake.
 *
 * The one trap worth stating explicitly: a single TLS record can carry several
 * protocol frames, and once OpenSSL has that record, poll() on the underlying
 * fd reports "nothing to read". A loop driven only by poll() therefore stalls
 * until the next server heartbeat happens to arrive. Callers MUST drain with
 *
 *     while (tls_pending(t)) { ...consume a frame... }
 *
 * after every tls_pump_in(), not just once.
 */
#ifndef SVX_TLS_H
#define SVX_TLS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <openssl/ssl.h>

typedef struct {
    SSL_CTX *ctx;              /* not owned; the caller frees it */
    SSL     *ssl;
    int      fd;
    int      handshake_done;

    uint8_t *in;               /* decrypted bytes not yet consumed */
    size_t   in_len, in_cap;

    uint8_t *out;              /* plaintext queued for encryption + send */
    size_t   out_len, out_cap;

    int      want_write;       /* SSL_write returned WANT_WRITE: arm POLLOUT */
    int      failed;
} tls_conn_t;

void tls_global_init(void);

/* Build an SSL_CTX. `ca_bundle_path` may be NULL. `cert_path`/`key_path` may
 * both be NULL for an unauthenticated context (used during enrolment, before
 * a certificate exists). Returns NULL on failure. */
SSL_CTX *tls_make_ctx(const char *ca_bundle_path,
                      const char *cert_path,
                      const char *key_path);

/* Wrap an existing connected fd and perform the handshake BLOCKING. The fd is
 * switched to non-blocking afterwards. Returns 0 on success.
 *
 * A blocking handshake is deliberate: it runs on the connect worker thread,
 * where blocking costs nothing, and a non-blocking SSL_connect state machine
 * is a lot of code that can only introduce bugs the blocking one cannot have. */
int tls_start(tls_conn_t *t, SSL_CTX *ctx, int fd);

/* Queue bytes for sending. Never blocks; grows the queue as needed.
 * Returns 0 on success, -1 only if the allocation failed. */
int tls_queue(tls_conn_t *t, const void *buf, size_t len);

/* Push as much of the queue as the socket will take.
 * Returns 0 on success (possibly with data still queued), -1 on a fatal error. */
int tls_flush(tls_conn_t *t);

/* Is there anything waiting to go out, or did SSL ask for writability? */
int tls_want_write(const tls_conn_t *t);

/* Read whatever is available into the inbound buffer.
 * Returns  1 when bytes were added, 0 when there was nothing to read,
 *         -1 on a closed connection or a fatal error. */
int tls_pump_in(tls_conn_t *t);

/* Bytes sitting in the inbound buffer. */
size_t tls_pending(const tls_conn_t *t);

/* Peek at the inbound buffer without consuming it. */
const uint8_t *tls_peek(const tls_conn_t *t, size_t *len);

/* Drop `n` bytes from the front of the inbound buffer. */
void tls_consume(tls_conn_t *t, size_t n);

/* Close and free everything except the SSL_CTX.
 *
 * Deliberately does NOT call SSL_shutdown(): sending close_notify confuses the
 * reflector, which then leaves the node registered until it times out. We drop
 * the TCP connection instead, which the server handles cleanly. */
void tls_close(tls_conn_t *t);

/* Last OpenSSL error as a string, for logging. */
const char *tls_last_error(void);

#endif
