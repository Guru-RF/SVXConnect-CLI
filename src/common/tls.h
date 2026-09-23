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
#include <stdatomic.h>
#include <sys/types.h>
#include <openssl/ssl.h>

/* Why a connection stopped working. The caller logs this at info level, so a
 * reflector that hangs up can be told from a path that died or a TLS alert —
 * they call for different remedies and used to read identically. */
typedef enum {
    TLS_CLOSE_NONE = 0,    /* still open                                        */
    TLS_CLOSE_NOTIFY,      /* the peer sent a TLS close_notify                  */
    TLS_CLOSE_EOF,         /* TCP FIN with no close_notify                      */
    TLS_CLOSE_RESET,       /* ECONNRESET: the peer or a middlebox aborted it    */
    TLS_CLOSE_NETWORK,     /* another socket error: ETIMEDOUT, EHOSTUNREACH ... */
    TLS_CLOSE_ALERT,       /* a TLS alert or protocol error                     */
    TLS_CLOSE_LOCAL        /* our own limit or an allocation failed             */
} tls_close_kind;

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

    tls_close_kind close_kind; /* set together with `failed`                   */
    char           close_detail[160];   /* errno text or OpenSSL reason     */
} tls_conn_t;

void tls_global_init(void);

/* Build an SSL_CTX. `ca_bundle_path` may be NULL. `cert_path`/`key_path` may
 * both be NULL for an unauthenticated context (used during enrolment, before
 * a certificate exists). Returns NULL on failure. */
SSL_CTX *tls_make_ctx(const char *ca_bundle_path,
                      const char *cert_path,
                      const char *key_path);

/* Wrap an existing connected fd and perform the handshake. Returns 0 on
 * success; the fd is left non-blocking either way.
 *
 * The call blocks the calling thread (the connect worker, or --enroll) until
 * the handshake completes, but never longer than `timeout_ms`, and it gives up
 * within about 100 ms of `*abort_flag` becoming non-zero. A server that
 * answers StartEncryption and then never speaks TLS used to hold SSL_connect()
 * — and whoever waited for it — forever. On failure errno is ETIMEDOUT,
 * ECANCELED, or EPROTO for a handshake the peer refused. */
int tls_start_ex(tls_conn_t *t, SSL_CTX *ctx, int fd, int timeout_ms,
                 const atomic_int *abort_flag);

/* tls_start_ex() with a 15 s limit and no abort flag. */
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
 *         -1 on a closed connection or a fatal error.
 *
 * A peer that sends a last message and hangs up delivers both in one go —
 * the reflector does exactly that with MsgError. So when the connection ends
 * after new bytes arrived, this returns 1, keeps the bytes, and records the
 * end in tls_failed()/close_kind; the next call returns -1. Callers drain the
 * frames first and then check tls_failed(). */
int tls_pump_in(tls_conn_t *t);

/* Non-zero once the connection is unusable; close_kind says why. */
int tls_failed(const tls_conn_t *t);

/* close_kind and close_detail as one short phrase, e.g. "TLS close_notify",
 * "ECONNRESET" or "TLS error: sslv3 alert certificate expired". Writes into
 * `buf` and returns it. */
const char *tls_close_describe(const tls_conn_t *t, char *buf, size_t cap);

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

/* Last OpenSSL error as a string, for logging. The buffer is per thread. */
const char *tls_last_error(void);

#endif
