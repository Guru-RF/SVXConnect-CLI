/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * A fake reflector for the connection tests: a loopback listener on its own
 * thread that plays one of a few scripted parts — silent, stalling the TLS
 * handshake, or logging the client in and then misbehaving in a chosen way.
 * It speaks just enough of the protocol to get a real rc_client to
 * RC_CONNECTED.
 */
#ifndef SVX_FAKEREFL_H
#define SVX_FAKEREFL_H

#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <openssl/ssl.h>

typedef enum {
    FR_SILENT = 0,      /* accept, read, never answer                           */
    FR_STALL_TLS,       /* answer ProtoVer with StartEncryption, then no TLS    */
    FR_LOGIN            /* complete the login, then do `after`                  */
} fr_mode;

typedef enum {
    FR_HOLD = 0,        /* read and answer nothing, keep the connection open    */
    FR_ERROR_NOTIFY,    /* send MsgError, then TLS close_notify and close        */
    FR_ERROR_EOF,       /* send MsgError, then close the socket (no close_notify)*/
    FR_RESET            /* abort the connection with an RST                     */
} fr_after;

typedef struct {
    fr_mode      mode;
    fr_after     after;
    const char  *error_text;          /* for FR_ERROR_*                        */

    int          port;
    int          lfd;
    SSL_CTX     *ctx;
    pthread_t    th;
    atomic_int   stop;
    atomic_int   accepts;             /* connections accepted so far           */
    atomic_int   logged_in;           /* logins completed                      */
    _Atomic uint64_t client_gone_at;  /* now_ms() when the client's socket closed */
} fakerefl;

/* Write a throwaway key + self-signed certificate for `callsign` into `dir`,
 * the layout the client expects in its pki_dir. Returns 0 on success. */
int  fr_make_pki(const char *dir, const char *callsign);

/* Start listening on 127.0.0.1 (an ephemeral port, in f->port). `pki_dir`
 * holds the certificate the server presents. */
int  fr_start(fakerefl *f, fr_mode mode, fr_after after, const char *pki_dir,
              const char *callsign);
void fr_stop(fakerefl *f);

#endif
