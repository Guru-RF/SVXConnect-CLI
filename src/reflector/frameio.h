/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — Copyright (C) 2026 Joeri Van Dooren
 *
 * Blocking, timeout-bounded framed message I/O, before and after the TLS
 * upgrade. Used by the two places that legitimately block: the connect
 * handshake (on its worker thread) and certificate enrolment (which is a
 * standalone mode with no UI to keep responsive).
 *
 * Nothing in the steady-state main loop uses these.
 */
#ifndef SVX_FRAMEIO_H
#define SVX_FRAMEIO_H

#include <stdint.h>
#include <stddef.h>
#include <signal.h>
#include <sys/types.h>

#include "common/tls.h"

/* ---- plain socket, before the TLS upgrade ---- */

int     fio_raw_send(int fd, const uint8_t *buf, size_t len);

/* Read one [u32 len][body] frame into `buf`. Returns the body length, or -1
 * (errno is ETIMEDOUT on timeout, ECONNRESET on a clean close). */
ssize_t fio_raw_recv_frame(int fd, uint8_t *buf, size_t cap, int timeout_ms,
                           volatile sig_atomic_t *abort_flag);

/* ---- after the TLS upgrade ---- */

int     fio_tls_send(tls_conn_t *t, const uint8_t *buf, size_t len);

/* As above, but driving the non-blocking TLS connection from poll(). Serves
 * frames already buffered inside OpenSSL before waiting on the socket. */
ssize_t fio_tls_recv_frame(tls_conn_t *t, uint8_t *buf, size_t cap,
                           int timeout_ms, volatile sig_atomic_t *abort_flag);

/* Send on whichever channel is live: TLS if it has been started, else the
 * raw fd. Lets the enrolment loop stay one flat switch statement across the
 * upgrade point. */
int     fio_send(tls_conn_t *t, int fd, const uint8_t *buf, size_t len);

/* Receive on whichever channel is live. */
ssize_t fio_recv_frame(tls_conn_t *t, int fd, uint8_t *buf, size_t cap,
                       int timeout_ms, volatile sig_atomic_t *abort_flag);

#endif
