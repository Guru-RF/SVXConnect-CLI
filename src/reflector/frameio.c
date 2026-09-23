/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "frameio.h"

#include "common/log.h"
#include "common/util.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>

/* ------------------------------------------------------------ plain fd */

/* Wait for `events` on `fd` until `deadline`, in slices so that an abort
 * is noticed promptly. Returns 1 when ready, -1 with errno set otherwise. */
static int wait_fd(int fd, short events, uint64_t deadline, const atomic_int *abort_flag) {
    for (;;) {
        if (abort_flag && atomic_load(abort_flag)) { errno = ECANCELED; return -1; }

        uint64_t now = now_ms();
        if (now >= deadline) { errno = ETIMEDOUT; return -1; }

        uint64_t left = deadline - now;
        struct pollfd pf = { .fd = fd, .events = events };
        int pr = poll(&pf, 1, (int)(left < FIO_SLICE_MS ? left : FIO_SLICE_MS));
        if (pr < 0) { if (errno == EINTR) continue; return -1; }
        if (pr > 0) return 1;
    }
}

int fio_raw_send(int fd, const uint8_t *p, size_t len) {
    uint64_t deadline = now_ms() + FIO_SEND_MS;
    while (len > 0) {
        ssize_t n = send(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (wait_fd(fd, POLLOUT, deadline, NULL) < 0) return -1;
                continue;
            }
            return -1;
        }
        if (n == 0) return -1;
        p += n; len -= (size_t)n;
    }
    return 0;
}

static int raw_recv_all(int fd, uint8_t *p, size_t len, uint64_t deadline,
                        const atomic_int *abort_flag) {
    while (len > 0) {
        if (wait_fd(fd, POLLIN, deadline, abort_flag) < 0) return -1;

        ssize_t n = recv(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return -1;
        }
        if (n == 0) { errno = ECONNRESET; return -1; }
        p += n; len -= (size_t)n;
    }
    return 0;
}

ssize_t fio_raw_recv_frame(int fd, uint8_t *buf, size_t cap, int timeout_ms,
                           const atomic_int *abort_flag) {
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;

    uint8_t hdr[4];
    if (raw_recv_all(fd, hdr, 4, deadline, abort_flag) != 0) return -1;

    uint32_t L = be_get_u32(hdr);
    if (L > cap) { errno = EMSGSIZE; return -1; }
    if (L == 0) return 0;

    if (raw_recv_all(fd, buf, L, deadline, abort_flag) != 0) return -1;
    return (ssize_t)L;
}

/* ---------------------------------------------------------------- TLS */

int fio_tls_send(tls_conn_t *t, const uint8_t *buf, size_t len) {
    if (tls_queue(t, buf, len) != 0) return -1;
    return tls_flush(t);
}

ssize_t fio_tls_recv_frame(tls_conn_t *t, uint8_t *buf, size_t cap,
                           int timeout_ms, const atomic_int *abort_flag) {
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;

    for (;;) {
        /* Serve from what OpenSSL already handed us before touching poll() —
         * a single TLS record routinely carries several protocol frames, and
         * poll() reports the socket as quiet while they are still buffered. */
        size_t         have = 0;
        const uint8_t *p    = tls_peek(t, &have);
        if (have >= 4) {
            uint32_t L = be_get_u32(p);
            if (L > cap) { errno = EMSGSIZE; return -1; }
            if (have >= 4 + (size_t)L) {
                memcpy(buf, p + 4, L);
                tls_consume(t, 4 + (size_t)L);
                return (ssize_t)L;
            }
        }

        /* The peer hung up after its last complete frame (served above). */
        if (tls_failed(t)) { errno = ECONNRESET; return -1; }

        if (abort_flag && atomic_load(abort_flag)) { errno = ECANCELED; return -1; }
        uint64_t now = now_ms();
        if (now >= deadline) { errno = ETIMEDOUT; return -1; }

        if (tls_flush(t) != 0) return -1;

        uint64_t left = deadline - now;
        struct pollfd pf = {
            .fd     = t->fd,
            .events = (short)(POLLIN | (tls_want_write(t) ? POLLOUT : 0))
        };
        int pr = poll(&pf, 1, (int)(left < FIO_SLICE_MS ? left : FIO_SLICE_MS));
        if (pr < 0) { if (errno == EINTR) continue; return -1; }
        if (pr == 0) continue;                 /* re-check abort and deadline */

        if (pf.revents & POLLOUT) { if (tls_flush(t) != 0) return -1; }
        if (pf.revents & (POLLIN | POLLHUP | POLLERR)) {
            if (tls_pump_in(t) < 0) { errno = ECONNRESET; return -1; }
        }
    }
}

/* ----------------------------------------------------------- whichever */

int fio_send(tls_conn_t *t, int fd, const uint8_t *buf, size_t len) {
    if (t && t->ssl) return fio_tls_send(t, buf, len);
    return fio_raw_send(fd, buf, len);
}

ssize_t fio_recv_frame(tls_conn_t *t, int fd, uint8_t *buf, size_t cap,
                       int timeout_ms, const atomic_int *abort_flag) {
    if (t && t->ssl) return fio_tls_recv_frame(t, buf, cap, timeout_ms, abort_flag);
    return fio_raw_recv_frame(fd, buf, cap, timeout_ms, abort_flag);
}
