/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — Copyright (C) 2026 Joeri Van Dooren
 *
 * The reflector connection, as seen by the rest of the program.
 *
 * Owns: the connect worker thread, the TLS control channel, the UDP audio
 * socket, both heartbeat timers and the reconnect backoff. Everything it
 * reports comes back through callbacks, which are always invoked on the main
 * thread from inside rc_service().
 *
 * Integration with a poll() loop:
 *
 *     struct pollfd p[8];
 *     int n = rc_poll_fds(rc, p, 8);
 *     poll(p, n, timeout);
 *     rc_service(rc, now_ms());
 *
 * rc_service() must be called every time round the loop even when poll()
 * returned nothing, because it also drives the timers.
 */
#ifndef SVX_RC_CLIENT_H
#define SVX_RC_CLIENT_H

#include <stdint.h>
#include <stddef.h>
#include <poll.h>

#include "common/config.h"

typedef enum {
    RC_IDLE = 0,     /* not connected and not trying                       */
    RC_CONNECTING,   /* worker thread is resolving / connecting / logging in */
    RC_CONNECTED,    /* logged in, audio can flow                          */
    RC_BACKOFF       /* waiting before the next attempt                    */
} rc_state;

const char *rc_state_name(rc_state s);

typedef struct {
    void *user;

    /* Every callback runs on the main thread, inside rc_service(). */
    void (*on_state)(void *u, rc_state st, const char *detail);
    void (*on_talker_start)(void *u, uint32_t tg, const char *callsign);
    void (*on_talker_stop) (void *u, uint32_t tg, const char *callsign);
    /* `gap` is how many datagrams were lost immediately before this one, so a
     * decoder can run that many concealment frames first. */
    void (*on_audio)(void *u, const uint8_t *opus, size_t len, int gap);
    void (*on_node)(void *u, int joined, const char *callsign);
    void (*on_flushed)(void *u);
    void (*on_error)(void *u, const char *msg);
} rc_callbacks;

typedef struct {
    uint64_t rx_packets, tx_packets;
    uint64_t rx_bytes,   tx_bytes;
    uint64_t rx_lost;             /* inferred from gaps in the GCM counter */
    uint64_t rx_replayed, rx_auth_fail;
    int      rx_pps, tx_pps;      /* refreshed once a second */
    double   loss_pct;
} rc_stats;

typedef struct rc_client rc_client;

/* `cfg` must outlive the client; it is not copied. */
rc_client *rc_new(const svx_config *cfg, const rc_callbacks *cb);
void       rc_free(rc_client *c);

/* Begin connecting. Harmless if already connected or connecting. */
void rc_start(rc_client *c);

/* Disconnect and stay down until rc_start() is called again. */
void rc_stop(rc_client *c, const char *reason);

/* Drop the current connection and reconnect immediately, resetting backoff. */
void rc_reconnect_now(rc_client *c);

/* Fill `p` with the descriptors to poll. Returns how many were written. */
int  rc_poll_fds(rc_client *c, struct pollfd *p, int max);

/* Do the work: read the control channel, drain UDP, run the timers, fire
 * callbacks, manage reconnection. */
void rc_service(rc_client *c, uint64_t now);

/* How long rc_service() would like to wait before it next has something to
 * do. Feed this into the poll() timeout. */
int  rc_next_timeout_ms(rc_client *c, uint64_t now);

/* ---- actions (no-ops unless connected) ---- */

/* Selecting a talkgroup RESETS the server's monitor set, so this always
 * re-sends the monitor list straight afterwards. Pass tg 0 for monitor-only. */
int rc_select_tg(rc_client *c, uint32_t tg);

/* Replace the monitored set. `ids` is sorted ascending by this call. */
int rc_set_monitor(rc_client *c, const uint32_t *ids, size_t n);

/* Send one encoded Opus frame. */
int rc_send_audio(rc_client *c, const uint8_t *opus, size_t len);

/* Tell the reflector a transmission has ended; without it the server waits
 * for an audio timeout and logs a complaint. */
int rc_send_flush(rc_client *c);

/* ---- accessors ---- */
rc_state    rc_get_state(const rc_client *c);
uint16_t    rc_client_id(const rc_client *c);
int         rc_node_count(const rc_client *c);
const char *rc_host(const rc_client *c);
uint16_t    rc_port(const rc_client *c);
uint32_t    rc_current_tg(const rc_client *c);
void        rc_get_stats(const rc_client *c, rc_stats *out);
const char *rc_last_error(const rc_client *c);

#endif
