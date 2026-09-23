/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * A reflector client that is always "connected" and sends nothing anywhere:
 * enough for app.c to key up, with a count of the audio it would have sent.
 */
#include "fakes.h"

#include <stdlib.h>

struct rc_client {
    rc_callbacks cb;
};

static rc_client *g_rc;
static rc_state   g_state = RC_CONNECTED;
static uint64_t   g_audio;

void     stub_rc_set_state(rc_state st) { g_state = st; }
uint64_t stub_rc_audio_sent(void)       { return g_audio; }

void stub_rc_talker_start(uint32_t tg, const char *call) {
    if (g_rc && g_rc->cb.on_talker_start) g_rc->cb.on_talker_start(g_rc->cb.user, tg, call);
}

const char *rc_state_name(rc_state s) {
    switch (s) {
    case RC_IDLE:       return "idle";
    case RC_CONNECTING: return "connecting";
    case RC_CONNECTED:  return "connected";
    case RC_BACKOFF:    return "reconnecting";
    default:            return "?";
    }
}

rc_client *rc_new(const svx_config *cfg, const rc_callbacks *cb) {
    (void)cfg;
    g_rc = calloc(1, sizeof(*g_rc));
    g_rc->cb = *cb;
    return g_rc;
}

void rc_free(rc_client *c)                          { if (c == g_rc) g_rc = NULL; free(c); }
void rc_start(rc_client *c)                         { (void)c; }
void rc_stop(rc_client *c, const char *reason)      { (void)c; (void)reason; }
void rc_reconnect_now(rc_client *c)                 { (void)c; }
int  rc_poll_fds(rc_client *c, struct pollfd *p, int max) { (void)c; (void)p; (void)max; return 0; }
void rc_service(rc_client *c, uint64_t now)         { (void)c; (void)now; }
int  rc_next_timeout_ms(rc_client *c, uint64_t now) { (void)c; (void)now; return 1000; }
int  rc_select_tg(rc_client *c, uint32_t tg)        { (void)c; (void)tg; return 0; }
int  rc_set_monitor(rc_client *c, const uint32_t *ids, size_t n) { (void)c; (void)ids; (void)n; return 0; }
int  rc_send_audio(rc_client *c, const uint8_t *opus, size_t len) { (void)c; (void)opus; (void)len; g_audio++; return 0; }
int  rc_send_flush(rc_client *c)                    { (void)c; return 0; }
rc_state    rc_get_state(const rc_client *c)        { (void)c; return g_state; }
uint16_t    rc_client_id(const rc_client *c)        { (void)c; return 1; }
int         rc_node_count(const rc_client *c)       { (void)c; return 0; }
const char *rc_host(const rc_client *c)             { (void)c; return "stub"; }
uint16_t    rc_port(const rc_client *c)             { (void)c; return 0; }
uint32_t    rc_current_tg(const rc_client *c)       { (void)c; return 0; }
void        rc_get_stats(const rc_client *c, rc_stats *out) { (void)c; *out = (rc_stats){0}; }
const char *rc_last_error(const rc_client *c)       { (void)c; return ""; }
