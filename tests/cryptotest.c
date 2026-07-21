/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * Crypto fixtures — round-trip, and specifically the replay protection, since
 * that path handles attacker-controlled input from the network and a mistake
 * there is a security bug rather than a glitch.
 */
#include "common/crypto.h"

#include <stdio.h>
#include <string.h>

static int g_fail, g_run;

#define CHECK(cond, ...) do {                               \
    g_run++;                                                \
    if (!(cond)) { g_fail++; printf("  FAIL  " __VA_ARGS__);\
                   printf("\n        at %s:%d\n", __FILE__, __LINE__); } \
} while (0)

/* A pair of contexts wired so that A transmits and B receives with A's key.
 *
 * Two deliberate simplifications make a self-loopback model the receive path
 * faithfully. (1) client_id = 0: the TX IV carries the client id in bytes 6-7
 * where the RX IV carries zeros, so they only coincide at id 0 — on the real
 * wire the two ends are different peers that agree on this by protocol, and the
 * live parrot round-trip already exercises the id-bearing form. (2)
 * sent_initial = 1: the very first TX datagram uses a 6-byte AAD to advertise
 * the client id, which the plain receive path (4-byte AAD) does not expect;
 * skipping it means every packet here uses the steady-state framing, which is
 * exactly the path the replay logic lives on. */
static void link_pair(crypto_ctx_t *a, crypto_ctx_t *b) {
    crypto_init(a);
    crypto_init(b);
    crypto_gen_tx_params(a, 0);
    a->sent_initial = 1;
    b->rx_configured = 1;
    memcpy(b->rx_iv_rand, a->tx_iv_rand, 6);
    memcpy(b->rx_key,     a->tx_key,     16);
    b->rx_have_high = 0;
    b->rx_high = 0;
}

static ssize_t send_one(crypto_ctx_t *a, const char *msg, uint8_t *wire, size_t cap) {
    return crypto_encrypt_wire(a, (const uint8_t *)msg, strlen(msg), wire, cap);
}

static void t_roundtrip(void) {
    printf("crypto: a normal datagram decrypts to the original plaintext\n");
    crypto_ctx_t a, b;
    link_pair(&a, &b);

    uint8_t wire[256], pt[256];
    ssize_t wn = send_one(&a, "hello reflector", wire, sizeof(wire));
    CHECK(wn > 0, "encrypt failed");

    uint32_t ctr = 0; int gap = 0;
    ssize_t pn = crypto_decrypt_wire(&b, wire, (size_t)wn, pt, sizeof(pt), &ctr, &gap);
    CHECK(pn == 15, "decrypt length wrong: %zd", pn);
    CHECK(memcmp(pt, "hello reflector", 15) == 0, "plaintext mismatch");
    CHECK(gap == 0, "first packet should report no gap, got %d", gap);
}

static void t_gap_reported(void) {
    printf("crypto: a skipped counter is reported as a gap for concealment\n");
    crypto_ctx_t a, b;
    link_pair(&a, &b);

    uint8_t wire[4][256], pt[256];
    ssize_t wn[4];
    for (int i = 0; i < 4; i++) wn[i] = send_one(&a, "x", wire[i], sizeof(wire[i]));

    uint32_t ctr; int gap;
    crypto_decrypt_wire(&b, wire[0], (size_t)wn[0], pt, sizeof(pt), &ctr, &gap);
    /* deliver #0, skip #1 and #2, deliver #3 -> gap of 2 */
    ssize_t pn = crypto_decrypt_wire(&b, wire[3], (size_t)wn[3], pt, sizeof(pt), &ctr, &gap);
    CHECK(pn > 0, "packet 3 should decrypt");
    CHECK(gap == 2, "expected a gap of 2, got %d", gap);
}

static void t_exact_replay_rejected(void) {
    printf("crypto: re-injecting a captured datagram is rejected\n");
    crypto_ctx_t a, b;
    link_pair(&a, &b);

    uint8_t wire[256], pt[256];
    ssize_t wn = send_one(&a, "over", wire, sizeof(wire));

    uint32_t ctr; int gap;
    CHECK(crypto_decrypt_wire(&b, wire, (size_t)wn, pt, sizeof(pt), &ctr, &gap) > 0,
          "first delivery should succeed");
    /* The attacker captured `wire` and sends it again, byte for byte. */
    CHECK(crypto_decrypt_wire(&b, wire, (size_t)wn, pt, sizeof(pt), &ctr, &gap) < 0,
          "an exact replay must be rejected");
    CHECK(b.n_replayed == 1, "the replay should be counted, n_replayed=%llu",
          (unsigned long long)b.n_replayed);
}

static void t_forged_counter_cannot_disable_replay(void) {
    printf("crypto: a forged past-counter cannot disable replay protection\n");
    /* This is the exact attack the pre-authentication resync bug allowed:
     * inject a datagram whose counter is far below the high-water mark to trip
     * a "resync", clearing the replay state, then replay a captured packet. */
    crypto_ctx_t a, b;
    link_pair(&a, &b);

    uint8_t wire[8][256], pt[256];
    ssize_t wn[8];
    for (int i = 0; i < 8; i++) wn[i] = send_one(&a, "audio", wire[i], sizeof(wire[i]));

    uint32_t ctr; int gap;
    /* Receive several so the high-water mark is well above 0. */
    for (int i = 0; i < 6; i++)
        crypto_decrypt_wire(&b, wire[i], (size_t)wn[i], pt, sizeof(pt), &ctr, &gap);
    uint32_t high_before = b.rx_high;
    int      have_before = b.rx_have_high;

    /* Forge a datagram: take a real one and stamp a low counter into its AAD
     * (wire bytes 0..3). The ciphertext/tag no longer match the counter, so
     * this MUST be treated as garbage and change no replay state. */
    uint8_t forged[256];
    memcpy(forged, wire[6], (size_t)wn[6]);
    forged[0] = 0; forged[1] = 0; forged[2] = 0; forged[3] = 0;   /* counter = 0, far behind */

    ssize_t fn = crypto_decrypt_wire(&b, forged, (size_t)wn[6], pt, sizeof(pt), &ctr, &gap);
    CHECK(fn < 0, "a forged datagram must not decrypt");
    CHECK(b.n_auth_fail >= 1, "the forgery should count as an auth failure");
    CHECK(b.rx_have_high == have_before && b.rx_high == high_before,
          "a forged datagram must NOT touch the replay high-water mark "
          "(have %d->%d, high %u->%u)",
          have_before, b.rx_have_high, high_before, b.rx_high);

    /* Now the attacker replays a genuine early packet. With replay protection
     * intact it must still be rejected. */
    CHECK(crypto_decrypt_wire(&b, wire[0], (size_t)wn[0], pt, sizeof(pt), &ctr, &gap) < 0,
          "after a forgery attempt, replaying an old packet must still fail");
}

static void t_tamper_rejected(void) {
    printf("crypto: flipping a ciphertext bit is rejected\n");
    crypto_ctx_t a, b;
    link_pair(&a, &b);

    uint8_t wire[256], pt[256];
    ssize_t wn = send_one(&a, "confidential", wire, sizeof(wire));
    wire[wn - 1] ^= 0x01;   /* flip a bit in the last ciphertext byte */

    uint32_t ctr; int gap;
    CHECK(crypto_decrypt_wire(&b, wire, (size_t)wn, pt, sizeof(pt), &ctr, &gap) < 0,
          "tampered ciphertext must fail the tag check");
}

int main(void) {
    printf("\ncrypto fixtures\n\n");
    t_roundtrip();
    t_gap_reported();
    t_exact_replay_rejected();
    t_forged_counter_cannot_disable_replay();
    t_tamper_rejected();
    printf("\n%d checks, %d failed\n\n", g_run, g_fail);
    return g_fail ? 1 : 0;
}
