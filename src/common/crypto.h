/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * AES-128-GCM with an 8-byte truncated tag — the SvxLink v3 UDP wire format.
 *
 * The byte layout here IS the protocol. Do not "clean it up": the asymmetry
 * between the TX and RX IV construction, and the extra client_id in the first
 * packet's AAD, are both real and both required.
 *
 *   wire   = [AAD][TAG(8)][CIPHERTEXT]
 *   TX IV  = tx_iv_rand[6] || client_id BE16 || counter BE32
 *   RX IV  = rx_iv_rand[6] || 0x00 0x00      || counter BE32
 *   TX AAD = counter BE32, or counter BE32 || client_id BE16 on the very
 *            first packet (with counter == 0)
 *   RX AAD = counter BE32
 */
#ifndef SVX_CRYPTO_H
#define SVX_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

typedef struct {
    /* TX */
    uint8_t  tx_iv_rand[6];
    uint8_t  tx_key[16];
    uint16_t client_id;
    uint32_t tx_counter;
    int      sent_initial;
    int      tx_exhausted;     /* counter 0xFFFFFFFF has been used */

    /* RX */
    uint8_t  rx_iv_rand[6];
    uint8_t  rx_key[16];
    int      rx_configured;
    uint32_t rx_high;          /* highest counter accepted so far */
    int      rx_have_high;

    /* Counters, for the status bar. */
    uint64_t n_replayed;       /* authenticated but non-monotonic: dropped */
    uint64_t n_auth_fail;      /* GCM tag mismatch: forged or corrupt */
} crypto_ctx_t;

void crypto_init(crypto_ctx_t *c);

/* Fresh random TX iv_rand + key, bound to the client id from MsgServerInfo. */
void crypto_gen_tx_params(crypto_ctx_t *c, uint16_t client_id);

/* RX parameters from the server's MsgStartUDPEncryption. */
void crypto_set_rx(crypto_ctx_t *c, const uint8_t iv_rand4[4], const uint8_t key[16]);

/* The server sent an empty MsgStartUDPEncryption: it will use our TX key to
 * talk back to us. Returns -1, configuring nothing, when our client id is 0:
 * the two directions' IVs differ only in the client-id bytes, so with id 0
 * both ends would encrypt under the same key with the same nonces. */
int  crypto_use_tx_for_rx(crypto_ctx_t *c);

/* Encrypt `plaintext` into `out`. Returns the wire length, or -1.
 * `out` needs at least pt_len + 12 bytes (pt_len + 14 for the first packet).
 * Also -1 once the 32-bit counter has been used up (crypto_tx_exhausted()):
 * wrapping it would repeat a nonce under the same key. */
ssize_t crypto_encrypt_wire(crypto_ctx_t *c,
                            const uint8_t *plaintext, size_t pt_len,
                            uint8_t *out, size_t out_cap);

/* Every counter value has been used under this key; reconnect for a new one.
 * (2^32 datagrams: years of continuous transmission on one connection.) */
int crypto_tx_exhausted(const crypto_ctx_t *c);

/* Decrypt a received datagram. Returns the plaintext length, or -1.
 *
 * `out_counter` receives the sender's counter, which is the only sequence
 * number the protocol gives us — the audio payload has none. It drives packet
 * loss concealment and the loss percentage. `out_gap` receives how many
 * datagrams appear to have been lost immediately before this one (0 when the
 * sequence is unbroken, and always 0 on the first packet).
 *
 * The datagram is AUTHENTICATED before any replay bookkeeping happens, so a
 * forged counter cannot influence the replay state — it fails the GCM tag
 * first. Acceptance is then strictly monotonic in the authenticated counter:
 * a replay or stale reorder returns -1 after bumping n_replayed. */
ssize_t crypto_decrypt_wire(crypto_ctx_t *c,
                            const uint8_t *wire, size_t wire_len,
                            uint8_t *out, size_t out_cap,
                            uint32_t *out_counter, int *out_gap);

#endif
