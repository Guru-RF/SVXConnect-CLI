/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "crypto.h"
#include "util.h"
#include "log.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

void crypto_init(crypto_ctx_t *c) {
    memset(c, 0, sizeof(*c));
}

void crypto_gen_tx_params(crypto_ctx_t *c, uint16_t client_id) {
    RAND_bytes(c->tx_iv_rand, sizeof(c->tx_iv_rand));
    RAND_bytes(c->tx_key,     sizeof(c->tx_key));
    c->client_id    = client_id;
    c->tx_counter   = 0;
    c->sent_initial = 0;
}

void crypto_set_rx(crypto_ctx_t *c, const uint8_t iv_rand4[4], const uint8_t key[16]) {
    /* The server sends only 4 IV bytes. The remaining two of the six-byte
     * field stay zero, and decrypt then appends another two zeros where the
     * TX direction puts the client id. */
    memset(c->rx_iv_rand, 0, sizeof(c->rx_iv_rand));
    memcpy(c->rx_iv_rand, iv_rand4, 4);
    memcpy(c->rx_key, key, 16);
    c->rx_configured = 1;
    c->rx_have_high  = 0;
    c->rx_high       = 0;
}

void crypto_use_tx_for_rx(crypto_ctx_t *c) {
    memcpy(c->rx_iv_rand, c->tx_iv_rand, sizeof(c->rx_iv_rand));
    memcpy(c->rx_key,     c->tx_key,     sizeof(c->rx_key));
    c->rx_configured = 1;
    c->rx_have_high  = 0;
    c->rx_high       = 0;
}

/* ------------------------------------------------------------ GCM core */

static int aes_gcm_encrypt(const uint8_t *key, const uint8_t *iv, int iv_len,
                           const uint8_t *aad, int aad_len,
                           const uint8_t *pt, int pt_len,
                           uint8_t *ct, int *ct_len,
                           uint8_t *tag, int tag_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0, total = 0, rc = -1;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) goto end;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) goto end;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) goto end;
    if (aad_len && !EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) goto end;
    if (pt_len  && !EVP_EncryptUpdate(ctx, ct,   &len, pt,  pt_len))  goto end;
    total = len;
    if (!EVP_EncryptFinal_ex(ctx, ct + total, &len)) goto end;
    total += len;
    *ct_len = total;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag)) goto end;
    rc = 0;
end:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

static int aes_gcm_decrypt(const uint8_t *key, const uint8_t *iv, int iv_len,
                           const uint8_t *aad, int aad_len,
                           const uint8_t *ct, int ct_len,
                           const uint8_t *tag, int tag_len,
                           uint8_t *pt, int *pt_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0, total = 0, rc = -1;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) goto end;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) goto end;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) goto end;
    if (aad_len && !EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) goto end;
    if (ct_len  && !EVP_DecryptUpdate(ctx, pt,  &len, ct,  ct_len))   goto end;
    total = len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, (void *)tag)) goto end;
    if (EVP_DecryptFinal_ex(ctx, pt + total, &len) <= 0) goto end;
    total += len;
    *pt_len = total;
    rc = 0;
end:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

/* ---------------------------------------------------------------- wire */

ssize_t crypto_encrypt_wire(crypto_ctx_t *c,
                            const uint8_t *plaintext, size_t pt_len,
                            uint8_t *out, size_t out_cap) {
    int      initial = !c->sent_initial;
    uint32_t counter = initial ? 0 : c->tx_counter;

    uint8_t iv[12];
    memcpy(iv, c->tx_iv_rand, 6);
    be_put_u16(iv + 6, c->client_id);
    be_put_u32(iv + 8, counter);

    /* The first datagram carries the client id in the AAD as well — that is
     * how the server learns which client this UDP flow belongs to. */
    uint8_t aad[6];
    be_put_u32(aad, counter);
    int aad_len = 4;
    if (initial) {
        be_put_u16(aad + 4, c->client_id);
        aad_len = 6;
    }

    size_t need = (size_t)aad_len + 8 + pt_len;
    if (need > out_cap) return -1;

    memcpy(out, aad, (size_t)aad_len);
    uint8_t *tag = out + aad_len;
    uint8_t *ct  = out + aad_len + 8;

    uint8_t tag16[16];
    int     ct_len = 0;
    if (aes_gcm_encrypt(c->tx_key, iv, 12, aad, aad_len,
                        plaintext, (int)pt_len, ct, &ct_len, tag16, 16) < 0)
        return -1;
    memcpy(tag, tag16, 8);      /* the wire carries a truncated tag */

    if (initial) { c->tx_counter = 1; c->sent_initial = 1; }
    else         { c->tx_counter += 1; }

    return (ssize_t)((size_t)aad_len + 8 + (size_t)ct_len);
}

ssize_t crypto_decrypt_wire(crypto_ctx_t *c,
                            const uint8_t *wire, size_t wire_len,
                            uint8_t *out, size_t out_cap,
                            uint32_t *out_counter, int *out_gap) {
    if (out_counter) *out_counter = 0;
    if (out_gap)     *out_gap     = 0;

    if (!c->rx_configured) return -1;
    if (wire_len < 4 + 8)  return -1;

    const uint8_t *aad     = wire;          /* AAD is the 4-byte counter */
    uint32_t       counter = be_get_u32(aad);
    const uint8_t *tag     = wire + 4;
    const uint8_t *ct      = wire + 12;
    size_t         ct_len  = wire_len - 12;

    if (ct_len > out_cap) return -1;

    /* AUTHENTICATE FIRST, then decide about replay — never the other way round.
     *
     * The counter is authenticated (it is the GCM AAD), so an attacker cannot
     * forge one: changing the counter changes the AAD and the tag check fails
     * here. Doing any replay bookkeeping before this point lets an unauth'd
     * attacker drive that bookkeeping with a made-up counter. An earlier
     * version cleared the replay high-water mark on a "resync" branch before
     * this check, which let a spoofed past-window counter DISABLE replay
     * protection and then replay captured audio. */
    uint8_t iv[12];
    memcpy(iv, c->rx_iv_rand, 6);
    iv[6] = 0; iv[7] = 0;
    be_put_u32(iv + 8, counter);

    int pt_len = 0;
    if (aes_gcm_decrypt(c->rx_key, iv, 12, aad, 4, ct, (int)ct_len,
                        tag, 8, out, &pt_len) < 0) {
        c->n_auth_fail++;
        return -1;                       /* forged or corrupt: no state change */
    }

    /* Authenticated. Now enforce strict monotonicity.
     *
     * The RX key is fixed for the whole connection (crypto_set_rx resets this
     * state once, at MsgStartUDPEncryption) and the server's counter only ever
     * increases within a connection, so a counter that is not strictly greater
     * than the last accepted one is a replay or a stale reorder — never a
     * legitimate reset. Drop it. There is deliberately no "resync backwards"
     * path: it could be driven by replaying an old authenticated packet. A
     * genuine server restart brings a new key and a fresh crypto_set_rx. */
    int gap = 0;
    if (c->rx_have_high) {
        if (counter <= c->rx_high) {
            c->n_replayed++;
            return -1;                   /* replay or stale reorder: drop */
        }
        uint32_t ahead = counter - c->rx_high - 1;   /* apparent loss before this */
        gap = ahead > 16 ? 16 : (int)ahead;          /* cap: conceal a few, not billions */
    }

    c->rx_high      = counter;
    c->rx_have_high = 1;

    if (out_counter) *out_counter = counter;
    if (out_gap)     *out_gap     = gap;
    return (ssize_t)pt_len;
}
