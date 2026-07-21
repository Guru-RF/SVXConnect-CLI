/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "proto.h"
#include "util.h"
#include "log.h"

#include <string.h>
#include <stdlib.h>

const char *proto_msg_name(uint16_t type) {
    switch (type) {
    case MSG_HEARTBEAT:            return "Heartbeat";
    case MSG_PROTO_VER:            return "ProtoVer";
    case MSG_PROTO_VER_DOWNGRADE:  return "ProtoVerDowngrade";
    case MSG_AUTH_CHALLENGE:       return "AuthChallenge";
    case MSG_AUTH_RESPONSE:        return "AuthResponse";
    case MSG_AUTH_OK:              return "AuthOk";
    case MSG_ERROR:                return "Error";
    case MSG_START_ENC_REQUEST:    return "StartEncryptionRequest";
    case MSG_START_ENCRYPTION:     return "StartEncryption";
    case MSG_CLIENT_CSR_REQUEST:   return "ClientCsrRequest";
    case MSG_CLIENT_CSR:           return "ClientCsr";
    case MSG_CLIENT_CERT:          return "ClientCert";
    case MSG_CA_INFO:              return "CAInfo";
    case MSG_CA_BUNDLE_REQUEST:    return "CABundleRequest";
    case MSG_CA_BUNDLE_RESPONSE:   return "CABundleResponse";
    case MSG_SERVER_INFO:          return "ServerInfo";
    case MSG_NODE_JOINED:          return "NodeJoined";
    case MSG_NODE_LEFT:            return "NodeLeft";
    case MSG_TALKER_START:         return "TalkerStart";
    case MSG_TALKER_STOP:          return "TalkerStop";
    case MSG_SELECT_TG:            return "SelectTG";
    case MSG_TG_MONITOR:           return "TgMonitor";
    case MSG_NODE_INFO:            return "NodeInfo";
    case MSG_START_UDP_ENCRYPTION: return "StartUdpEncryption";
    default:                       return "Unknown";
    }
}

/* ------------------------------------------------------------- framing */

static int frame_begin(uint8_t *buf, size_t cap, size_t *off) {
    (void)buf;                 /* the length prefix is filled in by frame_end */
    if (cap < 4) return -1;
    *off = 4;
    return 0;
}

static int frame_end(uint8_t *buf, size_t off, size_t *out_len) {
    size_t body = off - 4;     /* the prefix counts the body only */
    if (body > 0xFFFFFFFFu) return -1;
    be_put_u32(buf, (uint32_t)body);
    *out_len = off;
    return 0;
}

static int put_u16(uint8_t *buf, size_t cap, size_t *off, uint16_t v) {
    if (*off + 2 > cap) return -1;
    be_put_u16(buf + *off, v);
    *off += 2;
    return 0;
}
static int put_u32(uint8_t *buf, size_t cap, size_t *off, uint32_t v) {
    if (*off + 4 > cap) return -1;
    be_put_u32(buf + *off, v);
    *off += 4;
    return 0;
}
static int put_bytes(uint8_t *buf, size_t cap, size_t *off,
                     const void *data, size_t n) {
    if (*off + n > cap) return -1;
    memcpy(buf + *off, data, n);
    *off += n;
    return 0;
}
static int put_string(uint8_t *buf, size_t cap, size_t *off,
                      const char *s, size_t n) {
    if (n > 0xFFFF) return -1;
    if (put_u16(buf, cap, off, (uint16_t)n) < 0) return -1;
    return put_bytes(buf, cap, off, s, n);
}

/* Read a [u16 len][bytes] string at *off, advancing it. Returns 0 on success. */
static int get_string(const uint8_t *p, size_t len, size_t *off,
                      char *out, size_t cap) {
    if (*off + 2 > len) return -1;
    uint16_t n = be_get_u16(p + *off);
    *off += 2;
    if (*off + n > len) return -1;
    if (out && cap > 0) {
        size_t copy = n < cap - 1 ? n : cap - 1;
        memcpy(out, p + *off, copy);
        out[copy] = '\0';
    }
    *off += n;
    return 0;
}

/* ------------------------------------------------------------ builders */

int proto_build_proto_ver(uint8_t *buf, size_t cap, size_t *out_len) {
    size_t off; if (frame_begin(buf, cap, &off) < 0) return -1;
    if (put_u16(buf, cap, &off, MSG_PROTO_VER)) return -1;
    if (put_u16(buf, cap, &off, PROTO_MAJOR))   return -1;
    if (put_u16(buf, cap, &off, PROTO_MINOR))   return -1;
    return frame_end(buf, off, out_len);
}

int proto_build_ca_bundle_req(uint8_t *buf, size_t cap, size_t *out_len) {
    size_t off; if (frame_begin(buf, cap, &off) < 0) return -1;
    if (put_u16(buf, cap, &off, MSG_CA_BUNDLE_REQUEST)) return -1;
    return frame_end(buf, off, out_len);
}

int proto_build_start_enc_req(uint8_t *buf, size_t cap, size_t *out_len) {
    size_t off; if (frame_begin(buf, cap, &off) < 0) return -1;
    if (put_u16(buf, cap, &off, MSG_START_ENC_REQUEST)) return -1;
    return frame_end(buf, off, out_len);
}

int proto_build_heartbeat(uint8_t *buf, size_t cap, size_t *out_len) {
    size_t off; if (frame_begin(buf, cap, &off) < 0) return -1;
    if (put_u16(buf, cap, &off, MSG_HEARTBEAT)) return -1;
    return frame_end(buf, off, out_len);
}

int proto_build_csr_request(uint8_t *buf, size_t cap, size_t *out_len) {
    size_t off; if (frame_begin(buf, cap, &off) < 0) return -1;
    if (put_u16(buf, cap, &off, MSG_CLIENT_CSR_REQUEST)) return -1;
    return frame_end(buf, off, out_len);
}

int proto_build_client_csr(uint8_t *buf, size_t cap, size_t *out_len,
                           const char *csr_pem, size_t csr_pem_len) {
    size_t off; if (frame_begin(buf, cap, &off) < 0) return -1;
    if (put_u16(buf, cap, &off, MSG_CLIENT_CSR)) return -1;
    if (put_string(buf, cap, &off, csr_pem, csr_pem_len)) return -1;
    return frame_end(buf, off, out_len);
}

int proto_build_auth_response(uint8_t *buf, size_t cap, size_t *out_len,
                              const char *callsign, const uint8_t digest[20]) {
    size_t off; if (frame_begin(buf, cap, &off) < 0) return -1;
    if (put_u16(buf, cap, &off, MSG_AUTH_RESPONSE)) return -1;
    if (put_string(buf, cap, &off, callsign, strlen(callsign))) return -1;
    if (put_bytes(buf, cap, &off, digest, 20)) return -1;
    return frame_end(buf, off, out_len);
}

int proto_build_node_info(uint8_t *buf, size_t cap, size_t *out_len,
                          const uint8_t *iv_rand, size_t iv_len,
                          const uint8_t *key,     size_t key_len,
                          const char *json,       size_t json_len) {
    size_t off; if (frame_begin(buf, cap, &off) < 0) return -1;
    if (put_u16(buf, cap, &off, MSG_NODE_INFO)) return -1;
    if (put_u16(buf, cap, &off, (uint16_t)iv_len)) return -1;
    if (put_bytes(buf, cap, &off, iv_rand, iv_len)) return -1;
    if (put_u16(buf, cap, &off, (uint16_t)key_len)) return -1;
    if (put_bytes(buf, cap, &off, key, key_len)) return -1;
    if (put_string(buf, cap, &off, json, json_len)) return -1;
    return frame_end(buf, off, out_len);
}

int proto_build_select_tg(uint8_t *buf, size_t cap, size_t *out_len,
                          uint32_t tg_id) {
    size_t off; if (frame_begin(buf, cap, &off) < 0) return -1;
    if (put_u16(buf, cap, &off, MSG_SELECT_TG)) return -1;
    if (put_u32(buf, cap, &off, tg_id)) return -1;
    return frame_end(buf, off, out_len);
}

int proto_build_tg_monitor(uint8_t *buf, size_t cap, size_t *out_len,
                           const uint32_t *tg_ids, size_t n) {
    size_t off; if (frame_begin(buf, cap, &off) < 0) return -1;
    if (put_u16(buf, cap, &off, MSG_TG_MONITOR)) return -1;
    if (put_u16(buf, cap, &off, (uint16_t)n)) return -1;
    for (size_t i = 0; i < n; i++) {
        if (put_u32(buf, cap, &off, tg_ids[i])) return -1;
    }
    return frame_end(buf, off, out_len);
}

/* ------------------------------------------------------------- parsers */

int proto_parse_server_info(const uint8_t *payload, size_t len,
                            uint16_t *out_client_id,
                            int      *out_node_count,
                            int      *out_have_opus) {
    /* type(2) reserved(2) clientID(2) [nodes: u16 count + count strings]
     *                                 [codecs: u16 count + count strings] */
    if (len < 6) return -1;
    if (out_client_id)  *out_client_id  = be_get_u16(payload + 4);
    if (out_node_count) *out_node_count = 0;
    if (out_have_opus)  *out_have_opus  = 0;

    size_t off = 6;

    /* The node list is optional in practice — older servers stop after the
     * client id. Anything we cannot parse is simply not reported, never an
     * error: the client id is the only field we actually require. */
    if (off + 2 > len) return 0;
    uint16_t n_nodes = be_get_u16(payload + off);
    off += 2;
    for (uint16_t i = 0; i < n_nodes; i++) {
        if (get_string(payload, len, &off, NULL, 0) != 0) return 0;
    }
    if (out_node_count) *out_node_count = (int)n_nodes;

    if (off + 2 > len) return 0;
    uint16_t n_codecs = be_get_u16(payload + off);
    off += 2;
    for (uint16_t i = 0; i < n_codecs; i++) {
        char codec[32];
        if (get_string(payload, len, &off, codec, sizeof(codec)) != 0) return 0;
        if (str_ieq(codec, "OPUS") && out_have_opus) *out_have_opus = 1;
    }
    return 0;
}

int proto_parse_proto_ver_downgrade(const uint8_t *payload, size_t len,
                                    uint16_t *out_major, uint16_t *out_minor) {
    if (len < 6) return -1;
    if (out_major) *out_major = be_get_u16(payload + 2);
    if (out_minor) *out_minor = be_get_u16(payload + 4);
    return 0;
}

int proto_parse_start_udp_encryption(const uint8_t *payload, size_t len,
                                     uint8_t out_iv_rand[4],
                                     uint8_t out_key[16]) {
    /* An empty body means the server accepted our key for both directions. */
    if (len <= 2) return 1;
    if (len < 2 + 4 + 16) return -1;
    memcpy(out_iv_rand, payload + 2, 4);
    memcpy(out_key,     payload + 6, 16);
    return 0;
}

int proto_parse_talker(const uint8_t *payload, size_t len,
                       uint32_t *out_tg, char *out_callsign, size_t cs_cap) {
    /* type(2) tg(4) callsign(string) */
    if (len < 8) return -1;
    if (out_tg) *out_tg = be_get_u32(payload + 2);
    size_t off = 6;
    return get_string(payload, len, &off, out_callsign, cs_cap);
}

int proto_parse_node_event(const uint8_t *payload, size_t len,
                           char *out_callsign, size_t cs_cap) {
    if (len < 4) return -1;
    size_t off = 2;
    return get_string(payload, len, &off, out_callsign, cs_cap);
}

int proto_parse_error(const uint8_t *payload, size_t len,
                      char *out_msg, size_t msg_cap) {
    if (len < 4) return -1;
    size_t off = 2;
    return get_string(payload, len, &off, out_msg, msg_cap);
}

int proto_parse_pem_blob(const uint8_t *payload, size_t len,
                         char *out, size_t out_cap) {
    /* Some server messages wrap the PEM in a string field and others append it
     * raw, so rather than guess we scan for the armour and concatenate every
     * block we find. */
    size_t out_off = 0;
    size_t i = 0;
    while (i + 10 <= len) {
        size_t begin = SIZE_MAX;
        for (size_t k = i; k + 10 <= len; k++) {
            if (memcmp(payload + k, "-----BEGIN", 10) == 0) { begin = k; break; }
        }
        if (begin == SIZE_MAX) break;

        size_t end = SIZE_MAX;
        for (size_t k = begin + 10; k + 8 <= len; k++) {
            if (memcmp(payload + k, "-----END", 8) == 0) { end = k; break; }
        }
        if (end == SIZE_MAX) break;

        while (end < len && payload[end] != '\n') end++;   /* to end of line */
        if (end < len) end++;

        size_t block_len = end - begin;
        if (out_off + block_len + 2 >= out_cap) return -1;
        memcpy(out + out_off, payload + begin, block_len);
        out_off += block_len;
        if (out_off > 0 && out[out_off - 1] != '\n') out[out_off++] = '\n';
        i = end;
    }
    if (out_off == 0) return -1;
    out[out_off] = '\0';
    return 0;
}

/* -------------------------------------------------------- UDP plaintext */

int proto_build_udp_plaintext(uint8_t *buf, size_t cap, size_t *out_len,
                              uint16_t type,
                              const uint8_t *body, size_t body_len) {
    size_t off = 0;
    if (put_u16(buf, cap, &off, type) < 0) return -1;

    /* Audio carries its own length; every other type does not. Getting this
     * backwards produces a stream the reflector silently discards. */
    if (type == UDP_MSG_AUDIO) {
        if (body_len > 0xFFFF) return -1;
        if (put_u16(buf, cap, &off, (uint16_t)body_len) < 0) return -1;
    }
    if (body_len > 0) {
        if (put_bytes(buf, cap, &off, body, body_len) < 0) return -1;
    }
    *out_len = off;
    return 0;
}

int proto_parse_udp_plaintext(const uint8_t *pt, size_t len,
                              uint16_t *out_type,
                              const uint8_t **out_body, size_t *out_body_len) {
    if (len < 2) return -1;
    uint16_t type = be_get_u16(pt);
    if (out_type) *out_type = type;

    if (type == UDP_MSG_AUDIO) {
        if (len < 4) return -1;
        uint16_t n = be_get_u16(pt + 2);
        if ((size_t)4 + n > len) return -1;
        if (out_body)     *out_body     = pt + 4;
        if (out_body_len) *out_body_len = n;
        return 0;
    }
    if (out_body)     *out_body     = pt + 2;
    if (out_body_len) *out_body_len = len - 2;
    return 0;
}
