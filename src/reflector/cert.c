/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "cert.h"

#include "common/log.h"
#include "common/proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PEM_MAX (64 * 1024)

void cert_assess(const svx_config *cfg, time_t now, cert_state *out, int log) {
    memset(out, 0, sizeof(*out));
    pki_build_path(out->cert_path, sizeof(out->cert_path), cfg->pki_dir, cfg->callsign, "crt");
    pki_build_path(out->key_path,  sizeof(out->key_path),  cfg->pki_dir, cfg->callsign, "key");
    pki_build_path(out->csr_path,  sizeof(out->csr_path),  cfg->pki_dir, cfg->callsign, "csr");

    out->status = pki_cert_check_file(out->cert_path, &out->info, now);
    if (!log) return;

    char na[32], ra[32], nb[32];
    pki_format_time(out->info.not_after,  na, sizeof(na));
    pki_format_time(out->info.renew_at,   ra, sizeof(ra));
    pki_format_time(out->info.not_before, nb, sizeof(nb));
    int days = pki_days_until(out->info.not_after, now);

    switch (out->status) {
    case PKI_CERT_OK:
        log_info("certificate valid until %s (%d days left; the reflector renews it from %s)",
                 na, days, ra);
        break;
    case PKI_CERT_RENEW_DUE:
        log_info("certificate valid until %s (%d days left); the reflector should "
                 "push a renewed one once we have been connected for ten minutes",
                 na, days);
        break;
    case PKI_CERT_EXPIRING:
        log_warn("certificate valid until %s — only %d days left and the reflector "
                 "has not renewed it yet", na, days);
        break;
    case PKI_CERT_EXPIRED:
        log_warn("certificate EXPIRED on %s — asking the reflector for a new one "
                 "with the same key", na);
        break;
    case PKI_CERT_NOT_YET_VALID:
        log_warn("certificate not valid before %s — check this machine's clock; "
                 "trying it anyway", nb);
        break;
    case PKI_CERT_MISSING:
    case PKI_CERT_INVALID:
        /* The caller refuses to connect and says why; nothing to add. */
        break;
    }
}

pki_push_result cert_handle_push(const svx_config *cfg,
                                 const uint8_t *body, size_t len, time_t now,
                                 const char *refused_fp) {
    char cert_path[1024], key_path[1024];
    pki_build_path(cert_path, sizeof(cert_path), cfg->pki_dir, cfg->callsign, "crt");
    pki_build_path(key_path,  sizeof(key_path),  cfg->pki_dir, cfg->callsign, "key");

    char *pem = malloc(PEM_MAX);
    if (!pem) { log_err("out of memory"); return PKI_PUSH_WRITE_FAILED; }
    size_t pem_len = 0;
    if (proto_parse_pem_blob(body, len, pem, PEM_MAX) == 0) pem_len = strlen(pem);

    pki_cert_info_t info;
    char            why[320];
    pki_push_result r = pki_store_pushed_cert(cert_path, key_path, cfg->callsign,
                                              pem, pem_len, now, refused_fp,
                                              &info, why, sizeof(why));
    free(pem);

    char na[32];
    pki_format_time(info.not_after, na, sizeof(na));

    switch (r) {
    case PKI_PUSH_STORED:
        log_info("new certificate stored in %s, valid until %s (%d days)",
                 cert_path, na, pki_days_until(info.not_after, now));
        break;
    case PKI_PUSH_SAME:
        /* The reflector thinks the certificate we have is current. When ours
         * looks expired here, one of the two clocks is wrong. */
        log_warn("the reflector sent the certificate we already have (valid until "
                 "%s); if it looks expired here, check this machine's clock", na);
        break;
    case PKI_PUSH_EMPTY:
        log_info("%s", why);
        break;
    case PKI_PUSH_REJECTED:
        log_err("ignoring the certificate the reflector sent: %s. Keeping %s.",
                why, cert_path);
        break;
    case PKI_PUSH_WRITE_FAILED:
        log_err("the reflector sent a renewed certificate but %s", why);
        break;
    }
    return r;
}

int cert_banner_text(const svx_config *cfg, const cert_state *st, time_t now,
                     char *out, size_t cap) {
    char na[32], nb[32];
    pki_format_time(st->info.not_after,  na, sizeof(na));
    pki_format_time(st->info.not_before, nb, sizeof(nb));

    switch (st->status) {
    case PKI_CERT_EXPIRING: {
        int days = pki_days_until(st->info.not_after, now);
        snprintf(out, cap,
                 "CERTIFICATE EXPIRES %s (%d day%s) - not renewed yet. Stay connected "
                 "15 min so the reflector can; else ask its sysop to re-sign %s.",
                 na, days, days == 1 ? "" : "s", cfg->callsign);
        return 1;
    }
    case PKI_CERT_EXPIRED:
        snprintf(out, cap,
                 "CERTIFICATE EXPIRED %s - a new one has been requested. Ask the "
                 "reflector sysop to sign the request for %s; it is picked up by itself.",
                 na, cfg->callsign);
        return 1;
    case PKI_CERT_NOT_YET_VALID:
        snprintf(out, cap,
                 "CERTIFICATE not valid before %s - this computer's clock is wrong. "
                 "Set the date and time, then reconnect.", nb);
        return 1;
    case PKI_CERT_INVALID:
        snprintf(out, cap,
                 "CERTIFICATE %s cannot be read. Move it aside and run "
                 "'svxconnect --enroll'.", st->cert_path);
        return 1;
    case PKI_CERT_MISSING:
        snprintf(out, cap,
                 "NO CERTIFICATE for %s in %s. Run 'svxconnect --enroll'.",
                 cfg->callsign, cfg->pki_dir);
        return 1;
    case PKI_CERT_OK:
    case PKI_CERT_RENEW_DUE:
        break;
    }
    return 0;
}
