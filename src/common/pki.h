/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#ifndef SVX_PKI_H
#define SVX_PKI_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* Build "<dir>/<callsign>.<ext>". */
void pki_build_path(char *out, size_t cap,
                    const char *dir, const char *callsign, const char *ext);

/* 1 if the file exists and is non-empty. */
int pki_file_exists(const char *path);

/* Generate an RSA-2048 key and a matching CSR, entirely in-process.
 *
 * SvxBridge shells out to openssl(1) for this. That interpolates the callsign
 * and e-mail straight into a /bin/sh command line, blocks for the duration of
 * key generation, and depends on -addext, which LibreSSL's openssl(1) — the
 * one in $PATH on macOS — does not support. All three problems disappear here.
 *
 * The CSR carries CN=<callsign>, basicConstraints CA:FALSE, keyUsage
 * digitalSignature/keyEncipherment/keyAgreement, extendedKeyUsage clientAuth,
 * and, when `email` is non-empty, a subjectAltName rfc822Name so the sysop
 * can tell who is asking.
 *
 * The key is written 0600, the CSR 0644. Returns 0 on success. */
int pki_generate_csr(const char *key_path, const char *csr_path,
                     const char *callsign, const char *email);

/* Make sure a CSR exists that belongs to the key on disk, and return 0 when
 * it does. An existing key is NEVER replaced: svxreflector refuses a request
 * whose public key differs from the one it already signed for this callsign
 * (its anti-hijack rule), so a lost or stale .csr is rebuilt from the key we
 * have. A key is generated only when there is none at all. */
int pki_ensure_csr(const char *key_path, const char *csr_path,
                   const char *callsign, const char *email);

/* 1 if the CSR at `csr_path` was made with the key at `key_path`, 0 if not,
 * -1 if either cannot be read. */
int pki_csr_matches_key(const char *csr_path, const char *key_path);

/* Read a PEM certificate and report its subject CN and expiry.
 * `out_cn` and `out_notafter` may be NULL. `out_days_left` receives the days
 * remaining, negative if the certificate has already expired.
 * Returns 0 on success. */
int pki_cert_info(const char *cert_path,
                  char *out_cn, size_t cn_cap,
                  char *out_notafter, size_t na_cap,
                  int *out_days_left);

/* Confirm that a certificate and key belong together, before we try to use
 * them and get an opaque TLS failure instead. Returns 0 if they match. */
int pki_check_pair(const char *cert_path, const char *key_path);

/* ---- the certificate's lifetime ----
 *
 * svxreflector re-signs a client certificate by itself once it is past 2/3 of
 * its lifetime, and pushes it as MsgClientCert to a client that has stayed
 * connected for about ten minutes. So "renewal due" is normal and needs
 * nothing from the user; "expiring" means that window has mostly passed
 * without a renewal arriving, and a person has to look. */

typedef struct {
    time_t not_before;
    time_t not_after;
    time_t renew_at;        /* when the reflector starts pushing a new one  */
    time_t warn_at;         /* when to tell the user renewal has not happened */
    char   subject_cn[64];
    char   fingerprint[65]; /* SHA-256, lower-case hex */
} pki_cert_info_t;

typedef enum {
    PKI_CERT_MISSING = 0,
    PKI_CERT_INVALID,       /* present but not a PEM certificate */
    PKI_CERT_NOT_YET_VALID, /* notBefore is ahead of this machine's clock */
    PKI_CERT_OK,
    PKI_CERT_RENEW_DUE,     /* the reflector should push a renewal */
    PKI_CERT_EXPIRING,      /* ...and has not; the user should act */
    PKI_CERT_EXPIRED
} pki_cert_status_t;

/* Warn when this many days are left, or earlier than that for a certificate
 * with a short lifetime — see pki_cert_info_pem() for how warn_at is set. */
#define PKI_WARN_DAYS 14

int pki_cert_info_pem (const char *pem, size_t len, pki_cert_info_t *out);
int pki_cert_info_file(const char *path, pki_cert_info_t *out);

pki_cert_status_t pki_cert_status(const pki_cert_info_t *info, time_t now);
pki_cert_status_t pki_cert_check_file(const char *path, pki_cert_info_t *out,
                                      time_t now);
const char       *pki_cert_status_str(pki_cert_status_t st);

/* Whole days from `now` until `t`, rounded down; negative once it has passed. */
int  pki_days_until(time_t t, time_t now);

/* "2026-12-13 23:12 UTC". */
void pki_format_time(time_t t, char *out, size_t cap);

/* ---- a certificate the reflector sent us ---- */

typedef enum {
    PKI_PUSH_STORED = 0,    /* new certificate validated and written        */
    PKI_PUSH_SAME,          /* identical to the one on disk; nothing written */
    PKI_PUSH_EMPTY,         /* the message carried no certificate            */
    PKI_PUSH_REJECTED,      /* failed validation; the file was not touched   */
    PKI_PUSH_WRITE_FAILED
} pki_push_result;

/* Validate a PEM certificate the reflector pushed (MsgClientCert) and, if it
 * is good, write it atomically over `cert_path`. It must be for `callsign`,
 * belong to the private key at `key_path`, not be expired, and not expire
 * sooner than the certificate already on disk. Anything less leaves the file
 * alone, because the certificate we have may still work and the one offered
 * certainly will not. `why` receives a one-line reason for anything but
 * PKI_PUSH_STORED; `out` (may be NULL) the details of the offered certificate. */
pki_push_result pki_store_pushed_cert(const char *cert_path, const char *key_path,
                                      const char *callsign,
                                      const char *pem, size_t len, time_t now,
                                      pki_cert_info_t *out,
                                      char *why, size_t why_cap);

#endif
