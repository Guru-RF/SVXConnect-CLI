/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — Copyright (C) 2026 Joeri Van Dooren
 */
#ifndef SVX_PKI_H
#define SVX_PKI_H

#include <stddef.h>
#include <stdint.h>

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

#endif
