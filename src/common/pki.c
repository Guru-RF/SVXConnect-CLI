/* SPDX-License-Identifier: GPL-3.0-or-later
 * SVXConnect-CLI — Copyright (C) 2026 Joeri Van Dooren
 */
#include "pki.h"
#include "log.h"
#include "util.h"
#include "tls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

void pki_build_path(char *out, size_t cap,
                    const char *dir, const char *callsign, const char *ext) {
    snprintf(out, cap, "%s/%s.%s", dir, callsign, ext);
}

int pki_file_exists(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return st.st_size > 0;
}

/* --------------------------------------------------------------- keygen */

static EVP_PKEY *gen_rsa_2048(void) {
    /* The EVP_PKEY_CTX form rather than OpenSSL 3's EVP_RSA_gen(), so this
     * still builds against the 1.1.1 that Pi OS Bullseye ships. */
    EVP_PKEY     *pkey = NULL;
    EVP_PKEY_CTX *ctx  = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0) goto end;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) goto end;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) { pkey = NULL; goto end; }
end:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static int add_ext(STACK_OF(X509_EXTENSION) *exts, int nid, const char *value) {
    X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
    if (!ex) return -1;
    sk_X509_EXTENSION_push(exts, ex);
    return 0;
}

int pki_generate_csr(const char *key_path, const char *csr_path,
                     const char *callsign, const char *email) {
    tls_global_init();

    if (!callsign || !*callsign) {
        log_err("cannot generate a CSR without a callsign");
        return -1;
    }

    int                     rc   = -1;
    EVP_PKEY               *pkey = NULL;
    X509_REQ               *req  = NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;
    BIO                    *mem  = NULL;

    log_info("generating a 2048-bit RSA key, this takes a moment...");
    pkey = gen_rsa_2048();
    if (!pkey) { log_err("RSA key generation failed: %s", tls_last_error()); goto end; }

    req = X509_REQ_new();
    if (!req) goto end;
    if (X509_REQ_set_version(req, 0) != 1) goto end;   /* v1 */

    /* Subject: CN=<CALLSIGN>. No shell, no quoting, no injection. */
    {
        X509_NAME *name = X509_REQ_get_subject_name(req);
        if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                       (const unsigned char *)callsign, -1, -1, 0) != 1) {
            log_err("cannot set the CSR subject: %s", tls_last_error());
            goto end;
        }
    }

    exts = sk_X509_EXTENSION_new_null();
    if (!exts) goto end;

    if (add_ext(exts, NID_basic_constraints, "critical,CA:FALSE") != 0 ||
        add_ext(exts, NID_key_usage,
                "critical,digitalSignature,keyEncipherment,keyAgreement") != 0 ||
        add_ext(exts, NID_ext_key_usage, "clientAuth") != 0) {
        log_err("cannot build the CSR extensions: %s", tls_last_error());
        goto end;
    }

    if (email && *email) {
        char san[320];
        snprintf(san, sizeof(san), "email:%s", email);
        if (add_ext(exts, NID_subject_alt_name, san) != 0) {
            /* A malformed address should not stop enrolment — the sysop can
             * still identify the request by its callsign. */
            log_warn("could not add '%s' as a subjectAltName; continuing without it", email);
        }
    }

    if (X509_REQ_add_extensions(req, exts) != 1) {
        log_err("cannot attach the CSR extensions: %s", tls_last_error());
        goto end;
    }

    if (X509_REQ_set_pubkey(req, pkey) != 1) goto end;
    if (X509_REQ_sign(req, pkey, EVP_sha256()) <= 0) {
        log_err("cannot sign the CSR: %s", tls_last_error());
        goto end;
    }

    /* Write via a memory BIO and then write_file_atomic, so the key file is
     * created 0600 from the outset and never briefly world-readable. */
    {
        mem = BIO_new(BIO_s_mem());
        if (!mem) goto end;
        if (PEM_write_bio_PrivateKey(mem, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
            log_err("cannot serialise the private key: %s", tls_last_error());
            goto end;
        }
        char  *data = NULL;
        long   n    = BIO_get_mem_data(mem, &data);
        if (n <= 0 || write_file_atomic(key_path, data, (size_t)n, 0600) != 0) {
            log_err("cannot write %s", key_path);
            goto end;
        }
        BIO_free(mem); mem = NULL;
    }
    {
        mem = BIO_new(BIO_s_mem());
        if (!mem) goto end;
        if (PEM_write_bio_X509_REQ(mem, req) != 1) {
            log_err("cannot serialise the CSR: %s", tls_last_error());
            goto end;
        }
        char  *data = NULL;
        long   n    = BIO_get_mem_data(mem, &data);
        if (n <= 0 || write_file_atomic(csr_path, data, (size_t)n, 0644) != 0) {
            log_err("cannot write %s", csr_path);
            goto end;
        }
    }

    log_info("wrote %s (0600) and %s", key_path, csr_path);
    rc = 0;

end:
    if (mem)  BIO_free(mem);
    if (exts) sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    if (req)  X509_REQ_free(req);
    if (pkey) EVP_PKEY_free(pkey);
    return rc;
}

/* ----------------------------------------------------------- inspection */

int pki_cert_info(const char *cert_path,
                  char *out_cn, size_t cn_cap,
                  char *out_notafter, size_t na_cap,
                  int *out_days_left) {
    tls_global_init();

    FILE *f = fopen(cert_path, "r");
    if (!f) return -1;
    X509 *x = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    if (!x) return -1;

    if (out_cn && cn_cap > 0) {
        out_cn[0] = '\0';
        X509_NAME *n = X509_get_subject_name(x);
        X509_NAME_get_text_by_NID(n, NID_commonName, out_cn, (int)cn_cap);
    }

    const ASN1_TIME *na = X509_get0_notAfter(x);

    if (out_notafter && na_cap > 0) {
        out_notafter[0] = '\0';
        struct tm tm;
        memset(&tm, 0, sizeof(tm));
        if (ASN1_TIME_to_tm(na, &tm)) {
            strftime(out_notafter, na_cap, "%Y-%m-%d", &tm);
        }
    }

    if (out_days_left) {
        int days = 0, secs = 0;
        if (ASN1_TIME_diff(&days, &secs, NULL, na)) *out_days_left = days;
        else                                        *out_days_left = 0;
    }

    X509_free(x);
    return 0;
}

int pki_check_pair(const char *cert_path, const char *key_path) {
    tls_global_init();

    int       rc   = -1;
    X509     *x    = NULL;
    EVP_PKEY *pkey = NULL;
    FILE     *f;

    f = fopen(cert_path, "r");
    if (!f) { log_err("cannot open %s", cert_path); goto end; }
    x = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    if (!x) { log_err("%s is not a PEM certificate", cert_path); goto end; }

    f = fopen(key_path, "r");
    if (!f) { log_err("cannot open %s", key_path); goto end; }
    pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey) { log_err("%s is not a PEM private key", key_path); goto end; }

    if (X509_check_private_key(x, pkey) != 1) {
        log_err("%s does not match %s", cert_path, key_path);
        goto end;
    }
    rc = 0;
end:
    if (x)    X509_free(x);
    if (pkey) EVP_PKEY_free(pkey);
    return rc;
}
