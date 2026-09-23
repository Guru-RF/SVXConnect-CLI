/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "pki.h"
#include "log.h"
#include "util.h"
#include "tls.h"

#include <errno.h>
#include <limits.h>
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

/* Build and write a CSR for `pkey`. The key file is written only when
 * `key_path` is non-NULL, i.e. only for a key made here and now. */
static int write_csr(EVP_PKEY *pkey, const char *key_path, const char *csr_path,
                     const char *callsign, const char *email) {
    int                     rc   = -1;
    X509_REQ               *req  = NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;
    BIO                    *mem  = NULL;

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
    if (key_path) {
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

    if (key_path) log_info("wrote %s (0600) and %s", key_path, csr_path);
    else          log_info("wrote %s", csr_path);
    rc = 0;

end:
    if (mem)  BIO_free(mem);
    if (exts) sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    if (req)  X509_REQ_free(req);
    return rc;
}

static EVP_PKEY *load_private_key(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    EVP_PKEY *k = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!k) ERR_clear_error();
    return k;
}

int pki_generate_csr(const char *key_path, const char *csr_path,
                     const char *callsign, const char *email) {
    tls_global_init();

    if (!callsign || !*callsign) {
        log_err("cannot generate a CSR without a callsign");
        return -1;
    }

    log_info("generating a 2048-bit RSA key, this takes a moment...");
    EVP_PKEY *pkey = gen_rsa_2048();
    if (!pkey) { log_err("RSA key generation failed: %s", tls_last_error()); return -1; }

    int rc = write_csr(pkey, key_path, csr_path, callsign, email);
    EVP_PKEY_free(pkey);
    return rc;
}

int pki_csr_matches_key(const char *csr_path, const char *key_path) {
    tls_global_init();

    FILE *f = fopen(csr_path, "r");
    if (!f) return -1;
    X509_REQ *req = PEM_read_X509_REQ(f, NULL, NULL, NULL);
    fclose(f);
    if (!req) { ERR_clear_error(); return -1; }

    EVP_PKEY *k = load_private_key(key_path);
    if (!k) { X509_REQ_free(req); return -1; }

    int rc = (X509_REQ_check_private_key(req, k) == 1) ? 1 : 0;
    if (!rc) ERR_clear_error();
    EVP_PKEY_free(k);
    X509_REQ_free(req);
    return rc;
}

int pki_ensure_csr(const char *key_path, const char *csr_path,
                   const char *callsign, const char *email) {
    tls_global_init();

    if (!callsign || !*callsign) {
        log_err("cannot generate a CSR without a callsign");
        return -1;
    }

    if (!pki_file_exists(key_path)) {
        log_info("generating a key and certificate request for %s", callsign);
        return pki_generate_csr(key_path, csr_path, callsign, email);
    }

    if (pki_file_exists(csr_path)) {
        if (pki_csr_matches_key(csr_path, key_path) == 1) {
            /* Never regenerate. The sysop may be looking at the earlier
             * request right now; replacing it would invalidate whatever
             * they are about to sign. */
            log_dbg("reusing the existing request %s", csr_path);
            return 0;
        }
        log_warn("%s was not made with %s — rebuilding it from that key",
                 csr_path, key_path);
    } else {
        log_info("making a new certificate request from the existing key %s", key_path);
    }

    EVP_PKEY *pkey = load_private_key(key_path);
    if (!pkey) {
        /* Refuse rather than replace it: a new key means the sysop has to
         * delete our certificate on the reflector by hand before a request
         * made with it can be signed. That is a decision for a person. */
        log_err("%s is not a readable private key; not replacing it. Move it "
                "aside to start over with a new key.", key_path);
        return -1;
    }
    int rc = write_csr(pkey, NULL, csr_path, callsign, email);
    EVP_PKEY_free(pkey);
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

/* ------------------------------------------------------------- lifetime */

static X509 *x509_from_pem(const char *pem, size_t len) {
    if (!pem || len == 0 || len > (size_t)INT_MAX) return NULL;
    BIO *bio = BIO_new_mem_buf(pem, (int)len);
    if (!bio) return NULL;
    X509 *x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!x) ERR_clear_error();
    return x;
}

/* ASN1_TIME to time_t, by measuring its distance from now: timegm() is not
 * portable and ASN1_TIME_to_tm() gives a broken-down UTC time that mktime()
 * would misread as local. */
static int asn1_to_time_t(const ASN1_TIME *at, time_t *out) {
    int days = 0, secs = 0;
    time_t now = time(NULL);
    if (ASN1_TIME_diff(&days, &secs, NULL, at) != 1) {
        ERR_clear_error();
        return -1;
    }
    *out = now + (time_t)days * 86400 + secs;
    return 0;
}

int pki_cert_info_pem(const char *pem, size_t len, pki_cert_info_t *out) {
    tls_global_init();
    memset(out, 0, sizeof(*out));

    X509 *x = x509_from_pem(pem, len);
    if (!x) return -1;

    int rc = -1;
    if (asn1_to_time_t(X509_get0_notBefore(x), &out->not_before) == 0 &&
        asn1_to_time_t(X509_get0_notAfter(x),  &out->not_after)  == 0) {
        /* The reflector's rule: renew after 2/3 of the lifetime. */
        time_t life   = out->not_after - out->not_before;
        out->renew_at = out->not_before + life * 2 / 3;

        /* Tell the user once half of the renewal window has gone by with no
         * renewal, but never later than PKI_WARN_DAYS before expiry. Halving
         * the window keeps a short-lived certificate from raising the alarm
         * the moment renewal becomes possible. */
        time_t warn = out->not_after - (time_t)PKI_WARN_DAYS * 86400;
        time_t half = out->renew_at + (out->not_after - out->renew_at) / 2;
        out->warn_at = warn > half ? warn : half;

        X509_NAME *subj = X509_get_subject_name(x);
        if (subj) {
            X509_NAME_get_text_by_NID(subj, NID_commonName,
                                      out->subject_cn, (int)sizeof(out->subject_cn));
        }

        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int  mdlen = 0;
        if (X509_digest(x, EVP_sha256(), md, &mdlen) == 1) {
            for (unsigned int i = 0; i < mdlen && i * 2 + 2 < sizeof(out->fingerprint); i++)
                snprintf(out->fingerprint + i * 2, 3, "%02x", md[i]);
        }
        rc = 0;
    }
    X509_free(x);
    return rc;
}

int pki_cert_info_file(const char *path, pki_cert_info_t *out) {
    size_t len = 0;
    char  *pem = read_file(path, &len);
    if (!pem) { memset(out, 0, sizeof(*out)); return -1; }
    int rc = pki_cert_info_pem(pem, len, out);
    free(pem);
    return rc;
}

pki_cert_status_t pki_cert_status(const pki_cert_info_t *info, time_t now) {
    if (now >= info->not_after)  return PKI_CERT_EXPIRED;
    if (now <  info->not_before) return PKI_CERT_NOT_YET_VALID;
    if (now >= info->warn_at)    return PKI_CERT_EXPIRING;
    if (now >= info->renew_at)   return PKI_CERT_RENEW_DUE;
    return PKI_CERT_OK;
}

pki_cert_status_t pki_cert_check_file(const char *path, pki_cert_info_t *out,
                                      time_t now) {
    memset(out, 0, sizeof(*out));
    if (!pki_file_exists(path)) return PKI_CERT_MISSING;
    if (pki_cert_info_file(path, out) != 0) return PKI_CERT_INVALID;
    return pki_cert_status(out, now);
}

const char *pki_cert_status_str(pki_cert_status_t st) {
    switch (st) {
    case PKI_CERT_MISSING:       return "missing";
    case PKI_CERT_INVALID:       return "unreadable";
    case PKI_CERT_NOT_YET_VALID: return "not yet valid";
    case PKI_CERT_OK:            return "valid";
    case PKI_CERT_RENEW_DUE:     return "renewal due";
    case PKI_CERT_EXPIRING:      return "expiring";
    case PKI_CERT_EXPIRED:       return "expired";
    }
    return "?";
}

int pki_days_until(time_t t, time_t now) {
    /* Floor, not truncation: one hour past expiry is day -1, not day 0, so
     * "0 days left" never describes a certificate that no longer works. */
    long long d = (long long)t - (long long)now;
    return (int)(d >= 0 ? d / 86400 : -((-d + 86399) / 86400));
}

void pki_format_time(time_t t, char *out, size_t cap) {
    struct tm tm;
    if (!gmtime_r(&t, &tm) || strftime(out, cap, "%Y-%m-%d %H:%M UTC", &tm) == 0)
        snprintf(out, cap, "?");
}

pki_push_result pki_store_pushed_cert(const char *cert_path, const char *key_path,
                                      const char *callsign,
                                      const char *pem, size_t len, time_t now,
                                      pki_cert_info_t *out,
                                      char *why, size_t why_cap) {
    pki_cert_info_t info;
    if (!out) out = &info;
    if (why && why_cap) why[0] = '\0';

    if (!pem || len == 0) {
        /* svxreflector sends an empty MsgClientCert when it has nothing
         * signed for us yet. */
        snprintf(why, why_cap, "the reflector has no signed certificate for %s yet", callsign);
        return PKI_PUSH_EMPTY;
    }
    if (pki_cert_info_pem(pem, len, out) != 0) {
        snprintf(why, why_cap, "it is not a readable certificate");
        return PKI_PUSH_REJECTED;
    }

    char na[32];
    pki_format_time(out->not_after, na, sizeof(na));

    if (strcmp(out->subject_cn, callsign) != 0) {
        snprintf(why, why_cap, "it is for '%s', not %s", out->subject_cn, callsign);
        return PKI_PUSH_REJECTED;
    }

    /* Does it belong to OUR key? A certificate for another key would replace
     * a working pair with one that cannot complete a TLS handshake. */
    {
        X509     *x = x509_from_pem(pem, len);
        EVP_PKEY *k = load_private_key(key_path);
        int match = (x && k && X509_check_private_key(x, k) == 1);
        if (!match) ERR_clear_error();
        if (x) X509_free(x);
        if (k) EVP_PKEY_free(k);
        if (!match) {
            snprintf(why, why_cap, "it does not belong to our private key %s", key_path);
            return PKI_PUSH_REJECTED;
        }
    }

    if (out->not_after <= out->not_before) {
        snprintf(why, why_cap, "its validity period is empty");
        return PKI_PUSH_REJECTED;
    }

    pki_cert_info_t cur;
    int have_cur = (pki_cert_info_file(cert_path, &cur) == 0);

    if (have_cur && strcmp(cur.fingerprint, out->fingerprint) == 0) {
        snprintf(why, why_cap, "it is the certificate we already have (valid until %s)", na);
        return PKI_PUSH_SAME;
    }
    if (now >= out->not_after) {
        snprintf(why, why_cap, "it expired on %s — check this machine's clock", na);
        return PKI_PUSH_REJECTED;
    }
    if (have_cur && out->not_after < cur.not_after) {
        char cna[32];
        pki_format_time(cur.not_after, cna, sizeof(cna));
        snprintf(why, why_cap, "it expires on %s, before the one we have (%s)", na, cna);
        return PKI_PUSH_REJECTED;
    }

    if (write_file_atomic(cert_path, pem, len, 0644) != 0) {
        snprintf(why, why_cap, "cannot write %s: %s", cert_path, strerror(errno));
        return PKI_PUSH_WRITE_FAILED;
    }
    return PKI_PUSH_STORED;
}
