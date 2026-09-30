/*
 * Development credential generator for the DTLS 1.3 PQC demonstration.
 *
 * It creates a self-signed ML-DSA-44 CA and ML-DSA-44 server/client leaf
 * certificates. All output is DER despite the conventional .crt/.key names;
 * wolfSSL consumes the buffers as WOLFSSL_FILETYPE_ASN1.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>

#define CERT_BUFFER_SIZE 16384U
#define KEY_BUFFER_SIZE  8192U
#define MLDSA44_LEVEL    2

static int write_file(const char *path, const unsigned char *data, size_t len)
{
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) {
        fprintf(stderr, "cannot write %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fwrite(data, 1, len, fp) != len) {
        fprintf(stderr, "short write to %s\n", path);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

static int make_key(dilithium_key *key, WC_RNG *rng)
{
    int ret = wc_dilithium_init(key);
    if (ret == 0) {
        ret = wc_dilithium_set_level(key, MLDSA44_LEVEL);
    }
    if (ret == 0) {
        ret = wc_dilithium_make_key(key, rng);
    }
    return ret;
}

static int write_private_key(const char *path, dilithium_key *key)
{
    unsigned char der[KEY_BUFFER_SIZE];
    int der_len = wc_Dilithium_PrivateKeyToDer(key, der, sizeof(der));
    if (der_len <= 0) {
        fprintf(stderr, "ML-DSA private-key DER encoding failed: %d\n", der_len);
        return -1;
    }
    return write_file(path, der, (size_t)der_len);
}

static int write_certificate(const char *path, const char *common_name,
                             int is_ca, dilithium_key *subject_key,
                             const char *issuer_common_name,
                             dilithium_key *issuer_key, WC_RNG *rng)
{
    Cert cert;
    unsigned char der[CERT_BUFFER_SIZE];
    int ret = wc_InitCert(&cert);
    if (ret != 0) {
        fprintf(stderr, "wc_InitCert failed: %d\n", ret);
        return -1;
    }

    cert.sigType = CTC_ML_DSA_LEVEL2;
    cert.daysValid = 30;
    cert.selfSigned = is_ca;
    cert.isCA = is_ca;
    (void)snprintf(cert.subject.commonName, sizeof(cert.subject.commonName), "%s", common_name);
    if (!is_ca) {
        (void)snprintf(cert.issuer.commonName, sizeof(cert.issuer.commonName), "%s",
                       issuer_common_name);
    }

    ret = wc_MakeCert_ex(&cert, der, sizeof(der), ML_DSA_LEVEL2_TYPE,
                         subject_key, rng);
    if (ret <= 0) {
        fprintf(stderr, "ML-DSA certificate body generation failed: %d\n", ret);
        return -1;
    }

    ret = wc_SignCert_ex(cert.bodySz, CTC_ML_DSA_LEVEL2, der, sizeof(der),
                         ML_DSA_LEVEL2_TYPE, issuer_key, rng);
    if (ret <= 0) {
        fprintf(stderr, "ML-DSA certificate signing failed: %d\n", ret);
        return -1;
    }
    return write_file(path, der, (size_t)ret);
}

int main(int argc, char **argv)
{
    const char *output_dir = argc == 2 ? argv[1] : "certs";
    char path[512];
    WC_RNG rng;
    dilithium_key ca_key, server_key, client_key;
    int ret = 1;

    if (mkdir(output_dir, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "cannot create %s: %s\n", output_dir, strerror(errno));
        return 1;
    }
    if (wc_InitRng(&rng) != 0 || make_key(&ca_key, &rng) != 0 ||
        make_key(&server_key, &rng) != 0 || make_key(&client_key, &rng) != 0) {
        fprintf(stderr, "ML-DSA key generation failed\n");
        goto out;
    }

    (void)snprintf(path, sizeof(path), "%s/pqc_mldsa_ca.crt", output_dir);
    if (write_certificate(path, "PQC IoT Demo ML-DSA CA", 1, &ca_key,
                          NULL, &ca_key, &rng) != 0) goto out;
    (void)snprintf(path, sizeof(path), "%s/pqc_mldsa_ca.key", output_dir);
    if (write_private_key(path, &ca_key) != 0) goto out;

    (void)snprintf(path, sizeof(path), "%s/server_mldsa.crt", output_dir);
    if (write_certificate(path, "pqc-gateway", 0, &server_key,
                          "PQC IoT Demo ML-DSA CA", &ca_key, &rng) != 0) goto out;
    (void)snprintf(path, sizeof(path), "%s/server_mldsa.key", output_dir);
    if (write_private_key(path, &server_key) != 0) goto out;

    (void)snprintf(path, sizeof(path), "%s/client_mldsa.crt", output_dir);
    if (write_certificate(path, "riscv-node-01", 0, &client_key,
                          "PQC IoT Demo ML-DSA CA", &ca_key, &rng) != 0) goto out;
    (void)snprintf(path, sizeof(path), "%s/client_mldsa.key", output_dir);
    if (write_private_key(path, &client_key) != 0) goto out;

    puts("Generated ML-DSA-44 CA, gateway, and client DER credentials.");
    ret = 0;
out:
    wc_dilithium_free(&client_key);
    wc_dilithium_free(&server_key);
    wc_dilithium_free(&ca_key);
    wc_FreeRng(&rng);
    return ret;
}
