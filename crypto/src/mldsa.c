/**
 * @file mldsa.c
 * @brief ML-DSA-44 (Dilithium Level 2, NIST FIPS 204) implementation using wolfCrypt.
 *
 * Provides key generation, signing, and verification for the post-quantum
 * digital signature scheme ML-DSA-44 using the wolfSSL/wolfCrypt library.
 *
 * Compile with: -DHAVE_DILITHIUM -DWOLFSSL_WC_DILITHIUM -DWOLFSSL_USER_SETTINGS
 */

#include "mldsa.h"

#include <wolfssl/wolfcrypt/user_settings.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/random.h>
#include <string.h>
#include <stdio.h>

/* Forward declaration of entropy source (provided per-platform) */
extern int CustomRngGenerateBlock(unsigned char *output, unsigned int sz);

/* -------------------------------------------------------------------------
 * Internal: Initialize a dilithium_key struct at Level 2
 * ------------------------------------------------------------------------- */
static int mldsa44_init_key(dilithium_key *key)
{
    int ret = wc_dilithium_init(key);
    if (ret != 0) {
        fprintf(stderr, "[mldsa] wc_dilithium_init failed: %d\n", ret);
        return ret;
    }

    ret = wc_dilithium_set_level(key, MLDSA44_LEVEL);
    if (ret != 0) {
        fprintf(stderr, "[mldsa] wc_dilithium_set_level(2) failed: %d\n", ret);
        wc_dilithium_free(key);
        return ret;
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * Key Generation
 * ------------------------------------------------------------------------- */
int mldsa44_keygen(uint8_t *pubkey_out, uint8_t *privkey_out)
{
    if (!pubkey_out || !privkey_out) return -1;

    dilithium_key key;
    WC_RNG rng;

    int ret = wc_InitRng(&rng);
    if (ret != 0) {
        fprintf(stderr, "[mldsa] RNG init failed: %d\n", ret);
        return ret;
    }

    ret = mldsa44_init_key(&key);
    if (ret != 0) {
        wc_FreeRng(&rng);
        return ret;
    }

    /* Generate keypair */
    ret = wc_dilithium_make_key(&key, &rng);
    if (ret != 0) {
        fprintf(stderr, "[mldsa] wc_dilithium_make_key failed: %d\n", ret);
        wc_dilithium_free(&key);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Export public key */
    word32 pub_sz = MLDSA44_PUBKEY_SIZE;
    ret = wc_dilithium_export_public(&key, pubkey_out, &pub_sz);
    if (ret != 0) {
        fprintf(stderr, "[mldsa] export_public failed: %d\n", ret);
        wc_dilithium_free(&key);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Export private key */
    word32 priv_sz = MLDSA44_PRIVKEY_SIZE;
    ret = wc_dilithium_export_private(&key, privkey_out, &priv_sz);
    if (ret != 0) {
        fprintf(stderr, "[mldsa] export_private failed: %d\n", ret);
        wc_dilithium_free(&key);
        wc_FreeRng(&rng);
        return ret;
    }

    wc_dilithium_free(&key);
    wc_FreeRng(&rng);
    return 0;
}

/* -------------------------------------------------------------------------
 * Signing
 * ------------------------------------------------------------------------- */
int mldsa44_sign(const uint8_t *privkey,
                 const uint8_t *msg,
                 size_t msg_len,
                 uint8_t *sig_out,
                 size_t *sig_len_out)
{
    if (!privkey || !msg || !sig_out || !sig_len_out) return -1;

    dilithium_key key;
    WC_RNG rng;

    int ret = wc_InitRng(&rng);
    if (ret != 0) {
        fprintf(stderr, "[mldsa] RNG init failed: %d\n", ret);
        return ret;
    }

    ret = mldsa44_init_key(&key);
    if (ret != 0) {
        wc_FreeRng(&rng);
        return ret;
    }

    /* Import private key */
    ret = wc_dilithium_import_private(privkey, MLDSA44_PRIVKEY_SIZE, &key);
    if (ret != 0) {
        fprintf(stderr, "[mldsa] import_private failed: %d\n", ret);
        wc_dilithium_free(&key);
        wc_FreeRng(&rng);
        return ret;
    }

    word32 sig_sz = MLDSA44_SIG_SIZE;
    ret = wc_dilithium_sign_msg(msg, (word32)msg_len, sig_out, &sig_sz, &key, &rng);
    if (ret != 0) {
        fprintf(stderr, "[mldsa] sign_msg failed: %d\n", ret);
        wc_dilithium_free(&key);
        wc_FreeRng(&rng);
        return ret;
    }

    *sig_len_out = sig_sz;

    wc_dilithium_free(&key);
    wc_FreeRng(&rng);
    return 0;
}

/* -------------------------------------------------------------------------
 * Verification
 * ------------------------------------------------------------------------- */
int mldsa44_verify(const uint8_t *pubkey,
                   const uint8_t *msg,
                   size_t msg_len,
                   const uint8_t *sig,
                   size_t sig_len)
{
    if (!pubkey || !msg || !sig) return -1;

    dilithium_key key;

    int ret = mldsa44_init_key(&key);
    if (ret != 0) return ret;

    /* Import public key */
    ret = wc_dilithium_import_public(pubkey, MLDSA44_PUBKEY_SIZE, &key);
    if (ret != 0) {
        fprintf(stderr, "[mldsa] import_public failed: %d\n", ret);
        wc_dilithium_free(&key);
        return ret;
    }

    int verify_ok = 0;
    ret = wc_dilithium_verify_msg(sig, (word32)sig_len,
                                  msg, (word32)msg_len,
                                  &verify_ok, &key);
    wc_dilithium_free(&key);

    if (ret != 0) {
        fprintf(stderr, "[mldsa] verify_msg failed: %d\n", ret);
        return ret;
    }

    if (!verify_ok) {
        return -2;  /* Signature invalid */
    }

    return 0;
}
