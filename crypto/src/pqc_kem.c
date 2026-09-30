/**
 * @file pqc_kem.c
 * @brief ML-KEM-512 implementation wrapper using wolfSSL/wolfCrypt
 */

#include "pqc_kem.h"

#include <wolfssl/wolfcrypt/user_settings.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/mlkem.h>
#include <wolfssl/wolfcrypt/random.h>
#include <string.h>

int pqc_kem_rng_init(WC_RNG *rng)
{
    if (!rng) return -1;
    return wc_InitRng(rng);
}

void pqc_kem_rng_free(WC_RNG *rng)
{
    if (rng) {
        wc_FreeRng(rng);
    }
}

int pqc_kem_generate_keypair(MlKemKey **out_key,
                             uint8_t *pub_key_buf,
                             size_t pub_buf_len,
                             WC_RNG *rng)
{
    if (!out_key || !pub_key_buf || !rng) return -1;
    if (pub_buf_len < PQC_KEM_PUBLIC_KEY_SIZE) return -2;

    MlKemKey *key = wc_MlKemKey_New(WC_ML_KEM_512, NULL, INVALID_DEVID);
    if (!key) return -3;

    int ret = wc_MlKemKey_MakeKey(key, rng);
    if (ret != 0) {
        wc_MlKemKey_Free(key);
        return ret;
    }

    ret = wc_MlKemKey_EncodePublicKey(key, pub_key_buf, PQC_KEM_PUBLIC_KEY_SIZE);
    if (ret != 0) {
        wc_MlKemKey_Free(key);
        return ret;
    }

    *out_key = key;
    return 0;
}

int pqc_kem_encapsulate(const uint8_t *peer_pub_key,
                        size_t pub_key_len,
                        uint8_t *out_ciphertext,
                        size_t ct_buf_len,
                        uint8_t *out_shared_secret,
                        size_t ss_buf_len,
                        WC_RNG *rng)
{
    if (!peer_pub_key || !out_ciphertext || !out_shared_secret || !rng) return -1;
    if (pub_key_len < PQC_KEM_PUBLIC_KEY_SIZE) return -2;
    if (ct_buf_len < PQC_KEM_CIPHERTEXT_SIZE) return -3;
    if (ss_buf_len < PQC_KEM_SHARED_SECRET_SIZE) return -4;

    MlKemKey *peer_key = wc_MlKemKey_New(WC_ML_KEM_512, NULL, INVALID_DEVID);
    if (!peer_key) return -5;

    int ret = wc_MlKemKey_DecodePublicKey(peer_key, peer_pub_key, PQC_KEM_PUBLIC_KEY_SIZE);
    if (ret != 0) {
        wc_MlKemKey_Free(peer_key);
        return ret;
    }

    ret = wc_MlKemKey_Encapsulate(peer_key, out_ciphertext, out_shared_secret, rng);
    wc_MlKemKey_Free(peer_key);

    return ret;
}

int pqc_kem_decapsulate(MlKemKey *private_key,
                        const uint8_t *ciphertext,
                        size_t ct_len,
                        uint8_t *out_shared_secret,
                        size_t ss_buf_len)
{
    if (!private_key || !ciphertext || !out_shared_secret) return -1;
    if (ct_len < PQC_KEM_CIPHERTEXT_SIZE) return -2;
    if (ss_buf_len < PQC_KEM_SHARED_SECRET_SIZE) return -3;

    return wc_MlKemKey_Decapsulate(private_key, out_shared_secret, ciphertext, PQC_KEM_CIPHERTEXT_SIZE);
}

void pqc_kem_free_key(MlKemKey *key)
{
    if (key) {
        wc_MlKemKey_Free(key);
    }
}
