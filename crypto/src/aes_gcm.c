/**
 * @file aes_gcm.c
 * @brief AES-256-GCM AEAD implementation using wolfSSL/wolfCrypt
 */

#include "aes_gcm.h"

#include <wolfssl/wolfcrypt/user_settings.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <string.h>

int pqc_aes_gcm_encrypt(const uint8_t *key, size_t key_len,
                        const uint8_t *iv, size_t iv_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *plaintext, size_t plain_len,
                        uint8_t *out_ciphertext,
                        uint8_t *out_tag, size_t tag_len)
{
    if (!key || !iv || !out_ciphertext || !out_tag) return -1;
    if (key_len != PQC_AES_KEY_SIZE) return -2;
    if (iv_len != PQC_AES_GCM_IV_SIZE) return -3;
    if (tag_len != PQC_AES_GCM_TAG_SIZE) return -4;

    Aes aes;
    int ret = wc_AesGcmSetKey(&aes, key, (word32)key_len);
    if (ret != 0) return ret;

    ret = wc_AesGcmEncrypt(&aes,
                           out_ciphertext,
                           plaintext,
                           (word32)plain_len,
                           iv,
                           (word32)iv_len,
                           out_tag,
                           (word32)tag_len,
                           aad,
                           (word32)aad_len);

    return ret;
}

int pqc_aes_gcm_decrypt(const uint8_t *key, size_t key_len,
                        const uint8_t *iv, size_t iv_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ciphertext, size_t cipher_len,
                        const uint8_t *tag, size_t tag_len,
                        uint8_t *out_plaintext)
{
    if (!key || !iv || !ciphertext || !tag || !out_plaintext) return -1;
    if (key_len != PQC_AES_KEY_SIZE) return -2;
    if (iv_len != PQC_AES_GCM_IV_SIZE) return -3;
    if (tag_len != PQC_AES_GCM_TAG_SIZE) return -4;

    Aes aes;
    int ret = wc_AesGcmSetKey(&aes, key, (word32)key_len);
    if (ret != 0) return ret;

    ret = wc_AesGcmDecrypt(&aes,
                           out_plaintext,
                           ciphertext,
                           (word32)cipher_len,
                           iv,
                           (word32)iv_len,
                           tag,
                           (word32)tag_len,
                           aad,
                           (word32)aad_len);

    return ret;
}
