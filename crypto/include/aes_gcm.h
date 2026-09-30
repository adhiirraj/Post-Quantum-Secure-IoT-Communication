/**
 * @file aes_gcm.h
 * @brief AES-256-GCM Authenticated Encryption with Associated Data (AEAD)
 *
 * Provides symmetric encryption and decryption routines utilizing the
 * shared secret derived from ML-KEM-512.
 */

#ifndef PQC_AES_GCM_H
#define PQC_AES_GCM_H

#include <stdint.h>
#include <stddef.h>
#include "protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Encrypts plaintext and computes an authentication tag using AES-256-GCM.
 *
 * @param key 32-byte symmetric key (e.g. derived PQC shared secret).
 * @param key_len Length of key (must be PQC_AES_KEY_SIZE, 32 bytes).
 * @param iv 12-byte initialization vector.
 * @param iv_len Length of IV (must be PQC_AES_GCM_IV_SIZE, 12 bytes).
 * @param aad Optional Additional Authenticated Data (can be NULL if aad_len is 0).
 * @param aad_len Length of AAD.
 * @param plaintext Input plaintext buffer.
 * @param plain_len Length of plaintext.
 * @param out_ciphertext Output buffer for ciphertext (must be at least plain_len).
 * @param out_tag Output buffer for 16-byte authentication tag.
 * @param tag_len Desired tag length (typically PQC_AES_GCM_TAG_SIZE, 16 bytes).
 * @return 0 on success, negative error code on failure.
 */
int pqc_aes_gcm_encrypt(const uint8_t *key, size_t key_len,
                        const uint8_t *iv, size_t iv_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *plaintext, size_t plain_len,
                        uint8_t *out_ciphertext,
                        uint8_t *out_tag, size_t tag_len);

/**
 * @brief Decrypts ciphertext and verifies authentication tag using AES-256-GCM.
 *
 * @param key 32-byte symmetric key.
 * @param key_len Length of key (must be PQC_AES_KEY_SIZE, 32 bytes).
 * @param iv 12-byte initialization vector.
 * @param iv_len Length of IV (must be PQC_AES_GCM_IV_SIZE, 12 bytes).
 * @param aad Optional Additional Authenticated Data.
 * @param aad_len Length of AAD.
 * @param ciphertext Input ciphertext buffer.
 * @param cipher_len Length of ciphertext.
 * @param tag 16-byte authentication tag to verify against.
 * @param tag_len Tag length (PQC_AES_GCM_TAG_SIZE, 16 bytes).
 * @param out_plaintext Output buffer for decrypted plaintext.
 * @return 0 on success (authentic), negative error code on tag mismatch or failure.
 */
int pqc_aes_gcm_decrypt(const uint8_t *key, size_t key_len,
                        const uint8_t *iv, size_t iv_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ciphertext, size_t cipher_len,
                        const uint8_t *tag, size_t tag_len,
                        uint8_t *out_plaintext);

#ifdef __cplusplus
}
#endif

#endif /* PQC_AES_GCM_H */
