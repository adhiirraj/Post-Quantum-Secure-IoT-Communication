/**
 * @file pqc_kem.h
 * @brief High-level wrapper for ML-KEM (Kyber) Post-Quantum Cryptography
 *
 * Provides a clean, modular C API around wolfSSL/wolfCrypt ML-KEM-512 operations,
 * supporting keypair generation, public key encoding/decoding, encapsulation,
 * and decapsulation for constrained bare-metal targets.
 */

#ifndef PQC_KEM_H
#define PQC_KEM_H

#include <stdint.h>
#include <stddef.h>
#include "protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations for wolfSSL types */
typedef struct MlKemKey MlKemKey;
typedef struct WC_RNG WC_RNG;

/**
 * @brief Initializes the cryptographically secure random number generator (RNG).
 * @param rng Pointer to WC_RNG context to initialize.
 * @return 0 on success, negative error code on failure.
 */
int pqc_kem_rng_init(WC_RNG *rng);

/**
 * @brief Releases the RNG context.
 * @param rng Pointer to initialized WC_RNG context.
 */
void pqc_kem_rng_free(WC_RNG *rng);

/**
 * @brief Allocates and generates a fresh ML-KEM-512 keypair.
 * @param out_key Output pointer to newly allocated MlKemKey structure.
 * @param pub_key_buf Output buffer to store 800-byte encoded public key.
 * @param pub_buf_len Size of output buffer (must be at least PQC_KEM_PUBLIC_KEY_SIZE).
 * @param rng Pointer to initialized WC_RNG.
 * @return 0 on success, negative error code on failure.
 */
int pqc_kem_generate_keypair(MlKemKey **out_key,
                             uint8_t *pub_key_buf,
                             size_t pub_buf_len,
                             WC_RNG *rng);

/**
 * @brief Encapsulates a shared secret using peer's public key (Client/Sender side).
 * @param peer_pub_key 800-byte encoded public key of peer.
 * @param pub_key_len Length of public key (must equal PQC_KEM_PUBLIC_KEY_SIZE).
 * @param out_ciphertext Output buffer for 768-byte ciphertext.
 * @param ct_buf_len Size of ciphertext buffer.
 * @param out_shared_secret Output buffer for derived 32-byte shared secret.
 * @param ss_buf_len Size of shared secret buffer.
 * @param rng Pointer to initialized WC_RNG.
 * @return 0 on success, negative error code on failure.
 */
int pqc_kem_encapsulate(const uint8_t *peer_pub_key,
                        size_t pub_key_len,
                        uint8_t *out_ciphertext,
                        size_t ct_buf_len,
                        uint8_t *out_shared_secret,
                        size_t ss_buf_len,
                        WC_RNG *rng);

/**
 * @brief Decapsulates shared secret from received ciphertext (Server/Receiver side).
 * @param private_key MlKemKey containing private key from keypair generation.
 * @param ciphertext 768-byte received ciphertext.
 * @param ct_len Length of ciphertext.
 * @param out_shared_secret Output buffer for derived 32-byte shared secret.
 * @param ss_buf_len Size of shared secret buffer.
 * @return 0 on success, negative error code on failure.
 */
int pqc_kem_decapsulate(MlKemKey *private_key,
                        const uint8_t *ciphertext,
                        size_t ct_len,
                        uint8_t *out_shared_secret,
                        size_t ss_buf_len);

/**
 * @brief Frees an allocated MlKemKey structure.
 * @param key Pointer to MlKemKey to free.
 */
void pqc_kem_free_key(MlKemKey *key);

#ifdef __cplusplus
}
#endif

#endif /* PQC_KEM_H */
