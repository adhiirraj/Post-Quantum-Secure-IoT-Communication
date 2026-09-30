/**
 * @file mldsa.h
 * @brief ML-DSA-44 (NIST FIPS 204, Dilithium Level 2) Digital Signature Wrapper
 *
 * Provides key generation, signing, and verification for ML-DSA-44,
 * the NIST-standardized post-quantum digital signature algorithm.
 *
 * Parameters (ML-DSA-44 / Dilithium Level 2):
 *   Public key : 1312 bytes
 *   Private key: 2560 bytes
 *   Signature  : 2420 bytes (max)
 *   Security   : NIST Category 2 (~128-bit classical, 64-bit PQ)
 */

#ifndef MLDSA_H
#define MLDSA_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * ML-DSA-44 (Dilithium Level 2) Parameter Sizes
 * ------------------------------------------------------------------------- */
#define MLDSA44_PUBKEY_SIZE     1312   /**< Public key size in bytes */
#define MLDSA44_PRIVKEY_SIZE    2560   /**< Private/signing key size in bytes */
#define MLDSA44_SIG_SIZE        2420   /**< Maximum signature size in bytes */
#define MLDSA44_LEVEL           2      /**< Dilithium security level (2 = ML-DSA-44) */

/* -------------------------------------------------------------------------
 * Key Generation
 * ------------------------------------------------------------------------- */

/**
 * @brief Generate an ML-DSA-44 keypair.
 *
 * @param pubkey_out  Output buffer for public key (MLDSA44_PUBKEY_SIZE bytes).
 * @param privkey_out Output buffer for private/signing key (MLDSA44_PRIVKEY_SIZE bytes).
 * @return 0 on success, negative on failure.
 */
int mldsa44_keygen(uint8_t *pubkey_out,
                   uint8_t *privkey_out);

/* -------------------------------------------------------------------------
 * Signing
 * ------------------------------------------------------------------------- */

/**
 * @brief Sign a message using ML-DSA-44 private key.
 *
 * @param privkey     Private/signing key (MLDSA44_PRIVKEY_SIZE bytes).
 * @param msg         Message data to sign.
 * @param msg_len     Length of message in bytes.
 * @param sig_out     Output buffer for signature (MLDSA44_SIG_SIZE bytes).
 * @param sig_len_out Actual signature length written.
 * @return 0 on success, negative on failure.
 */
int mldsa44_sign(const uint8_t *privkey,
                 const uint8_t *msg,
                 size_t msg_len,
                 uint8_t *sig_out,
                 size_t *sig_len_out);

/* -------------------------------------------------------------------------
 * Verification
 * ------------------------------------------------------------------------- */

/**
 * @brief Verify an ML-DSA-44 signature.
 *
 * @param pubkey      Signer's public key (MLDSA44_PUBKEY_SIZE bytes).
 * @param msg         Message data that was signed.
 * @param msg_len     Length of message in bytes.
 * @param sig         Signature bytes to verify.
 * @param sig_len     Length of signature in bytes.
 * @return 0 on successful verification, negative on failure or invalid signature.
 */
int mldsa44_verify(const uint8_t *pubkey,
                   const uint8_t *msg,
                   size_t msg_len,
                   const uint8_t *sig,
                   size_t sig_len);

#ifdef __cplusplus
}
#endif

#endif /* MLDSA_H */
