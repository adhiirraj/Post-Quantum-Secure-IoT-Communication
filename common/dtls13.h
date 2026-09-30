/**
 * @file dtls13.h
 * @brief DTLS 1.3 (RFC 9147) Protocol Headers and PQC Extensions
 *
 * Defines record layers, handshake message structures, and PQC extensions
 * for ML-KEM-512 (Kyber) key exchange and ML-DSA-44 (Dilithium) mutual authentication.
 */

#ifndef DTLS13_H
#define DTLS13_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * DTLS 1.3 Protocol Constants (RFC 9147)
 * ------------------------------------------------------------------------- */
#define DTLS13_LEGACY_VERSION           0xFEFD  /**< DTLS 1.2 legacy version in record header */
#define DTLS13_VERSION                  0xFEFC  /**< DTLS 1.3 wire version in supported_versions */

#define DTLS13_PORT                     11111   /**< Default Gateway Server Port */

/* Content Types */
typedef enum {
    DTLS13_CT_CHANGE_CIPHER_SPEC        = 20,
    DTLS13_CT_ALERT                     = 21,
    DTLS13_CT_HANDSHAKE                 = 22,
    DTLS13_CT_APPLICATION_DATA          = 23,
    DTLS13_CT_ACK                       = 25
} dtls13_content_type_t;

/* Handshake Message Types */
typedef enum {
    DTLS13_HT_CLIENT_HELLO              = 1,
    DTLS13_HT_SERVER_HELLO              = 2,
    DTLS13_HT_ENCRYPTED_EXTENSIONS      = 8,
    DTLS13_HT_CERTIFICATE               = 11,
    DTLS13_HT_CERTIFICATE_REQUEST       = 13,
    DTLS13_HT_CERTIFICATE_VERIFY        = 15,
    DTLS13_HT_FINISHED                  = 20
} dtls13_handshake_type_t;

/* Cipher Suites */
#define TLS_AES_128_GCM_SHA256          0x1301
#define TLS_AES_256_GCM_SHA384          0x1302
#define TLS_CHACHA20_POLY1305_SHA256    0x1303

/* Named Groups (Key Exchange) */
#define GROUP_ML_KEM_512                512     /**< ML-KEM-512 (NIST FIPS 203) */
#define GROUP_KYBER_512                 570     /**< Kyber-512 Level 1 */

/* Signature Schemes */
#define SIG_ML_DSA_44                   0x0904  /**< ML-DSA-44 (Dilithium Level 2, NIST FIPS 204) */

/* Extension Types */
#define EXT_SUPPORTED_VERSIONS          0x002B  /**< 43 */
#define EXT_SIGNATURE_ALGORITHMS        0x000D  /**< 13 */
#define EXT_SUPPORTED_GROUPS            0x000A  /**< 10 */
#define EXT_KEY_SHARE                   0x0033  /**< 51 */

/* -------------------------------------------------------------------------
 * Packed Record and Handshake Headers (Wire Format)
 * ------------------------------------------------------------------------- */

/**
 * @brief DTLS 1.3 Unified Record Header (13 bytes)
 */
typedef struct __attribute__((packed)) {
    uint8_t  content_type;      /**< dtls13_content_type_t */
    uint16_t legacy_version;    /**< 0xFEFD */
    uint16_t epoch;             /**< Epoch 0 = plaintext, Epoch 1+ = encrypted */
    uint8_t  sequence_number[6];/**< 48-bit packet sequence number */
    uint16_t length;            /**< Length of fragment following this header */
} dtls13_record_header_t;

/**
 * @brief DTLS 1.3 Handshake Fragment Header (12 bytes)
 */
typedef struct __attribute__((packed)) {
    uint8_t  msg_type;          /**< dtls13_handshake_type_t */
    uint8_t  length[3];         /**< 24-bit total handshake message length */
    uint16_t message_seq;       /**< Handshake message sequence number */
    uint8_t  fragment_offset[3];/**< 24-bit fragment offset */
    uint8_t  fragment_length[3];/**< 24-bit fragment length */
} dtls13_handshake_header_t;

#ifdef __cplusplus
}
#endif

#endif /* DTLS13_H */
