/**
 * @file protocol.h
 * @brief Post-Quantum Cryptography (PQC) Secure IoT Communication Protocol
 *
 * Defines the packet format, message types, and cryptographic parameters
 * for post-quantum key exchange (ML-KEM-512) and authenticated symmetric
 * communication (AES-256-GCM) between constrained RISC-V IoT nodes and host gateways.
 */

#ifndef PQC_PROTOCOL_H
#define PQC_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Protocol Identifiers & Version
 * ------------------------------------------------------------------------- */
#define PQC_PROTOCOL_MAGIC          0x50514331  /**< "PQC1" in ASCII big-endian */
#define PQC_PROTOCOL_VERSION        0x01

#define PQC_DEFAULT_PORT            11111       /**< Default UDP port for PQC IoT Gateway */

/* -------------------------------------------------------------------------
 * Cryptographic Parameters (NIST FIPS 203 & FIPS 197)
 * ------------------------------------------------------------------------- */
#define PQC_KEM_PUBLIC_KEY_SIZE     800         /**< ML-KEM-512 Public Key size (bytes) */
#define PQC_KEM_PRIVATE_KEY_SIZE    1632        /**< ML-KEM-512 Private Key size (bytes) */
#define PQC_KEM_CIPHERTEXT_SIZE     768         /**< ML-KEM-512 Ciphertext size (bytes) */
#define PQC_KEM_SHARED_SECRET_SIZE  32          /**< ML-KEM-512 Derived Secret (256 bits) */

#define PQC_AES_KEY_SIZE            32          /**< AES-256 Key size (256 bits) */
#define PQC_AES_GCM_IV_SIZE         12          /**< AES-GCM standard IV nonce (96 bits) */
#define PQC_AES_GCM_TAG_SIZE        16          /**< AES-GCM Authentication Tag (128 bits) */

/* -------------------------------------------------------------------------
 * Message Types
 * ------------------------------------------------------------------------- */
typedef enum {
    PQC_MSG_DISCOVERY_REQ      = 0x01,  /**< Client broadcasting discovery request */
    PQC_MSG_KEM_PUBLIC_KEY     = 0x02,  /**< Node/Server sending ML-KEM Public Key (800 bytes) */
    PQC_MSG_KEM_CIPHERTEXT     = 0x03,  /**< Node/Server sending KEM Ciphertext (768 bytes) */
    PQC_MSG_SECURE_PAYLOAD     = 0x04,  /**< Encrypted application payload (IV + Tag + Data) */
    PQC_MSG_ACK                = 0x05,  /**< Status response / handshake confirmation */
    PQC_MSG_ERROR              = 0xFF   /**< Error notification */
} pqc_msg_type_t;

/* -------------------------------------------------------------------------
 * Status Codes
 * ------------------------------------------------------------------------- */
typedef enum {
    PQC_STATUS_OK              = 0x00,
    PQC_STATUS_ERR_MAGIC       = 0x01,
    PQC_STATUS_ERR_VERSION     = 0x02,
    PQC_STATUS_ERR_TYPE        = 0x03,
    PQC_STATUS_ERR_CRYPTO      = 0x04,
    PQC_STATUS_ERR_AUTH_FAIL   = 0x05,
    PQC_STATUS_ERR_TIMEOUT     = 0x06
} pqc_status_t;

/* -------------------------------------------------------------------------
 * Packet Headers & Structures (Packed for Wire Compatibility)
 * ------------------------------------------------------------------------- */

/**
 * @brief Common PQC Protocol Header (12 bytes)
 */
typedef struct __attribute__((packed)) {
    uint32_t magic;         /**< Protocol identifier (PQC_PROTOCOL_MAGIC) */
    uint8_t  version;       /**< Protocol version (PQC_PROTOCOL_VERSION) */
    uint8_t  msg_type;      /**< Message type (pqc_msg_type_t) */
    uint16_t payload_len;   /**< Length of payload body following this header */
    uint32_t seq_num;       /**< Monotonically increasing sequence number */
} pqc_header_t;

/**
 * @brief Payload for PQC_MSG_KEM_PUBLIC_KEY
 */
typedef struct __attribute__((packed)) {
    uint8_t public_key[PQC_KEM_PUBLIC_KEY_SIZE];
} pqc_kem_pubkey_msg_t;

/**
 * @brief Payload for PQC_MSG_KEM_CIPHERTEXT
 */
typedef struct __attribute__((packed)) {
    uint8_t ciphertext[PQC_KEM_CIPHERTEXT_SIZE];
} pqc_kem_ciphertext_msg_t;

/**
 * @brief Header for PQC_MSG_SECURE_PAYLOAD
 */
typedef struct __attribute__((packed)) {
    uint8_t iv[PQC_AES_GCM_IV_SIZE];        /**< 12-byte initialization vector */
    uint8_t tag[PQC_AES_GCM_TAG_SIZE];      /**< 16-byte GCM authentication tag */
    uint8_t ciphertext[];                   /**< Variable-length encrypted payload */
} pqc_secure_payload_msg_t;

/**
 * @brief Payload for PQC_MSG_ACK
 */
typedef struct __attribute__((packed)) {
    uint8_t  status_code;   /**< pqc_status_t */
    uint32_t ack_seq_num;   /**< Sequence number being acknowledged */
} pqc_ack_msg_t;

#ifdef __cplusplus
}
#endif

#endif /* PQC_PROTOCOL_H */
