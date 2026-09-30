/**
 * @file client_pqc.c
 * @brief Post-Quantum Cryptography IoT Client Implementation
 */

#include "client_pqc.h"
#include "net_client.h"
#include "pqc_kem.h"
#include "aes_gcm.h"

#include <stdio.h>
#include <string.h>
#include <wolfssl/wolfcrypt/random.h>

static pqc_client_state_t s_state = PQC_CLIENT_STATE_INIT;
static WC_RNG s_rng;
static uint8_t s_shared_secret[PQC_KEM_SHARED_SECRET_SIZE];
static uint32_t s_telemetry_counter = 0;

int client_pqc_init(void)
{
    int ret = pqc_kem_rng_init(&s_rng);
    if (ret != 0) {
        printf("[-] Failed to initialize RNG: %d\n", ret);
        s_state = PQC_CLIENT_STATE_ERROR;
        return ret;
    }

    s_state = PQC_CLIENT_STATE_DISCOVERY;
    return 0;
}

pqc_client_state_t client_pqc_get_state(void)
{
    return s_state;
}

int client_pqc_send_discovery(void)
{
    printf("[CLIENT] Sending Discovery Request to PQC Gateway...\n");
    return net_client_send_msg(PQC_MSG_DISCOVERY_REQ, NULL, 0);
}

void client_pqc_on_rx_msg(uint8_t msg_type,
                          const uint8_t *payload,
                          uint16_t payload_len,
                          uint32_t seq_num)
{
    switch (msg_type) {
    case PQC_MSG_KEM_PUBLIC_KEY: {
        printf("\n[CLIENT] Received Gateway ML-KEM-512 Public Key (%u bytes, seq=%u)\n",
               (unsigned int)payload_len, (unsigned int)seq_num);

        if (payload_len != PQC_KEM_PUBLIC_KEY_SIZE) {
            printf("[-] Invalid Public Key size: %u\n", (unsigned int)payload_len);
            return;
        }

        s_state = PQC_CLIENT_STATE_ENCAPSULATING;

        /* Encapsulate shared secret using Gateway's Public Key */
        static uint8_t ciphertext[PQC_KEM_CIPHERTEXT_SIZE];
        printf("[CLIENT] Encapsulating shared secret via ML-KEM-512...\n");

        int ret = pqc_kem_encapsulate(payload,
                                      payload_len,
                                      ciphertext,
                                      sizeof(ciphertext),
                                      s_shared_secret,
                                      sizeof(s_shared_secret),
                                      &s_rng);
        if (ret != 0) {
            printf("[-] ML-KEM encapsulation failed: %d\n", ret);
            s_state = PQC_CLIENT_STATE_ERROR;
            return;
        }

        printf("[CLIENT] Derived 256-bit PQC Session Key: ");
        for (int i = 0; i < 16; i++) printf("%02x", s_shared_secret[i]);
        printf("...\n");

        /* Send Ciphertext back to Gateway */
        printf("[CLIENT] Transmitting KEM Ciphertext (%d bytes) to Gateway...\n",
               PQC_KEM_CIPHERTEXT_SIZE);
        net_client_send_msg(PQC_MSG_KEM_CIPHERTEXT, ciphertext, sizeof(ciphertext));

        s_state = PQC_CLIENT_STATE_ESTABLISHED;
        printf(">>> [CLIENT] PQC Secure Channel ESTABLISHED with Gateway! <<<\n\n");
        break;
    }

    case PQC_MSG_ACK: {
        if (payload_len >= sizeof(pqc_ack_msg_t)) {
            const pqc_ack_msg_t *ack = (const pqc_ack_msg_t *)payload;
            printf("[CLIENT] Received Gateway ACK (status=%u, ack_seq=%u)\n",
                   (unsigned int)ack->status_code, (unsigned int)ack->ack_seq_num);
        }
        break;
    }

    default:
        printf("[CLIENT] Received unhandled message type 0x%02x\n", msg_type);
        break;
    }
}

int client_pqc_send_telemetry(const char *telemetry_str)
{
    if (s_state != PQC_CLIENT_STATE_ESTABLISHED) {
        printf("[-] Cannot send telemetry: secure channel not established\n");
        return -1;
    }

    size_t plain_len = strlen(telemetry_str);
    if (plain_len > 512) plain_len = 512;

    /* Build secure payload: IV (12B) + Tag (16B) + Ciphertext */
    uint8_t packet_buf[12 + 16 + 512];
    uint8_t *iv = packet_buf;
    uint8_t *tag = packet_buf + PQC_AES_GCM_IV_SIZE;
    uint8_t *ciphertext = packet_buf + PQC_AES_GCM_IV_SIZE + PQC_AES_GCM_TAG_SIZE;

    /* Generate random IV nonce */
    int ret = wc_RNG_GenerateBlock(&s_rng, iv, PQC_AES_GCM_IV_SIZE);
    if (ret != 0) {
        printf("[-] Failed to generate IV nonce: %d\n", ret);
        return ret;
    }

    /* Encrypt telemetry with AES-256-GCM using derived PQC session key */
    ret = pqc_aes_gcm_encrypt(s_shared_secret,
                              PQC_AES_KEY_SIZE,
                              iv,
                              PQC_AES_GCM_IV_SIZE,
                              NULL, 0,
                              (const uint8_t *)telemetry_str,
                              plain_len,
                              ciphertext,
                              tag,
                              PQC_AES_GCM_TAG_SIZE);
    if (ret != 0) {
        printf("[-] AES-256-GCM encryption failed: %d\n", ret);
        return ret;
    }

    uint16_t total_payload_len = PQC_AES_GCM_IV_SIZE + PQC_AES_GCM_TAG_SIZE + plain_len;
    s_telemetry_counter++;

    printf("[CLIENT] Transmitting Encrypted Telemetry #%u (%u bytes plain, %u bytes wire)\n",
           (unsigned int)s_telemetry_counter, (unsigned int)plain_len, total_payload_len);
    printf("         Plaintext preview: \"%s\"\n", telemetry_str);

    return net_client_send_msg(PQC_MSG_SECURE_PAYLOAD, packet_buf, total_payload_len);
}
