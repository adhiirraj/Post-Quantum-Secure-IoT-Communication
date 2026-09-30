/**
 * @file client_pqc.h
 * @brief Post-Quantum Cryptography IoT Client State Machine
 */

#ifndef CLIENT_PQC_H
#define CLIENT_PQC_H

#include <stdint.h>
#include <stddef.h>
#include "protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PQC_CLIENT_STATE_INIT = 0,
    PQC_CLIENT_STATE_DISCOVERY,
    PQC_CLIENT_STATE_ENCAPSULATING,
    PQC_CLIENT_STATE_ESTABLISHED,
    PQC_CLIENT_STATE_ERROR
} pqc_client_state_t;

/**
 * @brief Initializes the PQC client state machine, entropy source, and crypto contexts.
 */
int client_pqc_init(void);

/**
 * @brief Handles incoming PQC messages from gateway/server.
 */
void client_pqc_on_rx_msg(uint8_t msg_type,
                          const uint8_t *payload,
                          uint16_t payload_len,
                          uint32_t seq_num);

/**
 * @brief Initiates post-quantum handshake by transmitting discovery request.
 */
int client_pqc_send_discovery(void);

/**
 * @brief Sends authenticated AES-256-GCM encrypted IoT telemetry payload to gateway.
 * @param telemetry_str Null-terminated JSON/telemetry string.
 */
int client_pqc_send_telemetry(const char *telemetry_str);

/**
 * @brief Returns current client state.
 */
pqc_client_state_t client_pqc_get_state(void);

#ifdef __cplusplus
}
#endif

#endif /* CLIENT_PQC_H */
