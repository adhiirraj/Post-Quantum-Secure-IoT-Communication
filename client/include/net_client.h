/**
 * @file net_client.h
 * @brief Low-level network client interface for LiteX bare-metal Ethernet/UDP
 */

#ifndef NET_CLIENT_H
#define NET_CLIENT_H

#include <stdint.h>
#include <stddef.h>
#include "protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Callback function type for received PQC protocol messages
 * @param msg_type Type of message (pqc_msg_type_t)
 * @param payload Pointer to message payload body
 * @param payload_len Length of payload body in bytes
 * @param seq_num Sequence number from packet header
 */
typedef void (*net_client_rx_callback_t)(uint8_t msg_type,
                                         const uint8_t *payload,
                                         uint16_t payload_len,
                                         uint32_t seq_num);

/**
 * @brief Initializes the bare-metal Ethernet and UDP networking stack.
 *
 * @param mac 6-byte hardware MAC address.
 * @param local_ip Local IPv4 address (e.g. IPTOINT(192, 168, 1, 50)).
 * @param server_ip Gateway/Server IPv4 address (e.g. IPTOINT(192, 168, 1, 100)).
 * @param server_port Gateway UDP port (e.g. PQC_DEFAULT_PORT = 11111).
 * @param local_port Local listening UDP port.
 * @return 0 on success, negative on error.
 */
int net_client_init(const uint8_t *mac,
                    uint32_t local_ip,
                    uint32_t server_ip,
                    uint16_t server_port,
                    uint16_t local_port);

/**
 * @brief Registers the application callback for incoming PQC messages.
 */
void net_client_set_rx_callback(net_client_rx_callback_t cb);

/**
 * @brief Sends a PQC protocol frame over UDP.
 *
 * Constructs a pqc_header_t, appends the payload, and transmits via libliteeth.
 *
 * @param msg_type PQC message type.
 * @param payload Pointer to payload buffer.
 * @param payload_len Length of payload.
 * @return Number of payload bytes sent, or negative on error.
 */
int net_client_send_msg(uint8_t msg_type,
                        const void *payload,
                        uint16_t payload_len);

/**
 * @brief Polling service function; processes incoming Ethernet frames and ARP.
 * Must be called continuously in the application main loop.
 */
void net_client_service(void);

/**
 * @brief Resolves server MAC address via ARP if necessary.
 * @return 1 on success, 0 on timeout/failure.
 */
int net_client_resolve_server(void);

#ifdef __cplusplus
}
#endif

#endif /* NET_CLIENT_H */
