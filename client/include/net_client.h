/**
 * @file net_client.h
 * @brief Low-level network client interface for LiteX bare-metal Ethernet/UDP
 */

#ifndef NET_CLIENT_H
#define NET_CLIENT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int net_client_init(const uint8_t *mac,
                    uint32_t local_ip,
                    uint32_t server_ip,
                    uint16_t server_port,
                    uint16_t local_port);

int net_client_send_raw(const void *payload, uint16_t payload_len);

int net_client_recv_raw(void *payload, uint16_t max_len);

void net_client_service(void);

int net_client_resolve_server(void);

#ifdef __cplusplus
}
#endif

#endif /* NET_CLIENT_H */
