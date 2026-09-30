/**
 * @file net_client.c
 * @brief LiteX bare-metal Ethernet/UDP network client implementation
 */

#include "net_client.h"
#include <stdio.h>
#include <string.h>

#include <generated/csr.h>
#include <generated/soc.h>
#include <libliteeth/udp.h>
#include <libliteeth/inet.h>

static uint8_t s_mac[6];
static uint32_t s_local_ip;
static uint32_t s_server_ip;
static uint16_t s_server_port;
static uint16_t s_local_port;

#define RX_BUFFER_SIZE 2048
static uint8_t rx_buffer[RX_BUFFER_SIZE];
static uint16_t rx_len = 0;

static void udp_rx_handler(uint32_t src_ip, uint16_t src_port, uint16_t dst_port, void *data, uint32_t length)
{
    if (dst_port != s_local_port) {
        return;
    }

    if (length > RX_BUFFER_SIZE) {
        printf("[-] UDP RX dropped, too large: %u\n", (unsigned int)length);
        return;
    }
    
    if (rx_len == 0) {
        memcpy(rx_buffer, data, length);
        rx_len = length;
    }
}

int net_client_init(const uint8_t *mac,
                    uint32_t local_ip,
                    uint32_t server_ip,
                    uint16_t server_port,
                    uint16_t local_port)
{
    if (!mac) return -1;

    memcpy(s_mac, mac, 6);
    s_local_ip   = local_ip;
    s_server_ip  = server_ip;
    s_server_port = server_port;
    s_local_port  = local_port;

    udp_start(s_mac, s_local_ip);
    udp_set_callback(udp_rx_handler);

    return 0;
}

int net_client_resolve_server(void)
{
    return udp_arp_resolve(s_server_ip);
}

int net_client_send_raw(const void *payload, uint16_t payload_len)
{
    void *tx_buf = udp_get_tx_buffer();
    if (!tx_buf) return -1;

    if (payload && payload_len > 0) {
        memcpy(tx_buf, payload, payload_len);
    }

    int ret = udp_send(s_local_port, s_server_port, payload_len);
    if (!ret) return -2;

    return (int)payload_len;
}

int net_client_recv_raw(void *payload, uint16_t max_len)
{
    if (rx_len == 0) {
        return -1;
    }

    uint16_t copy_len = rx_len > max_len ? max_len : rx_len;
    memcpy(payload, rx_buffer, copy_len);
    
    // In DTLS, each UDP datagram is a record or fragment. We consume the whole datagram.
    int ret_len = copy_len;
    rx_len = 0; // Clear buffer
    
    return ret_len;
}

void net_client_service(void)
{
    udp_service();
}
