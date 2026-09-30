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
static uint32_t s_tx_seq = 1;

static net_client_rx_callback_t s_rx_callback = NULL;

static void udp_rx_handler(uint32_t src_ip, uint16_t src_port, uint16_t dst_port, void *data, uint32_t length)
{
    if (dst_port != s_local_port) {
        return;
    }

    if (length < sizeof(pqc_header_t)) {
        return;
    }

    const pqc_header_t *hdr = (const pqc_header_t *)data;

    /* Validate magic and protocol version */
    if (hdr->magic != PQC_PROTOCOL_MAGIC) {
        return;
    }

    if (hdr->version != PQC_PROTOCOL_VERSION) {
        return;
    }

    uint16_t payload_len = hdr->payload_len;
    if ((uint32_t)(sizeof(pqc_header_t) + payload_len) > length) {
        return;
    }

    const uint8_t *payload = (const uint8_t *)data + sizeof(pqc_header_t);

    if (s_rx_callback) {
        s_rx_callback(hdr->msg_type, payload, payload_len, hdr->seq_num);
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

void net_client_set_rx_callback(net_client_rx_callback_t cb)
{
    s_rx_callback = cb;
}

int net_client_resolve_server(void)
{
    return udp_arp_resolve(s_server_ip);
}

int net_client_send_msg(uint8_t msg_type,
                        const void *payload,
                        uint16_t payload_len)
{
    void *tx_buf = udp_get_tx_buffer();
    if (!tx_buf) return -1;

    pqc_header_t *hdr = (pqc_header_t *)tx_buf;
    hdr->magic       = PQC_PROTOCOL_MAGIC;
    hdr->version     = PQC_PROTOCOL_VERSION;
    hdr->msg_type    = msg_type;
    hdr->payload_len = payload_len;
    hdr->seq_num     = s_tx_seq++;

    if (payload && payload_len > 0) {
        memcpy((uint8_t *)tx_buf + sizeof(pqc_header_t), payload, payload_len);
    }

    uint32_t total_len = sizeof(pqc_header_t) + payload_len;
    int ret = udp_send(s_local_port, s_server_port, total_len);
    if (!ret) return -2;

    return (int)payload_len;
}

void net_client_service(void)
{
    udp_service();
}
