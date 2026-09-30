/**
 * @file main.c
 * @brief Bare-Metal Post-Quantum Secure IoT Node Entry Point
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <irq.h>
#include <libbase/uart.h>
#include <libbase/console.h>
#include <generated/csr.h>
#include <generated/soc.h>

#include <libliteeth/udp.h>
#include "protocol.h"
#include "net_client.h"
#include "client_pqc.h"

#include <sys/time.h>
#include <time.h>

int CustomRngGenerateBlock(unsigned char *output, unsigned int sz);

/* Bare-metal entropy source stub for wolfSSL RNG seeding */
int CustomRngGenerateBlock(unsigned char *output, unsigned int sz)
{
    for (unsigned int i = 0; i < sz; i++) {
        output[i] = (unsigned char)(i * 37 + 123);
    }
    return 0;
}

/* UNIX time stub for bare-metal targets */
int gettimeofday(struct timeval *tv, void *tz)
{
    if (tv) {
        tv->tv_sec = 0;
        tv->tv_usec = 0;
    }
    return 0;
}

/* Simple busy-wait delay using loop */
static void delay_cycles(volatile uint32_t count)
{
    while (count--) {
        __asm__ volatile("nop");
    }
}

int main(void)
{
#ifdef CONFIG_CPU_HAS_INTERRUPT
    irq_setmask(0);
    irq_setie(0);
#endif
    uart_init();

    printf("\n");
    printf("==============================================================\n");
    printf("     POST-QUANTUM SECURE IoT NODE (RISC-V BARE-METAL)         \n");
    printf("       LiteX / VexRiscv + wolfSSL ML-KEM-512 + AES-GCM        \n");
    printf("==============================================================\n\n");

    /* 1. Network configuration */
    const uint8_t mac[6] = {0x10, 0xe2, 0xd5, 0x00, 0x00, 0x00};
    uint32_t local_ip  = IPTOINT(192, 168, 1, 50);
    uint32_t server_ip = IPTOINT(192, 168, 1, 100);
    uint16_t server_port = PQC_DEFAULT_PORT;
    uint16_t local_port  = 11110;

    printf("[INIT] Configuring Ethernet & UDP...\n");
    printf("       Node MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    printf("       Node IP  : 192.168.1.50:%u\n", local_port);
    printf("       Target GW: 192.168.1.100:%u\n\n", server_port);

    if (net_client_init(mac, local_ip, server_ip, server_port, local_port) != 0) {
        printf("[-] Network initialization failed!\n");
        return 1;
    }

    /* 2. PQC Crypto initialization */
    printf("[INIT] Initializing Post-Quantum Cryptography engine...\n");
    if (client_pqc_init() != 0) {
        printf("[-] PQC initialization failed!\n");
        return 1;
    }
    printf("[+] ML-KEM-512 engine ready.\n\n");

    /* 3. Resolve Gateway MAC and send initial discovery request */
    printf("[INIT] Resolving Gateway ARP (192.168.1.100)...\n");
    if (net_client_resolve_server()) {
        printf("[+] Gateway ARP resolved successfully.\n");
    } else {
        printf("[*] Gateway ARP pending, will resolve during discovery loop.\n");
    }

    client_pqc_send_discovery();

    /* 4. Main Event Loop */
    printf("[LOOP] Entering IoT Node main service loop...\n\n");
    uint32_t loop_count = 0;
    uint32_t telemetry_seq = 1;

    while (1) {
        /* Process network descriptors */
        net_client_service();

        loop_count++;

        /* Periodically re-send discovery if not yet established */
        if (client_pqc_get_state() == PQC_CLIENT_STATE_DISCOVERY) {
            if ((loop_count % 25000) == 0) {
                net_client_resolve_server();
                client_pqc_send_discovery();
            }
        }
        /* Once established, periodically transmit encrypted sensor telemetry */
        else if (client_pqc_get_state() == PQC_CLIENT_STATE_ESTABLISHED) {
            if ((loop_count % 25000) == 0) {
                char telemetry_json[256];
                /* Generate simulated environmental telemetry */
                int temp_c_int = 24 + (loop_count % 5);
                int temp_c_dec = (loop_count % 10);
                int pressure   = 1013 + (loop_count % 3);

                snprintf(telemetry_json, sizeof(telemetry_json),
                         "{\"device\":\"RISCV-NODE-01\",\"seq\":%u,\"temp\":%d.%d,\"hPa\":%d,\"pqc_kem\":\"ML-KEM-512\"}",
                         (unsigned int)telemetry_seq++, temp_c_int, temp_c_dec, pressure);

                client_pqc_send_telemetry(telemetry_json);
            }
        }

        delay_cycles(10);
    }

    return 0;
}
