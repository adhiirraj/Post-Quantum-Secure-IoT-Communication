/**
 * @file client_pqc.c
 * @brief Post-Quantum Cryptography IoT Client Implementation via wolfSSL DTLS 1.3
 */

#include "client_pqc.h"
#include "net_client.h"
#include "../../common/mldsa_identity.h"

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

static WOLFSSL_CTX *s_ctx = NULL;
static WOLFSSL *s_ssl = NULL;
static pqc_client_state_t s_state = PQC_CLIENT_STATE_INIT;
static uint32_t s_telemetry_counter = 0;

/* Custom IO callbacks mapping wolfSSL to our bare-metal UDP driver */
static int my_IO_Send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    (void)ctx;
    int ret = net_client_send_raw(buf, sz);
    if (ret < 0) {
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    }
    return ret;
}

static int my_IO_Recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    (void)ctx;
    int ret = net_client_recv_raw(buf, sz);
    if (ret < 0) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    return ret;
}

int client_pqc_init(void)
{
    printf("[CLIENT] Initializing wolfSSL DTLS 1.3 Context...\n");
    wolfSSL_Init();

    s_ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
    if (!s_ctx) {
        printf("[-] Failed to create WOLFSSL_CTX\n");
        s_state = PQC_CLIENT_STATE_ERROR;
        return -1;
    }

    /* Configure cipher suite */
    if (wolfSSL_CTX_set_cipher_list(s_ctx, "TLS_AES_256_GCM_SHA384") != WOLFSSL_SUCCESS) {
        printf("[-] Failed to set cipher suite\n");
        return -1;
    }

    /* Load ML-DSA Client Identity */
    printf("[CLIENT] Loading ML-DSA-44 Identity...\n");
    if (wolfSSL_CTX_use_certificate_buffer(s_ctx, g_client_mldsa_pubkey, sizeof(g_client_mldsa_pubkey), WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        printf("[-] Failed to load client ML-DSA pubkey\n");
        return -1;
    }

    if (wolfSSL_CTX_use_PrivateKey_buffer(s_ctx, g_client_mldsa_privkey, sizeof(g_client_mldsa_privkey), WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        printf("[-] Failed to load client ML-DSA privkey\n");
        return -1;
    }

    /* Configure Peer Verification (Gateway Server's ML-DSA cert) */
    wolfSSL_CTX_set_verify(s_ctx, WOLFSSL_VERIFY_PEER, NULL);
    if (wolfSSL_CTX_load_verify_buffer(s_ctx, g_server_mldsa_pubkey, sizeof(g_server_mldsa_pubkey), WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        printf("[-] Failed to load Gateway CA ML-DSA pubkey\n");
        return -1;
    }

    s_ssl = wolfSSL_new(s_ctx);
    if (!s_ssl) {
        printf("[-] Failed to create WOLFSSL object\n");
        return -1;
    }

    /* Configure ML-KEM-512 Key Exchange */
    if (wolfSSL_UseKeyShare(s_ssl, WOLFSSL_ML_KEM_512) != WOLFSSL_SUCCESS) {
        printf("[-] Failed to set ML-KEM-512 KeyShare\n");
        return -1;
    }

    /* Register Custom IO Callbacks */
    wolfSSL_SetIOSend(s_ctx, my_IO_Send);
    wolfSSL_SetIORecv(s_ctx, my_IO_Recv);

    s_state = PQC_CLIENT_STATE_DISCOVERY;
    return 0;
}

pqc_client_state_t client_pqc_get_state(void)
{
    return s_state;
}

int client_pqc_send_discovery(void)
{
    if (s_state != PQC_CLIENT_STATE_DISCOVERY && s_state != PQC_CLIENT_STATE_ENCAPSULATING) {
        return -1;
    }

    printf("\n[CLIENT] Initiating DTLS 1.3 Handshake with ML-KEM and ML-DSA...\n");
    s_state = PQC_CLIENT_STATE_ENCAPSULATING;
    
    int ret = wolfSSL_connect(s_ssl);
    if (ret != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(s_ssl, ret);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            /* Non-blocking wait, normal */
            return 0;
        } else {
            printf("[-] wolfSSL_connect failed: %d (err %d)\n", ret, err);
            char err_buf[80];
            wolfSSL_ERR_error_string(err, err_buf);
            printf("[-] Reason: %s\n", err_buf);
            s_state = PQC_CLIENT_STATE_ERROR;
            return -1;
        }
    }

    printf(">>> [CLIENT] DTLS 1.3 Session ESTABLISHED with Gateway! <<<\n");
    
    WOLFSSL_CIPHER *cipher = wolfSSL_get_current_cipher(s_ssl);
    if (cipher) {
        printf("    Cipher Suite: %s\n", wolfSSL_CIPHER_get_name(cipher));
    }
    
    s_state = PQC_CLIENT_STATE_ESTABLISHED;
    return 0;
}

/* This replaces the old custom packet parser */
void client_pqc_on_rx_msg(uint8_t msg_type, const uint8_t *payload, uint16_t payload_len, uint32_t seq_num)
{
    (void)msg_type;
    (void)payload;
    (void)payload_len;
    (void)seq_num;
    /* Handled by DTLS rx loop now */
}

int client_pqc_send_telemetry(const char *telemetry_str)
{
    if (s_state != PQC_CLIENT_STATE_ESTABLISHED) {
        /* Still handshaking? Drive the state machine forward */
        if (s_state == PQC_CLIENT_STATE_ENCAPSULATING) {
            client_pqc_send_discovery();
        }
        return -1;
    }

    size_t plain_len = strlen(telemetry_str);
    s_telemetry_counter++;

    printf("[CLIENT] Transmitting Encrypted Telemetry #%u via DTLS (%u bytes plain)\n",
           (unsigned int)s_telemetry_counter, (unsigned int)plain_len);
    printf("         Plaintext preview: \"%s\"\n", telemetry_str);

    int ret = wolfSSL_write(s_ssl, telemetry_str, (int)plain_len);
    if (ret <= 0) {
        int err = wolfSSL_get_error(s_ssl, ret);
        printf("[-] DTLS write failed: %d\n", err);
        return -1;
    }

    /* Try to read any pending server response */
    char rx_buf[256];
    ret = wolfSSL_read(s_ssl, rx_buf, sizeof(rx_buf) - 1);
    if (ret > 0) {
        rx_buf[ret] = '\0';
        printf("[CLIENT] Received DTLS Payload: %s\n", rx_buf);
    }

    return 0;
}
