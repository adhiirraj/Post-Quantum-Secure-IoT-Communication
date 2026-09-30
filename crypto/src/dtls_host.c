/* Native wolfSSL DTLS 1.3 server adapter used by server/crypto_backend.py. */

#include "dtls_host.h"

#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define DTLS_HOST_MTU         8192
#define DTLS_HOST_PACKET_QUEUE 16

struct dtls_host_session {
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
    unsigned char input[DTLS_HOST_MTU];
    int input_len;
    unsigned char output[DTLS_HOST_PACKET_QUEUE][DTLS_HOST_MTU];
    int output_len[DTLS_HOST_PACKET_QUEUE];
    int output_head;
    int output_count;
    int connected;
    int last_error;
};

static int host_send(WOLFSSL *ssl, char *buf, int sz, void *io_ctx)
{
    struct dtls_host_session *session = (struct dtls_host_session *)io_ctx;
    int slot;
    (void)ssl;
    if (session == NULL || buf == NULL || sz < 0 || sz > DTLS_HOST_MTU ||
        session->output_count == DTLS_HOST_PACKET_QUEUE) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    slot = (session->output_head + session->output_count) % DTLS_HOST_PACKET_QUEUE;
    memcpy(session->output[slot], buf, (size_t)sz);
    session->output_len[slot] = sz;
    session->output_count++;
    return sz;
}

static int host_recv(WOLFSSL *ssl, char *buf, int sz, void *io_ctx)
{
    struct dtls_host_session *session = (struct dtls_host_session *)io_ctx;
    int copy_len;
    (void)ssl;
    if (session == NULL || buf == NULL || sz <= 0) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    if (session->input_len == 0) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    copy_len = session->input_len;
    if (copy_len > sz) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    memcpy(buf, session->input, (size_t)copy_len);
    session->input_len = 0;
    return copy_len;
}

static void clear_session(struct dtls_host_session *session)
{
    if (session == NULL) return;
    if (session->ssl != NULL) wolfSSL_free(session->ssl);
    if (session->ctx != NULL) wolfSSL_CTX_free(session->ctx);
    free(session);
}

dtls_host_session *dtls_host_server_new(const unsigned char *server_cert, int server_cert_len,
                                        const unsigned char *server_key, int server_key_len,
                                        const unsigned char *ca_cert, int ca_cert_len)
{
    struct dtls_host_session *session;
    int ret;

    if (server_cert == NULL || server_key == NULL || ca_cert == NULL ||
        server_cert_len <= 0 || server_key_len <= 0 || ca_cert_len <= 0) {
        return NULL;
    }
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) return NULL;

    session = (struct dtls_host_session *)calloc(1, sizeof(*session));
    if (session == NULL) return NULL;
    session->ctx = wolfSSL_CTX_new(wolfDTLSv1_3_server_method());
    if (session->ctx == NULL) goto error;
    if (wolfSSL_CTX_set_cipher_list(session->ctx, "TLS_AES_256_GCM_SHA384") != WOLFSSL_SUCCESS)
        goto error;
    if (wolfSSL_CTX_use_certificate_buffer(session->ctx, server_cert, server_cert_len,
                                           WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
        goto error;
    if (wolfSSL_CTX_use_PrivateKey_buffer(session->ctx, server_key, server_key_len,
                                          WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
        goto error;
    if (wolfSSL_CTX_load_verify_buffer(session->ctx, ca_cert, ca_cert_len,
                                       WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
        goto error;
    wolfSSL_CTX_set_verify(session->ctx,
        WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    wolfSSL_CTX_SetIORecv(session->ctx, host_recv);
    wolfSSL_CTX_SetIOSend(session->ctx, host_send);

    session->ssl = wolfSSL_new(session->ctx);
    if (session->ssl == NULL) goto error;
    ret = wolfSSL_UseKeyShare(session->ssl, WOLFSSL_ML_KEM_512);
    if (ret != WOLFSSL_SUCCESS) goto error;
    if (wolfSSL_dtls_set_mtu(session->ssl, DTLS_HOST_MTU) != WOLFSSL_SUCCESS) goto error;
    wolfSSL_SetIOReadCtx(session->ssl, session);
    wolfSSL_SetIOWriteCtx(session->ssl, session);
    return session;

error:
    clear_session(session);
    return NULL;
}

void dtls_host_free(dtls_host_session *session)
{
    clear_session(session);
}

int dtls_host_feed(dtls_host_session *session, const unsigned char *packet, int packet_len)
{
    if (session == NULL || packet == NULL || packet_len <= 0 || packet_len > DTLS_HOST_MTU ||
        session->input_len != 0) return -1;
    memcpy(session->input, packet, (size_t)packet_len);
    session->input_len = packet_len;
    return 0;
}

int dtls_host_handshake(dtls_host_session *session)
{
    int ret;
    if (session == NULL || session->ssl == NULL) return -1;
    ret = wolfSSL_accept(session->ssl);
    if (ret == WOLFSSL_SUCCESS) {
        session->connected = 1;
        return 1;
    }
    session->last_error = wolfSSL_get_error(session->ssl, ret);
    if (session->last_error == WOLFSSL_ERROR_WANT_READ ||
        session->last_error == WOLFSSL_ERROR_WANT_WRITE) return 0;
    return -1;
}

int dtls_host_read(dtls_host_session *session, unsigned char *out, int out_len)
{
    int ret;
    if (session == NULL || session->ssl == NULL || out == NULL || out_len <= 0) return -1;
    ret = wolfSSL_read(session->ssl, out, out_len);
    if (ret > 0) return ret;
    session->last_error = wolfSSL_get_error(session->ssl, ret);
    if (session->last_error == WOLFSSL_ERROR_WANT_READ ||
        session->last_error == WOLFSSL_ERROR_WANT_WRITE) return 0;
    return -1;
}

int dtls_host_write(dtls_host_session *session, const unsigned char *data, int data_len)
{
    int ret;
    if (session == NULL || session->ssl == NULL || data == NULL || data_len <= 0) return -1;
    ret = wolfSSL_write(session->ssl, data, data_len);
    if (ret > 0) return ret;
    session->last_error = wolfSSL_get_error(session->ssl, ret);
    if (session->last_error == WOLFSSL_ERROR_WANT_READ ||
        session->last_error == WOLFSSL_ERROR_WANT_WRITE) return 0;
    return -1;
}

int dtls_host_drain(dtls_host_session *session, unsigned char *out, int out_len)
{
    int length;
    if (session == NULL || out == NULL || out_len <= 0 || session->output_count == 0) return 0;
    length = session->output_len[session->output_head];
    if (length > out_len) return -1;
    memcpy(out, session->output[session->output_head], (size_t)length);
    session->output_head = (session->output_head + 1) % DTLS_HOST_PACKET_QUEUE;
    session->output_count--;
    return length;
}

int dtls_host_last_error(const dtls_host_session *session)
{
    return session == NULL ? 0 : session->last_error;
}

int dtls_host_is_connected(const dtls_host_session *session)
{
    return session != NULL && session->connected;
}

const char *dtls_host_cipher_name(const dtls_host_session *session)
{
    const WOLFSSL_CIPHER *cipher;
    if (session == NULL || session->ssl == NULL) return NULL;
    cipher = wolfSSL_get_current_cipher(session->ssl);
    return cipher == NULL ? NULL : wolfSSL_CIPHER_get_name(cipher);
}
