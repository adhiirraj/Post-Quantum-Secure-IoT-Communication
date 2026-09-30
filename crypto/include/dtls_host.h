#ifndef DTLS_HOST_H
#define DTLS_HOST_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dtls_host_session dtls_host_session;

dtls_host_session *dtls_host_server_new(const unsigned char *server_cert, int server_cert_len,
                                        const unsigned char *server_key, int server_key_len,
                                        const unsigned char *ca_cert, int ca_cert_len);
void dtls_host_free(dtls_host_session *session);

int dtls_host_feed(dtls_host_session *session, const unsigned char *packet, int packet_len);
int dtls_host_handshake(dtls_host_session *session);
int dtls_host_read(dtls_host_session *session, unsigned char *out, int out_len);
int dtls_host_write(dtls_host_session *session, const unsigned char *data, int data_len);
int dtls_host_drain(dtls_host_session *session, unsigned char *out, int out_len);
int dtls_host_last_error(const dtls_host_session *session);
int dtls_host_is_connected(const dtls_host_session *session);
const char *dtls_host_cipher_name(const dtls_host_session *session);

#ifdef __cplusplus
}
#endif

#endif /* DTLS_HOST_H */
