#ifndef PQPROXY_INTERNAL_H
#define PQPROXY_INTERNAL_H

#include "pqproxy.h"
#include "backend_pool.h"

#include <openssl/ssl.h>

/* TLS helpers (tls_mtls.c) */
SSL_CTX *pqproxy_tls_ctx_create(const pqproxy_config_t *cfg);
void pqproxy_tls_ctx_free(SSL_CTX *ctx);

/** Memory-BIO SSL (legacy path; no kTLS). */
SSL *pqproxy_tls_conn_new(SSL_CTX *ctx);

/** Socket-BIO SSL for kTLS (SSL_set_fd). Preferred. */
SSL *pqproxy_tls_conn_new_fd(SSL_CTX *ctx, int fd);

int pqproxy_tls_identity(SSL *ssl, pqproxy_identity_t *out);

/** Feed ciphertext from socket into SSL rbio (memory-BIO path). */
int pqproxy_tls_feed_encrypted(SSL *ssl, const uint8_t *data, size_t len);
int pqproxy_tls_drain_encrypted(SSL *ssl, uint8_t *out, size_t out_cap, size_t *out_len);

/** Drive handshake. Returns 1 finished, 0 need more I/O, -1 error. */
int pqproxy_tls_handshake(SSL *ssl);

/** SSL_read plain. Returns 1 data, 0 want I/O, -1 error, -2 EOF. */
int pqproxy_tls_read_plain(SSL *ssl, uint8_t *out, size_t out_cap, size_t *out_len);

/** SSL_write plain. Returns 1 ok, 0 want I/O, -1 error. */
int pqproxy_tls_write_plain(SSL *ssl, const uint8_t *data, size_t len, size_t *written);

/* kTLS (ktls.c) */
void pqproxy_tls_enable_ktls_ctx(SSL_CTX *ctx);
int pqproxy_ktls_query(SSL *ssl, int *tx_on, int *rx_on);
int pqproxy_ktls_note_after_handshake(SSL *ssl, int quiet);

#endif /* PQPROXY_INTERNAL_H */
