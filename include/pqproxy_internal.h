#ifndef PQPROXY_INTERNAL_H
#define PQPROXY_INTERNAL_H

#include "pqproxy.h"

#include <openssl/ssl.h>

/* TLS helpers (tls_mtls.c) */
SSL_CTX *pqproxy_tls_ctx_create(const pqproxy_config_t *cfg);
void pqproxy_tls_ctx_free(SSL_CTX *ctx);
SSL *pqproxy_tls_conn_new(SSL_CTX *ctx);
int pqproxy_tls_identity(SSL *ssl, pqproxy_identity_t *out);

/** Feed ciphertext from socket into SSL rbio. Returns 0 on success. */
int pqproxy_tls_feed_encrypted(SSL *ssl, const uint8_t *data, size_t len);

/** Drain ciphertext from SSL wbio into out. Returns bytes or 0. */
int pqproxy_tls_drain_encrypted(SSL *ssl, uint8_t *out, size_t out_cap, size_t *out_len);

/**
 * Drive handshake. Returns 1 finished, 0 need more I/O, -1 error.
 * Caller must drain wbio and submit send after each call.
 */
int pqproxy_tls_handshake(SSL *ssl);

/** SSL_read into plain buffer. Returns 1 data, 0 want I/O, -1 error, -2 EOF. */
int pqproxy_tls_read_plain(SSL *ssl, uint8_t *out, size_t out_cap, size_t *out_len);

/** SSL_write plain. Returns 1 ok, 0 want I/O, -1 error. */
int pqproxy_tls_write_plain(SSL *ssl, const uint8_t *data, size_t len, size_t *written);

/* Connection + io_uring (iouring_loop.c) — implemented as pqproxy_run */

#endif /* PQPROXY_INTERNAL_H */
