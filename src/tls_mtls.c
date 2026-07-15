/**
 * @file tls_mtls.c
 * @brief OpenSSL TLS context for mTLS (server + required client cert).
 */

#include "pqproxy_internal.h"

#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

SSL_CTX *pqproxy_tls_ctx_create(const pqproxy_config_t *cfg)
{
    SSL_CTX *ctx;
    long mode;

    if (!cfg || cfg->plain) {
        return NULL;
    }
    if (!cfg->cert_file || !cfg->key_file) {
        fprintf(stderr, "pqproxy: TLS requires --cert and --key\n");
        return NULL;
    }

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fprintf(stderr, "pqproxy: SSL_CTX_new failed\n");
        return NULL;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    mode = SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;
    SSL_CTX_set_mode(ctx, mode);

    if (SSL_CTX_use_certificate_chain_file(ctx, cfg->cert_file) != 1) {
        fprintf(stderr, "pqproxy: failed to load cert %s\n", cfg->cert_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, cfg->key_file, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "pqproxy: failed to load key %s\n", cfg->key_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "pqproxy: cert/key mismatch\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (cfg->require_mtls) {
        if (!cfg->ca_file) {
            fprintf(stderr, "pqproxy: mTLS requires --ca\n");
            SSL_CTX_free(ctx);
            return NULL;
        }
        if (SSL_CTX_load_verify_locations(ctx, cfg->ca_file, NULL) != 1) {
            fprintf(stderr, "pqproxy: failed to load CA %s\n", cfg->ca_file);
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return NULL;
        }
        SSL_CTX_set_verify(ctx,
                           SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                           NULL);
        SSL_CTX_set_verify_depth(ctx, 4);
    }

    return ctx;
}

void pqproxy_tls_ctx_free(SSL_CTX *ctx)
{
    if (ctx) {
        SSL_CTX_free(ctx);
    }
}

SSL *pqproxy_tls_conn_new(SSL_CTX *ctx)
{
    SSL *ssl;
    BIO *rbio;
    BIO *wbio;

    if (!ctx) {
        return NULL;
    }
    ssl = SSL_new(ctx);
    if (!ssl) {
        return NULL;
    }
    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());
    if (!rbio || !wbio) {
        BIO_free(rbio);
        BIO_free(wbio);
        SSL_free(ssl);
        return NULL;
    }
    BIO_set_mem_eof_return(rbio, -1);
    BIO_set_mem_eof_return(wbio, -1);
    SSL_set_bio(ssl, rbio, wbio);
    SSL_set_accept_state(ssl);
    return ssl;
}

int pqproxy_tls_identity(SSL *ssl, pqproxy_identity_t *out)
{
    X509 *peer;

    if (!ssl || !out) {
        return -1;
    }
    peer = SSL_get_peer_certificate(ssl);
    if (!peer) {
        return -1;
    }
    if (pqproxy_identity_from_x509(peer, out) != 0) {
        X509_free(peer);
        return -1;
    }
    X509_free(peer);
    return 0;
}

int pqproxy_tls_feed_encrypted(SSL *ssl, const uint8_t *data, size_t len)
{
    BIO *rbio;
    int n;

    if (!ssl || (!data && len > 0)) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    rbio = SSL_get_rbio(ssl);
    if (!rbio) {
        return -1;
    }
    n = BIO_write(rbio, data, (int)len);
    if (n <= 0 || (size_t)n != len) {
        return -1;
    }
    return 0;
}

int pqproxy_tls_drain_encrypted(SSL *ssl, uint8_t *out, size_t out_cap, size_t *out_len)
{
    BIO *wbio;
    int n;

    if (!ssl || !out || !out_len || out_cap == 0) {
        return -1;
    }
    *out_len = 0;
    wbio = SSL_get_wbio(ssl);
    if (!wbio) {
        return -1;
    }
    n = BIO_read(wbio, out, (int)out_cap);
    if (n > 0) {
        *out_len = (size_t)n;
        return 1;
    }
    return 0;
}

int pqproxy_tls_handshake(SSL *ssl)
{
    int rc;
    if (!ssl) {
        return -1;
    }
    if (SSL_is_init_finished(ssl)) {
        return 1;
    }
    rc = SSL_do_handshake(ssl);
    if (rc == 1) {
        return 1;
    }
    rc = SSL_get_error(ssl, rc);
    if (rc == SSL_ERROR_WANT_READ || rc == SSL_ERROR_WANT_WRITE) {
        return 0; /* in progress */
    }
    return -1;
}

int pqproxy_tls_read_plain(SSL *ssl, uint8_t *out, size_t out_cap, size_t *out_len)
{
    int n;
    if (!ssl || !out || !out_len || out_cap == 0) {
        return -1;
    }
    *out_len = 0;
    n = SSL_read(ssl, out, (int)out_cap);
    if (n > 0) {
        *out_len = (size_t)n;
        return 1;
    }
    n = SSL_get_error(ssl, n);
    if (n == SSL_ERROR_WANT_READ || n == SSL_ERROR_WANT_WRITE ||
        n == SSL_ERROR_WANT_CLIENT_HELLO_CB) {
        return 0;
    }
    if (n == SSL_ERROR_ZERO_RETURN) {
        return -2; /* clean close */
    }
    return -1;
}

int pqproxy_tls_write_plain(SSL *ssl, const uint8_t *data, size_t len, size_t *written)
{
    int n;
    if (!ssl || !data || !written) {
        return -1;
    }
    *written = 0;
    if (len == 0) {
        return 1;
    }
    n = SSL_write(ssl, data, (int)len);
    if (n > 0) {
        *written = (size_t)n;
        return 1;
    }
    n = SSL_get_error(ssl, n);
    if (n == SSL_ERROR_WANT_READ || n == SSL_ERROR_WANT_WRITE) {
        return 0;
    }
    return -1;
}
