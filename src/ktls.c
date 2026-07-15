/**
 * @file ktls.c
 * @brief Best-effort Kernel TLS enablement via OpenSSL SSL_OP_ENABLE_KTLS.
 *
 * OpenSSL installs kTLS on the socket BIO after the handshake when the
 * selected cipher is supported (typically AES-GCM). Callers must use
 * SSL_set_fd (socket BIO), not memory BIOs, for this to succeed.
 */

#include "pqproxy_internal.h"

#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <netinet/tcp.h>
#include <sys/socket.h>

#ifndef TCP_ULP
#define TCP_ULP 31
#endif

void pqproxy_tls_enable_ktls_ctx(SSL_CTX *ctx)
{
    if (!ctx) {
        return;
    }
#ifdef SSL_OP_ENABLE_KTLS
    SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
#endif
#ifdef SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE
    SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE);
#endif
}

int pqproxy_ktls_query(SSL *ssl, int *tx_on, int *rx_on)
{
    BIO *rbio;
    BIO *wbio;
    if (tx_on) {
        *tx_on = 0;
    }
    if (rx_on) {
        *rx_on = 0;
    }
    if (!ssl) {
        return -1;
    }
    wbio = SSL_get_wbio(ssl);
    rbio = SSL_get_rbio(ssl);
    if (tx_on && wbio) {
        *tx_on = BIO_get_ktls_send(wbio) ? 1 : 0;
    }
    if (rx_on && rbio) {
        *rx_on = BIO_get_ktls_recv(rbio) ? 1 : 0;
    }
    return 0;
}

int pqproxy_ktls_note_after_handshake(SSL *ssl, int quiet)
{
    int tx = 0, rx = 0;
    const char *cipher;

    if (!ssl) {
        return -1;
    }
    (void)pqproxy_ktls_query(ssl, &tx, &rx);
    cipher = SSL_get_cipher_name(ssl);
    if (!quiet) {
        fprintf(stderr, "pqproxy: TLS handshake ok cipher=%s ktls_tx=%d ktls_rx=%d\n",
                cipher ? cipher : "?", tx, rx);
    }
    /* Returning 1 if either direction offloaded; 0 if software path. */
    return (tx || rx) ? 1 : 0;
}
