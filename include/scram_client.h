#ifndef PQPROXY_SCRAM_CLIENT_H
#define PQPROXY_SCRAM_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * PostgreSQL SCRAM-SHA-256 client (OpenSSL-backed).
 * Used for backend pool warm-up when the server requests auth type 10.
 */

typedef struct {
    char     username[128];
    char     client_nonce[32];
    char     server_nonce[128]; /* combined r= from server-first */
    uint8_t  salt[64];
    size_t   salt_len;
    uint32_t iterations;
    uint8_t  salted_password[32];
    uint8_t  client_key[32];
    uint8_t  stored_key[32];
    uint8_t  server_key[32];
    char     client_first_bare[256];
    char     auth_message[768];
    int      step; /* 0 init, 1 first sent, 2 final sent */
} pq_scram_t;

/** Initialize with username; generates client nonce. */
int pq_scram_init(pq_scram_t *s, const char *username);

/**
 * Build client-first-message-bare and GS2 header form for SASLInitialResponse.
 * gs2_out: "n,,n=user,r=nonce"  bare_out: "n=user,r=nonce"
 */
int pq_scram_client_first(pq_scram_t *s, char *gs2_out, size_t gs2_cap,
                          char *bare_out, size_t bare_cap);

/**
 * Parse server-first-message, run PBKDF2 with password.
 * server_first is NUL-terminated SCRAM text (r=...,s=...,i=...).
 */
int pq_scram_handle_server_first(pq_scram_t *s, const char *server_first,
                                 const char *password);

/**
 * Build client-final-message (without proof attribute list fully):
 * "c=biws,r=<server_nonce>,p=<base64 proof>"
 */
int pq_scram_client_final(pq_scram_t *s, char *out, size_t out_cap);

/**
 * Verify server-final-message "v=<base64 server signature>".
 * Returns 0 if signature matches.
 */
int pq_scram_verify_server_final(pq_scram_t *s, const char *server_final);

#ifdef __cplusplus
}
#endif

#endif /* PQPROXY_SCRAM_CLIENT_H */
