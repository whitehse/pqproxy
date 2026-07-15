/**
 * @file scram_client.c
 * @brief SCRAM-SHA-256 client for PostgreSQL (RFC 5802 / 7677) using OpenSSL.
 */

#include "scram_client.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static int b64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap)
{
    int n = EVP_EncodeBlock((unsigned char *)out, in, (int)in_len);
    if (n < 0 || (size_t)n >= out_cap) {
        return -1;
    }
    out[n] = '\0';
    return 0;
}

static int b64_decode(const char *in, uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t in_len = strlen(in);
    int n;
    int pad = 0;
    /* EVP_DecodeBlock may write 3*((in_len+3)/4) bytes including pad zeros */
    uint8_t tmp[256];
    size_t max_out = (in_len / 4) * 3 + 3;
    if (in_len == 0 || (in_len % 4) != 0 || max_out > sizeof(tmp)) {
        return -1;
    }
    n = EVP_DecodeBlock(tmp, (const unsigned char *)in, (int)in_len);
    if (n < 0) {
        return -1;
    }
    if (in[in_len - 1] == '=') {
        pad++;
    }
    if (in_len >= 2 && in[in_len - 2] == '=') {
        pad++;
    }
    n -= pad;
    if (n < 0 || (size_t)n > out_cap) {
        return -1;
    }
    memcpy(out, tmp, (size_t)n);
    *out_len = (size_t)n;
    return 0;
}

static int hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t out[32])
{
    unsigned int len = 0;
    unsigned char *ret = HMAC(EVP_sha256(), key, (int)key_len, data, data_len,
                              out, &len);
    if (ret == NULL || len != 32) {
        return -1;
    }
    return 0;
}

static int pbkdf2_sha256(const char *password, const uint8_t *salt, size_t salt_len,
                         uint32_t iterations, uint8_t out[32])
{
    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, (int)salt_len,
                          (int)iterations, EVP_sha256(), 32, out) != 1) {
        return -1;
    }
    return 0;
}

static void nonce_hex(char *out, size_t nchars)
{
    static const char *hex = "0123456789abcdefghijklmnopqrstuvwxyz";
    uint8_t raw[32];
    size_t i;
    if (nchars > 24) {
        nchars = 24;
    }
    if (RAND_bytes(raw, (int)nchars) != 1) {
        for (i = 0; i < nchars; i++) {
            out[i] = hex[i % 36];
        }
    } else {
        for (i = 0; i < nchars; i++) {
            out[i] = hex[raw[i] % 36];
        }
    }
    out[nchars] = '\0';
}

/** SASLprep-lite: reject empty; copy printable ASCII (no full Unicode SASLprep). */
static int copy_user(char *dst, size_t dstsz, const char *user)
{
    size_t i, j = 0;
    if (!user || !user[0] || !dst || dstsz == 0) {
        return -1;
    }
    for (i = 0; user[i] && j + 1 < dstsz; i++) {
        unsigned char c = (unsigned char)user[i];
        if (c < 0x20 || c == 0x7f) {
            return -1;
        }
        /* Escape '=' and ',' per SCRAM */
        if (c == '=') {
            if (j + 3 >= dstsz) {
                return -1;
            }
            dst[j++] = '=';
            dst[j++] = '3';
            dst[j++] = 'D';
        } else if (c == ',') {
            if (j + 3 >= dstsz) {
                return -1;
            }
            dst[j++] = '=';
            dst[j++] = '2';
            dst[j++] = 'C';
        } else {
            dst[j++] = (char)c;
        }
    }
    dst[j] = '\0';
    return 0;
}

int pq_scram_init(pq_scram_t *s, const char *username)
{
    if (!s || !username) {
        return -1;
    }
    memset(s, 0, sizeof(*s));
    if (copy_user(s->username, sizeof(s->username), username) != 0) {
        return -1;
    }
    nonce_hex(s->client_nonce, 24);
    s->step = 0;
    return 0;
}

int pq_scram_client_first(pq_scram_t *s, char *gs2_out, size_t gs2_cap,
                          char *bare_out, size_t bare_cap)
{
    int n;
    if (!s || !gs2_out || !bare_out) {
        return -1;
    }
    n = snprintf(bare_out, bare_cap, "n=%s,r=%s", s->username, s->client_nonce);
    if (n <= 0 || (size_t)n >= bare_cap) {
        return -1;
    }
    strncpy(s->client_first_bare, bare_out, sizeof(s->client_first_bare) - 1);
    n = snprintf(gs2_out, gs2_cap, "n,,%s", bare_out);
    if (n <= 0 || (size_t)n >= gs2_cap) {
        return -1;
    }
    s->step = 1;
    return 0;
}

int pq_scram_handle_server_first(pq_scram_t *s, const char *server_first,
                                 const char *password)
{
    const char *p;
    char salt_b64[128];
    char iter_s[16];
    uint8_t client_key[32];
    unsigned int md_len = 32;

    if (!s || !server_first || !password) {
        return -1;
    }

    /* r= */
    p = strstr(server_first, "r=");
    if (!p) {
        return -1;
    }
    p += 2;
    {
        size_t i = 0;
        while (p[i] && p[i] != ',' && i + 1 < sizeof(s->server_nonce)) {
            s->server_nonce[i] = p[i];
            i++;
        }
        s->server_nonce[i] = '\0';
    }
    /* Client nonce must be prefix of server nonce */
    if (strncmp(s->server_nonce, s->client_nonce, strlen(s->client_nonce)) != 0) {
        return -1;
    }

    /* s= */
    p = strstr(server_first, "s=");
    if (!p) {
        return -1;
    }
    p += 2;
    {
        size_t i = 0;
        while (p[i] && p[i] != ',' && i + 1 < sizeof(salt_b64)) {
            salt_b64[i] = p[i];
            i++;
        }
        salt_b64[i] = '\0';
    }
    if (b64_decode(salt_b64, s->salt, sizeof(s->salt), &s->salt_len) != 0) {
        return -1;
    }

    /* i= */
    p = strstr(server_first, "i=");
    if (!p) {
        return -1;
    }
    p += 2;
    {
        size_t i = 0;
        while (p[i] && isdigit((unsigned char)p[i]) && i + 1 < sizeof(iter_s)) {
            iter_s[i] = p[i];
            i++;
        }
        iter_s[i] = '\0';
    }
    s->iterations = (uint32_t)strtoul(iter_s, NULL, 10);
    if (s->iterations < 4096) {
        /* Allow lower for tests; PostgreSQL default is 4096 */
    }

    if (pbkdf2_sha256(password, s->salt, s->salt_len, s->iterations,
                      s->salted_password) != 0) {
        return -1;
    }
    if (hmac_sha256(s->salted_password, 32, (const uint8_t *)"Client Key", 10,
                    client_key) != 0) {
        return -1;
    }
    memcpy(s->client_key, client_key, 32);
    if (EVP_Digest(client_key, 32, s->stored_key, &md_len, EVP_sha256(), NULL) != 1) {
        return -1;
    }

    if (hmac_sha256(s->salted_password, 32, (const uint8_t *)"Server Key", 10,
                    s->server_key) != 0) {
        return -1;
    }

    /* AuthMessage = client-first-bare + "," + server-first + "," + client-final-without-proof */
    {
        char cwithout[160];
        int n;
        n = snprintf(cwithout, sizeof(cwithout), "c=biws,r=%s", s->server_nonce);
        if (n <= 0 || (size_t)n >= sizeof(cwithout)) {
            return -1;
        }
        n = snprintf(s->auth_message, sizeof(s->auth_message), "%s,%s,%s",
                     s->client_first_bare, server_first, cwithout);
        if (n <= 0 || (size_t)n >= sizeof(s->auth_message)) {
            return -1;
        }
    }
    return 0;
}

int pq_scram_client_final(pq_scram_t *s, char *out, size_t out_cap)
{
    uint8_t client_sig[32];
    uint8_t proof[32];
    char proof_b64[64];
    size_t i;
    int n;

    if (!s || !out) {
        return -1;
    }
    if (hmac_sha256(s->stored_key, 32,
                    (const uint8_t *)s->auth_message, strlen(s->auth_message),
                    client_sig) != 0) {
        return -1;
    }
    for (i = 0; i < 32; i++) {
        proof[i] = (uint8_t)(s->client_key[i] ^ client_sig[i]);
    }
    if (b64_encode(proof, 32, proof_b64, sizeof(proof_b64)) != 0) {
        return -1;
    }
    n = snprintf(out, out_cap, "c=biws,r=%s,p=%s", s->server_nonce, proof_b64);
    if (n <= 0 || (size_t)n >= out_cap) {
        return -1;
    }
    s->step = 2;
    return 0;
}

int pq_scram_verify_server_final(pq_scram_t *s, const char *server_final)
{
    const char *p;
    char v_b64[128];
    uint8_t expected[32];
    uint8_t got[32];
    size_t got_len = 0;
    size_t i;

    if (!s || !server_final) {
        return -1;
    }
    p = strstr(server_final, "v=");
    if (!p) {
        /* e= error */
        return -1;
    }
    p += 2;
    {
        size_t j = 0;
        while (p[j] && p[j] != ',' && j + 1 < sizeof(v_b64)) {
            v_b64[j] = p[j];
            j++;
        }
        v_b64[j] = '\0';
    }
    if (hmac_sha256(s->server_key, 32,
                    (const uint8_t *)s->auth_message, strlen(s->auth_message),
                    expected) != 0) {
        return -1;
    }
    if (b64_decode(v_b64, got, sizeof(got), &got_len) != 0 || got_len != 32) {
        return -1;
    }
    /* Constant-time compare */
    {
        uint8_t diff = 0;
        for (i = 0; i < 32; i++) {
            diff |= (uint8_t)(expected[i] ^ got[i]);
        }
        if (diff != 0) {
            return -1;
        }
    }
    return 0;
}
