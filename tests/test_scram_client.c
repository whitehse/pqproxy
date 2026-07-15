/**
 * SCRAM-SHA-256 self-test: client first → mock server-first → final → verify.
 * Uses a fixed password/salt/nonce path with OpenSSL PBKDF2.
 */

#include "scram_client.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

static int b64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap)
{
    int n = EVP_EncodeBlock((unsigned char *)out, in, (int)in_len);
    if (n < 0 || (size_t)n >= out_cap) {
        return -1;
    }
    out[n] = '\0';
    return 0;
}

int main(void)
{
    pq_scram_t c;
    char gs2[320], bare[288], final_msg[512];
    char server_first[256];
    char server_final[128];
    uint8_t salt[16];
    char salt_b64[64];
    const char *password = "secret";
    int i;

    /* Fixed salt for reproducibility */
    for (i = 0; i < 16; i++) {
        salt[i] = (uint8_t)(i + 1);
    }
    assert(b64_encode(salt, 16, salt_b64, sizeof(salt_b64)) == 0);

    assert(pq_scram_init(&c, "alice") == 0);
    assert(pq_scram_client_first(&c, gs2, sizeof(gs2), bare, sizeof(bare)) == 0);
    assert(strstr(gs2, "n,,n=alice,r=") == gs2);
    assert(strncmp(bare, "n=alice,r=", 10) == 0);

    /* Server extends client nonce */
    snprintf(server_first, sizeof(server_first),
             "r=%sserverext,s=%s,i=4096", c.client_nonce, salt_b64);

    assert(pq_scram_handle_server_first(&c, server_first, password) == 0);
    assert(pq_scram_client_final(&c, final_msg, sizeof(final_msg)) == 0);
    assert(strstr(final_msg, "c=biws,r=") != NULL);
    assert(strstr(final_msg, ",p=") != NULL);

    /* Compute expected server signature the same way verify does */
    {
        uint8_t server_sig[32];
        char v_b64[64];
        unsigned int len = 32;
        assert(HMAC(EVP_sha256(), c.server_key, 32,
                    (const unsigned char *)c.auth_message, strlen(c.auth_message),
                    server_sig, &len) != NULL);
        assert(b64_encode(server_sig, 32, v_b64, sizeof(v_b64)) == 0);
        snprintf(server_final, sizeof(server_final), "v=%s", v_b64);
        assert(pq_scram_verify_server_final(&c, server_final) == 0);
    }

    /* Tampered final must fail */
    assert(pq_scram_verify_server_final(&c, "v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") != 0);

    printf("scram client test PASSED\n");
    return 0;
}
