/**
 * Live SCRAM integration: connect pool to real Postgres (SCRAM-SHA-256).
 * Environment (set by scripts/run_live_scram_test.sh):
 *   PQPROXY_TEST_PG_HOST, PORT, USER, PASSWORD, DB
 * Or skip if PQPROXY_SKIP_LIVE_PG=1 / host unset.
 */

#include "backend_pool.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    const char *host = getenv("PQPROXY_TEST_PG_HOST");
    const char *port_s = getenv("PQPROXY_TEST_PG_PORT");
    const char *user = getenv("PQPROXY_TEST_PG_USER");
    const char *pass = getenv("PQPROXY_TEST_PG_PASSWORD");
    const char *db = getenv("PQPROXY_TEST_PG_DB");
    const char *skip = getenv("PQPROXY_SKIP_LIVE_PG");
    pqproxy_backend_config_t cfg;
    pqproxy_backend_pool_t *pool;
    pqproxy_backend_conn_t *be;
    pqwire_ctx_t *wire;
    uint8_t buf[4096];
    size_t n;

    if (skip && skip[0] == '1') {
        printf("SKIP live SCRAM (PQPROXY_SKIP_LIVE_PG=1)\n");
        return 0;
    }
    if (!host || !host[0] || !user || !pass) {
        printf("SKIP live SCRAM (set PQPROXY_TEST_PG_* or use run_live_scram_test.sh)\n");
        return 0;
    }

    pqproxy_backend_config_defaults(&cfg);
    cfg.host = host;
    cfg.port = port_s ? (uint16_t)atoi(port_s) : 5432;
    cfg.user = user;
    cfg.password = pass;
    cfg.database = db && db[0] ? db : "postgres";
    cfg.pool_size = 1;
    cfg.quiet = 1;
    cfg.connect_timeout_ms = 5000;
    cfg.io_timeout_ms = 5000;

    pool = pqproxy_backend_pool_create(&cfg);
    if (!pool) {
        fprintf(stderr, "FAIL: pool create / SCRAM warm-up failed\n");
        return 1;
    }
    if (!pqproxy_backend_pool_alive(pool)) {
        fprintf(stderr, "FAIL: pool not alive\n");
        pqproxy_backend_pool_destroy(pool);
        return 1;
    }

    be = pqproxy_backend_checkout(pool, NULL);
    if (!be) {
        fprintf(stderr, "FAIL: checkout\n");
        pqproxy_backend_pool_destroy(pool);
        return 1;
    }
    wire = pqproxy_backend_wire(be);
    if (!wire) {
        fprintf(stderr, "FAIL: no wire\n");
        pqproxy_backend_checkin(pool, be);
        pqproxy_backend_pool_destroy(pool);
        return 1;
    }

    /* Simple Query path via raw wire helper */
    if (pqwire_send_query(wire, "SELECT 1") != 0) {
        fprintf(stderr, "FAIL: send_query\n");
        pqproxy_backend_checkin(pool, be);
        pqproxy_backend_pool_destroy(pool);
        return 1;
    }
    n = 0;
    if (pqproxy_backend_flush_pipeline(be, buf, sizeof(buf), &n, 0) != 0) {
        fprintf(stderr, "FAIL: flush after SELECT 1\n");
        pqproxy_backend_checkin(pool, be);
        pqproxy_backend_pool_destroy(pool);
        return 1;
    }
    if (n == 0) {
        fprintf(stderr, "FAIL: empty response\n");
        pqproxy_backend_checkin(pool, be);
        pqproxy_backend_pool_destroy(pool);
        return 1;
    }
    /* Expect ReadyForQuery somewhere */
    {
        size_t i;
        int saw_z = 0;
        for (i = 0; i + 5 <= n; ) {
            uint32_t mlen = ((uint32_t)buf[i + 1] << 24) | ((uint32_t)buf[i + 2] << 16) |
                            ((uint32_t)buf[i + 3] << 8) | (uint32_t)buf[i + 4];
            if (buf[i] == 'Z') {
                saw_z = 1;
            }
            i += 1u + mlen;
        }
        if (!saw_z) {
            fprintf(stderr, "FAIL: no ReadyForQuery in response (%zu bytes)\n", n);
            pqproxy_backend_checkin(pool, be);
            pqproxy_backend_pool_destroy(pool);
            return 1;
        }
    }

    pqproxy_backend_checkin(pool, be);
    pqproxy_backend_pool_destroy(pool);
    printf("live SCRAM pool test PASSED (host=%s port=%u user=%s)\n",
           host, (unsigned)cfg.port, user);
    return 0;
}
