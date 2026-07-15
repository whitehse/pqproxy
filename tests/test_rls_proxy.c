/**
 * Integration: identity inject + RLS-friendly insert against live Postgres.
 *
 * Uses pool SCRAM login as group role, injects verified router_id, verifies
 * row content (forged client value must not win).
 *
 * Env: PQPROXY_TEST_PG_HOST/PORT/USER/PASSWORD/DB (from run_rls_integration.sh)
 */

#include "backend_pool.h"
#include "pqproxy.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int find_ready(const uint8_t *buf, size_t n)
{
    size_t i = 0;
    while (i + 5 <= n) {
        uint32_t mlen = ((uint32_t)buf[i + 1] << 24) | ((uint32_t)buf[i + 2] << 16) |
                        ((uint32_t)buf[i + 3] << 8) | (uint32_t)buf[i + 4];
        if (buf[i] == 'Z') {
            return 1;
        }
        if (buf[i] == 'E') {
            return -1;
        }
        i += 1u + mlen;
    }
    return 0;
}

int main(void)
{
    const char *host = getenv("PQPROXY_TEST_PG_HOST");
    const char *port_s = getenv("PQPROXY_TEST_PG_PORT");
    const char *user = getenv("PQPROXY_TEST_PG_USER");
    const char *pass = getenv("PQPROXY_TEST_PG_PASSWORD");
    const char *db = getenv("PQPROXY_TEST_PG_DB");
    pqproxy_backend_config_t cfg;
    pqproxy_backend_pool_t *pool;
    pqproxy_stmt_cache_t cache;
    pqproxy_identity_t id;
    pq_parse_t parse;
    pq_bind_t bind;
    uint8_t out[8192];
    size_t olen = 0;
    const char *sql =
        "INSERT INTO events(router_id, payload) VALUES ($1, $2)";
    const char *forged = "forged-evil-id";
    const char *payload = "hello-rls";
    int32_t lengths[2];
    const uint8_t *values[2];

    if (getenv("PQPROXY_SKIP_LIVE_PG") && getenv("PQPROXY_SKIP_LIVE_PG")[0] == '1') {
        printf("SKIP RLS (PQPROXY_SKIP_LIVE_PG=1)\n");
        return 0;
    }
    if (!host || !user || !pass) {
        printf("SKIP RLS (set PQPROXY_TEST_PG_* or use run_rls_integration.sh)\n");
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

    pool = pqproxy_backend_pool_create(&cfg);
    if (!pool) {
        fprintf(stderr, "FAIL: pool create\n");
        return 1;
    }

    assert(pqproxy_identity_from_cert_subject("router-verified:region_east", &id) == 0);
    /* Login user is region_east; inject router_id for WITH CHECK setting-style use */
    id.identity_slot = 0;

    pqproxy_stmt_cache_init(&cache);
    memset(&parse, 0, sizeof(parse));
    strcpy(parse.statement, "ins");
    strncpy(parse.query, sql, sizeof(parse.query) - 1);
    assert(pqproxy_stmt_cache_put(&cache, &parse, 0) == 0);

    /* SET app.router_id for RLS WITH CHECK */
    {
        pqproxy_backend_conn_t *be = pqproxy_backend_checkout(pool, NULL);
        uint8_t rbuf[4096];
        size_t rn = 0;
        char setcmd[256];
        assert(be);
        snprintf(setcmd, sizeof(setcmd), "SELECT set_config('app.router_id', '%s', false)",
                 id.router_id);
        assert(pqwire_send_query(pqproxy_backend_wire(be), setcmd) == 0);
        assert(pqproxy_backend_flush_pipeline(be, rbuf, sizeof(rbuf), &rn, 0) == 0);
        assert(find_ready(rbuf, rn) == 1);
        pqproxy_backend_checkin(pool, be);
    }

    memset(&bind, 0, sizeof(bind));
    strcpy(bind.statement, "ins");
    bind.n_params = 2;
    lengths[0] = (int32_t)strlen(forged);
    values[0] = (const uint8_t *)forged;
    lengths[1] = (int32_t)strlen(payload);
    values[1] = (const uint8_t *)payload;
    bind.params[0].length = lengths[0];
    bind.params[0].data = values[0];
    bind.params[0].format = 0;
    bind.params[1].length = lengths[1];
    bind.params[1].data = values[1];
    bind.params[1].format = 0;
    bind.n_formats = 0;

    if (pqproxy_backend_exec_bind(pool, &cache, &bind, &id, out, sizeof(out), &olen) != 0) {
        fprintf(stderr, "FAIL: exec_bind inject insert\n");
        pqproxy_backend_pool_destroy(pool);
        return 1;
    }
    if (find_ready(out, olen) != 1) {
        fprintf(stderr, "FAIL: insert did not complete cleanly (olen=%zu)\n", olen);
        pqproxy_backend_pool_destroy(pool);
        return 1;
    }

    /* Verify forged id is not stored */
    {
        pqproxy_backend_conn_t *be = pqproxy_backend_checkout(pool, NULL);
        uint8_t rbuf[8192];
        size_t rn = 0;
        int saw_verified = 0, saw_forged = 0;
        assert(be);
        assert(pqwire_send_query(pqproxy_backend_wire(be),
                                 "SELECT router_id, payload FROM events") == 0);
        assert(pqproxy_backend_flush_pipeline(be, rbuf, sizeof(rbuf), &rn, 0) == 0);
        /* Search raw text for values (DataRow text format) */
        if (memmem(rbuf, rn, id.router_id, strlen(id.router_id))) {
            saw_verified = 1;
        }
        if (memmem(rbuf, rn, forged, strlen(forged))) {
            saw_forged = 1;
        }
        pqproxy_backend_checkin(pool, be);
        if (!saw_verified) {
            fprintf(stderr, "FAIL: verified router_id not in result\n");
            pqproxy_backend_pool_destroy(pool);
            return 1;
        }
        if (saw_forged) {
            fprintf(stderr, "FAIL: forged router_id appeared in DB\n");
            pqproxy_backend_pool_destroy(pool);
            return 1;
        }
    }

    pqproxy_backend_pool_destroy(pool);
    printf("RLS inject integration PASSED (user=%s router_id=%s)\n",
           user, id.router_id);
    return 0;
}
