#include "pqproxy.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

static size_t write_startup(uint8_t *buf, size_t cap)
{
    size_t p = 4;
    if (cap < 64) {
        return 0;
    }
    buf[p++] = 0;
    buf[p++] = 3;
    buf[p++] = 0;
    buf[p++] = 0;
    memcpy(buf + p, "user", 5);
    p += 5;
    memcpy(buf + p, "u", 2);
    p += 2;
    memcpy(buf + p, "database", 9);
    p += 9;
    memcpy(buf + p, "d", 2);
    p += 2;
    buf[p++] = 0;
    buf[0] = (uint8_t)((p >> 24) & 0xFF);
    buf[1] = (uint8_t)((p >> 16) & 0xFF);
    buf[2] = (uint8_t)((p >> 8) & 0xFF);
    buf[3] = (uint8_t)(p & 0xFF);
    return p;
}

static void test_identity_inject(void)
{
    pqwire_ctx_t *frontend = pqwire_create(PQWIRE_ROLE_SERVER);
    pqwire_ctx_t *backend = pqwire_create(PQWIRE_ROLE_CLIENT);
    pqwire_ctx_t *client = pqwire_create(PQWIRE_ROLE_CLIENT);
    pqproxy_stmt_cache_t cache;
    pqproxy_identity_t id;
    protocol_event_t ev;
    uint8_t buf[8192];
    size_t n;
    int got_parse = 0, got_bind = 0;
    const char *sql = "INSERT INTO events(router_id, payload) VALUES ($1, $2)";
    const char *payload = "hello";
    int32_t lengths[2];
    const uint8_t *values[2];
    int16_t formats[2] = {0, 0};

    assert(frontend && backend && client);
    pqproxy_stmt_cache_init(&cache);
    assert(pqproxy_identity_from_cert_subject("router-9:region_east", &id) == 0);
    assert(strcmp(id.router_id, "router-9") == 0);

    n = write_startup(buf, sizeof(buf));
    assert(n > 0);
    pqwire_feed_input(frontend, buf, n);
    while (pqwire_next_event(frontend, &ev)) {
        assert(ev.type == PQ_EVENT_STARTUP);
    }

    assert(pqwire_send_parse(client, "st1", sql, NULL, 0) == 0);
    lengths[0] = (int32_t)strlen("forged-id");
    values[0] = (const uint8_t *)"forged-id";
    lengths[1] = (int32_t)strlen(payload);
    values[1] = (const uint8_t *)payload;
    assert(pqwire_send_bind(client, "", "st1", formats, 2,
                            lengths, values, 2, NULL, 0) == 0);

    n = pqwire_get_output(client, buf, sizeof(buf));
    assert(n > 0);
    pqwire_feed_input(frontend, buf, n);

    while (pqwire_next_event(frontend, &ev)) {
        if (ev.type == PQ_EVENT_PARSE) {
            got_parse = 1;
            assert(pqproxy_on_parse(frontend, &cache, &ev.payload.parse,
                                    id.identity_slot) == 0);
        } else if (ev.type == PQ_EVENT_BIND) {
            got_bind = 1;
            assert(pqproxy_on_bind(backend, &cache, &ev.payload.bind, &id) == 0);
        }
    }
    assert(got_parse && got_bind);
    assert(pqproxy_stmt_cache_get(&cache, "st1") != NULL);

    n = pqwire_get_output(frontend, buf, sizeof(buf));
    assert(n >= 5 && buf[0] == '1');

    n = pqwire_get_output(backend, buf, sizeof(buf));
    assert(n > 0);
    assert(buf[0] == 'P');

    {
        pqwire_ctx_t *be_srv = pqwire_create(PQWIRE_ROLE_SERVER);
        int saw_bind = 0;
        uint8_t startup[64];
        size_t sp = write_startup(startup, sizeof(startup));
        assert(be_srv);
        pqwire_feed_input(be_srv, startup, sp);
        while (pqwire_next_event(be_srv, &ev)) {
        }

        pqwire_feed_input(be_srv, buf, n);
        while (pqwire_next_event(be_srv, &ev)) {
            if (ev.type == PQ_EVENT_BIND) {
                saw_bind = 1;
                assert(ev.payload.bind.n_params >= 1);
                assert(ev.payload.bind.params[0].length == (int32_t)strlen("router-9"));
                assert(memcmp(ev.payload.bind.params[0].data, "router-9",
                              (size_t)ev.payload.bind.params[0].length) == 0);
            }
        }
        assert(saw_bind);
        pqwire_destroy(be_srv);
    }

    pqwire_destroy(frontend);
    pqwire_destroy(backend);
    pqwire_destroy(client);
    printf("  PASS: identity injection\n");
}

static void test_stmt_hash_cache(void)
{
    pqproxy_stmt_cache_t cache;
    pq_parse_t p;
    char name[32];
    int i;
    const pqwire_prepared_stmt_t *got;

    pqproxy_stmt_cache_init(&cache);
    for (i = 0; i < 48; i++) {
        memset(&p, 0, sizeof(p));
        snprintf(name, sizeof(name), "stmt_%d", i);
        strncpy(p.statement, name, sizeof(p.statement) - 1);
        snprintf(p.query, sizeof(p.query), "SELECT %d", i);
        assert(pqproxy_stmt_cache_put(&cache, &p, 0) == 0);
    }
    assert(cache.count == 48);
    for (i = 0; i < 48; i++) {
        snprintf(name, sizeof(name), "stmt_%d", i);
        got = pqproxy_stmt_cache_get(&cache, name);
        assert(got != NULL);
        assert(strstr(got->query, name + 5) != NULL || got->query[0] == 'S');
    }
    /* update existing */
    memset(&p, 0, sizeof(p));
    strncpy(p.statement, "stmt_7", sizeof(p.statement) - 1);
    strncpy(p.query, "SELECT 777", sizeof(p.query) - 1);
    assert(pqproxy_stmt_cache_put(&cache, &p, 1) == 0);
    assert(cache.count == 48);
    got = pqproxy_stmt_cache_get(&cache, "stmt_7");
    assert(got && strcmp(got->query, "SELECT 777") == 0);
    assert(got->identity_param_slot == 1);

    assert(pqproxy_stmt_cache_remove(&cache, "stmt_7") == 0);
    assert(pqproxy_stmt_cache_get(&cache, "stmt_7") == NULL);
    assert(cache.count == 47);
    /* neighbors still findable after rehash */
    assert(pqproxy_stmt_cache_get(&cache, "stmt_0") != NULL);
    assert(pqproxy_stmt_cache_get(&cache, "stmt_47") != NULL);

    printf("  PASS: stmt hash cache\n");
}

static void test_simple_query_policy(void)
{
    pqwire_ctx_t *fe = pqwire_create(PQWIRE_ROLE_SERVER);
    uint8_t buf[512];
    size_t n;
    uint8_t startup[64];
    size_t sp;
    protocol_event_t ev;

    assert(fe);
    sp = write_startup(startup, sizeof(startup));
    pqwire_feed_input(fe, startup, sp);
    while (pqwire_next_event(fe, &ev)) {
    }

    assert(pqproxy_on_simple_query(fe, 1, "SELECT 1") == 0);
    n = pqwire_get_output(fe, buf, sizeof(buf));
    assert(n >= 5);
    assert(buf[0] == 'E'); /* ErrorResponse */
    /* should also include RFQ */
    {
        size_t off = 0;
        int saw_e = 0, saw_z = 0;
        while (off + 5 <= n) {
            char type;
            size_t total;
            assert(pqwire_msg_peek(buf + off, n - off, &type, &total) == 0);
            if (type == 'E') {
                saw_e = 1;
            }
            if (type == 'Z') {
                saw_z = 1;
            }
            off += total;
        }
        assert(saw_e && saw_z);
    }
    printf("  PASS: simple Query reject policy\n");
    pqwire_destroy(fe);
}

static void test_identity_slot_by_name(void)
{
    const char *sql =
        "INSERT INTO events(router_id, payload, ts) VALUES ($1, $2, $3)";
    assert(pqproxy_resolve_identity_slot(sql, "router_id", -1) == 0);
    assert(pqproxy_resolve_identity_slot(sql, "payload", -1) == 1);
    assert(pqproxy_resolve_identity_slot(sql, "ts", -1) == 2);
    assert(pqproxy_resolve_identity_slot(sql, "$2", -1) == 1);
    assert(pqproxy_resolve_identity_slot(sql, "1", -1) == 1);
    assert(pqproxy_resolve_identity_slot(sql, "missing", 7) == 7);
    assert(pqproxy_resolve_identity_slot(sql, NULL, 3) == 3);
    printf("  PASS: identity slot by name\n");
}

static void test_zerocopy_bind_rewrite(void)
{
    pqwire_ctx_t *client = pqwire_create(PQWIRE_ROLE_CLIENT);
    pqwire_ctx_t *server = pqwire_create(PQWIRE_ROLE_SERVER);
    uint8_t startup[64], wire[2048], out[2048];
    size_t n, sp, out_len = 0;
    int32_t lengths[2];
    const uint8_t *values[2];
    int16_t formats[2] = {0, 0};
    protocol_event_t ev;
    int saw = 0;

    assert(client && server);
    sp = write_startup(startup, sizeof(startup));
    pqwire_feed_input(server, startup, sp);
    while (pqwire_next_event(server, &ev)) {
    }

    lengths[0] = (int32_t)strlen("forged");
    values[0] = (const uint8_t *)"forged";
    lengths[1] = (int32_t)strlen("body");
    values[1] = (const uint8_t *)"body";
    assert(pqwire_send_bind(client, "p", "st", formats, 2,
                            lengths, values, 2, NULL, 0) == 0);
    n = pqwire_get_output(client, wire, sizeof(wire));
    assert(n > 0);
    pqwire_feed_input(server, wire, n);
    while (pqwire_next_event(server, &ev) == 1) {
        if (ev.type == PQ_EVENT_BIND) {
            assert(pqwire_bind_rewrite_identity_zerocopy(
                       &ev.payload.bind, "", "", 0, "router-Z", 0,
                       out, sizeof(out), &out_len) == 0);
            assert(out_len >= 5 && out[0] == 'B');
            /* re-parse rewritten bind */
            {
                pqwire_ctx_t *srv2 = pqwire_create(PQWIRE_ROLE_SERVER);
                uint8_t st2[64];
                size_t s2 = write_startup(st2, sizeof(st2));
                protocol_event_t ev2;
                pqwire_feed_input(srv2, st2, s2);
                while (pqwire_next_event(srv2, &ev2)) {
                }
                pqwire_feed_input(srv2, out, out_len);
                while (pqwire_next_event(srv2, &ev2) == 1) {
                    if (ev2.type == PQ_EVENT_BIND) {
                        saw = 1;
                        assert(ev2.payload.bind.n_params >= 1);
                        assert(ev2.payload.bind.params[0].length ==
                               (int32_t)strlen("router-Z"));
                        assert(memcmp(ev2.payload.bind.params[0].data, "router-Z",
                                      8) == 0);
                    }
                }
                pqwire_destroy(srv2);
            }
        }
    }
    assert(saw);
    pqwire_destroy(client);
    pqwire_destroy(server);
    printf("  PASS: zerocopy bind rewrite\n");
}

static void test_pipeline_error_observe(void)
{
    /* Dialectic without live PG: Error then RFQ status */
    pqwire_ctx_t *srv = pqwire_create(PQWIRE_ROLE_SERVER);
    pqwire_ctx_t *cli = pqwire_create(PQWIRE_ROLE_CLIENT);
    pqwire_pipeline_status_t st;
    uint8_t buf[1024];
    size_t n, off;
    char type;
    size_t total;

    assert(srv && cli);
    pqwire_pipeline_status_init(&st);
    assert(pqwire_send_error_response(srv, "ERROR", "23505", "duplicate") == 0);
    assert(pqwire_send_ready_for_query(srv) == 0);
    n = pqwire_get_output(srv, buf, sizeof(buf));
    off = 0;
    while (off < n) {
        assert(pqwire_msg_peek(buf + off, n - off, &type, &total) == 0);
        assert(pqwire_pipeline_feed_backend_msg(cli, &st, buf + off, total) == 0);
        off += total;
    }
    assert(st.saw_error == 1);
    assert(st.complete == 1);
    assert(strcmp(st.last_error.code, "23505") == 0);
    assert(pqwire_pipeline_filter_backend_type('1', 1) == 1);
    assert(pqwire_pipeline_filter_backend_type('E', 1) == 0);
    pqwire_destroy(srv);
    pqwire_destroy(cli);
    printf("  PASS: pipeline error observe (dialectic)\n");
}

int main(void)
{
    test_identity_inject();
    test_stmt_hash_cache();
    test_simple_query_policy();
    test_pipeline_error_observe();
    test_identity_slot_by_name();
    test_zerocopy_bind_rewrite();
    printf("rewrite engine tests PASSED\n");
    return 0;
}
