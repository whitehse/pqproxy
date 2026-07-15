#include "pqproxy.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

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

int main(void)
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

    /* Frontend must see Startup before typed messages (server role). */
    n = write_startup(buf, sizeof(buf));
    assert(n > 0);
    pqwire_feed_input(frontend, buf, n);
    while (pqwire_next_event(frontend, &ev)) {
        assert(ev.type == PQ_EVENT_STARTUP);
    }

    /* Client sends Parse + Bind with forged identity in $1 */
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

    /* Frontend ParseComplete */
    n = pqwire_get_output(frontend, buf, sizeof(buf));
    assert(n >= 5 && buf[0] == '1');

    /* Backend unnamed Parse + Bind with injected identity */
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

    printf("rewrite engine test PASSED (identity injection)\n");
    pqwire_destroy(frontend);
    pqwire_destroy(backend);
    pqwire_destroy(client);
    return 0;
}
