#include "pqproxy.h"

#include <string.h>
#include <stdio.h>

void pqproxy_stmt_cache_init(pqproxy_stmt_cache_t *cache)
{
    if (!cache) {
        return;
    }
    memset(cache, 0, sizeof(*cache));
}

int pqproxy_stmt_cache_put(pqproxy_stmt_cache_t *cache, const pq_parse_t *parse,
                           int16_t identity_slot)
{
    size_t i;
    if (!cache || !parse) {
        return -1;
    }
    for (i = 0; i < cache->count; i++) {
        if (cache->slots[i].in_use &&
            strcmp(cache->slots[i].stmt.name, parse->statement) == 0) {
            if (pqwire_prepared_from_parse(parse, &cache->slots[i].stmt) != 0) {
                return -1;
            }
            cache->slots[i].stmt.identity_param_slot = identity_slot;
            return 0;
        }
    }
    if (cache->count >= PQPROXY_MAX_CACHED_STMTS) {
        return -1;
    }
    i = cache->count;
    if (pqwire_prepared_from_parse(parse, &cache->slots[i].stmt) != 0) {
        return -1;
    }
    cache->slots[i].stmt.identity_param_slot = identity_slot;
    cache->slots[i].in_use = 1;
    cache->count++;
    return 0;
}

const pqwire_prepared_stmt_t *pqproxy_stmt_cache_get(const pqproxy_stmt_cache_t *cache,
                                                     const char *name)
{
    size_t i;
    if (!cache || !name) {
        return NULL;
    }
    for (i = 0; i < cache->count; i++) {
        if (cache->slots[i].in_use &&
            strcmp(cache->slots[i].stmt.name, name) == 0) {
            return &cache->slots[i].stmt;
        }
    }
    return NULL;
}

int pqproxy_on_parse(pqwire_ctx_t *frontend, pqproxy_stmt_cache_t *cache,
                     const pq_parse_t *parse, int16_t identity_slot)
{
    if (!frontend || !cache || !parse) {
        return -1;
    }
    if (pqproxy_stmt_cache_put(cache, parse, identity_slot) != 0) {
        return -1;
    }
    return pqwire_send_parse_complete(frontend);
}

int pqproxy_on_bind(pqwire_ctx_t *backend, const pqproxy_stmt_cache_t *cache,
                    const pq_bind_t *bind, const pqproxy_identity_t *id)
{
    const pqwire_prepared_stmt_t *prep;
    pqwire_param_t params[PQWIRE_MAX_BIND_PARAMS];
    int16_t formats[PQWIRE_MAX_BIND_PARAMS];
    int32_t lengths[PQWIRE_MAX_BIND_PARAMS];
    const uint8_t *values[PQWIRE_MAX_BIND_PARAMS];
    int16_t slot;
    uint16_t i;
    int rc = -1;

    if (!backend || !cache || !bind || !id) {
        return -1;
    }

    prep = pqproxy_stmt_cache_get(cache, bind->statement);
    if (!prep) {
        return -1;
    }

    slot = id->identity_slot >= 0 ? id->identity_slot : prep->identity_param_slot;
    if (slot < 0) {
        slot = 0;
    }
    if (bind->n_params == 0 || (uint16_t)slot >= bind->n_params) {
        return -1;
    }

    memset(params, 0, sizeof(params));
    for (i = 0; i < PQWIRE_MAX_BIND_PARAMS; i++) {
        params[i].length = -1;
    }

    if (pqwire_bind_inject_identity(bind, params, (uint16_t)slot,
                                    id->router_id, 0) != 0) {
        return -1;
    }

    for (i = 0; i < bind->n_params; i++) {
        formats[i] = params[i].format;
        lengths[i] = params[i].length;
        values[i] = params[i].data;
    }

    if (pqwire_send_parse(backend, "", prep->query,
                          prep->param_type_oids, prep->n_param_types) != 0) {
        goto out;
    }
    if (pqwire_send_bind(backend, "", "",
                         formats, bind->n_params,
                         lengths, values, bind->n_params,
                         bind->result_formats, bind->n_result_formats) != 0) {
        goto out;
    }
    if (pqwire_send_execute(backend, "", 0) != 0) {
        goto out;
    }
    rc = pqwire_send_sync(backend);

out:
    for (i = 0; i < bind->n_params; i++) {
        pqwire_param_clear(&params[i]);
    }
    return rc;
}
