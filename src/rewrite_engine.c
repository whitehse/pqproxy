#include "pqproxy.h"

#include <string.h>
#include <stdio.h>

/* FNV-1a 32-bit */
static uint32_t stmt_name_hash(const char *name)
{
    uint32_t h = 2166136261u;
    const unsigned char *p;
    if (!name) {
        name = "";
    }
    for (p = (const unsigned char *)name; *p; p++) {
        h ^= *p;
        h *= 16777619u;
    }
    return h;
}

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
    uint32_t h;
    size_t i, probes;
    size_t free_slot = (size_t)-1;

    if (!cache || !parse) {
        return -1;
    }

    if (cache->count >= PQPROXY_MAX_CACHED_STMTS) {
        /* May still update an existing name below */
    }

    h = stmt_name_hash(parse->statement);
    for (probes = 0; probes < PQPROXY_MAX_CACHED_STMTS; probes++) {
        i = (h + probes) % PQPROXY_MAX_CACHED_STMTS;
        if (!cache->slots[i].in_use) {
            if (free_slot == (size_t)-1) {
                free_slot = i;
            }
            /* No tombstones: first empty ends search (key not present). */
            break;
        }
        if (strcmp(cache->slots[i].stmt.name, parse->statement) == 0) {
            if (pqwire_prepared_from_parse(parse, &cache->slots[i].stmt) != 0) {
                return -1;
            }
            cache->slots[i].stmt.identity_param_slot = identity_slot;
            return 0;
        }
    }

    if (free_slot == (size_t)-1 || cache->count >= PQPROXY_MAX_CACHED_STMTS) {
        return -1;
    }

    i = free_slot;
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
    uint32_t h;
    size_t i, probes;

    if (!cache || !name) {
        return NULL;
    }

    h = stmt_name_hash(name);
    for (probes = 0; probes < PQPROXY_MAX_CACHED_STMTS; probes++) {
        i = (h + probes) % PQPROXY_MAX_CACHED_STMTS;
        if (!cache->slots[i].in_use) {
            return NULL;
        }
        if (strcmp(cache->slots[i].stmt.name, name) == 0) {
            return &cache->slots[i].stmt;
        }
    }
    return NULL;
}

int pqproxy_stmt_cache_remove(pqproxy_stmt_cache_t *cache, const char *name)
{
    uint32_t h;
    size_t i, probes;

    if (!cache || !name) {
        return -1;
    }

    h = stmt_name_hash(name);
    for (probes = 0; probes < PQPROXY_MAX_CACHED_STMTS; probes++) {
        i = (h + probes) % PQPROXY_MAX_CACHED_STMTS;
        if (!cache->slots[i].in_use) {
            return -1;
        }
        if (strcmp(cache->slots[i].stmt.name, name) == 0) {
            memset(&cache->slots[i], 0, sizeof(cache->slots[i]));
            if (cache->count > 0) {
                cache->count--;
            }
            /*
             * Open-addressing without tombstones: rehash remaining entries so
             * probes past the hole still find their keys.
             */
            {
                pqproxy_stmt_slot_t old[PQPROXY_MAX_CACHED_STMTS];
                size_t j, n = 0;
                memcpy(old, cache->slots, sizeof(old));
                memset(cache->slots, 0, sizeof(cache->slots));
                cache->count = 0;
                for (j = 0; j < PQPROXY_MAX_CACHED_STMTS; j++) {
                    if (old[j].in_use) {
                        pq_parse_t p;
                        memset(&p, 0, sizeof(p));
                        strncpy(p.statement, old[j].stmt.name, sizeof(p.statement) - 1);
                        strncpy(p.query, old[j].stmt.query, sizeof(p.query) - 1);
                        p.n_param_types = old[j].stmt.n_param_types;
                        memcpy(p.param_type_oids, old[j].stmt.param_type_oids,
                               sizeof(p.param_type_oids));
                        if (pqproxy_stmt_cache_put(cache, &p,
                                                   old[j].stmt.identity_param_slot) != 0) {
                            return -1;
                        }
                        n++;
                    }
                }
                (void)n;
            }
            return 0;
        }
    }
    return -1;
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

int pqproxy_on_simple_query(pqwire_ctx_t *frontend, int reject_simple_query,
                            const char *sql)
{
    (void)sql;
    if (!frontend) {
        return -1;
    }
    if (reject_simple_query) {
        if (pqwire_send_error_response(
                frontend, "ERROR", "0A000",
                "simple Query disabled; use extended protocol") != 0) {
            return -1;
        }
        return pqwire_send_ready_for_query(frontend);
    }
    /* allow path without backend forward still refuses inject-less SQL */
    if (pqwire_send_error_response(
            frontend, "ERROR", "0A000",
            "simple Query allowed only with backend forward (not configured here)") != 0) {
        return -1;
    }
    return pqwire_send_ready_for_query(frontend);
}
