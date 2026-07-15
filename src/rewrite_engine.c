#include "pqproxy.h"

#include <stdlib.h>
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

static int is_ident_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '"';
}

static int name_eq_ci(const char *a, size_t alen, const char *b)
{
    size_t i, blen;
    if (!a || !b) {
        return 0;
    }
    blen = strlen(b);
    if (alen != blen) {
        return 0;
    }
    for (i = 0; i < alen; i++) {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca - 'A' + 'a');
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb - 'A' + 'a');
        }
        if (ca != cb) {
            return 0;
        }
    }
    return 1;
}

int16_t pqproxy_resolve_identity_slot(const char *query, const char *param_name,
                                      int16_t fallback)
{
    const char *p, *cols, *end, *q;
    int idx;
    char namebuf[64];
    size_t nlen;

    if (!param_name || !param_name[0]) {
        return fallback;
    }

    /* Numeric or $N */
    if (param_name[0] == '$') {
        return (int16_t)atoi(param_name + 1) - 1; /* $1 → 0 */
    }
    {
        int all_digit = 1;
        const char *s;
        for (s = param_name; *s; s++) {
            if (*s < '0' || *s > '9') {
                all_digit = 0;
                break;
            }
        }
        if (all_digit) {
            return (int16_t)atoi(param_name);
        }
    }

    if (!query || !query[0]) {
        return fallback;
    }

    /* Find first '(' after INSERT or after table name for column list before VALUES */
    p = query;
    cols = NULL;
    while (*p) {
        /* case-insensitive "values" stops search for column list start */
        if ((p[0] == 'v' || p[0] == 'V') &&
            (p[1] == 'a' || p[1] == 'A') &&
            (p[2] == 'l' || p[2] == 'L') &&
            (p[3] == 'u' || p[3] == 'U') &&
            (p[4] == 'e' || p[4] == 'E') &&
            (p[5] == 's' || p[5] == 'S') &&
            !is_ident_char(p[6])) {
            break;
        }
        if (*p == '(') {
            cols = p + 1;
            /* keep scanning — last '(' before VALUES is the column list */
        }
        p++;
    }
    if (!cols) {
        return fallback;
    }
    end = p; /* at VALUES or EOS */
    idx = 0;
    q = cols;
    while (q < end) {
        /* skip space */
        while (q < end && (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r')) {
            q++;
        }
        if (q >= end || *q == ')') {
            break;
        }
        nlen = 0;
        if (*q == '"') {
            q++;
            while (q < end && *q != '"' && nlen + 1 < sizeof(namebuf)) {
                namebuf[nlen++] = *q++;
            }
            if (q < end && *q == '"') {
                q++;
            }
        } else {
            while (q < end && is_ident_char(*q) && *q != '"' &&
                   nlen + 1 < sizeof(namebuf)) {
                namebuf[nlen++] = *q++;
            }
        }
        namebuf[nlen] = '\0';
        if (nlen > 0 && name_eq_ci(namebuf, nlen, param_name)) {
            return (int16_t)idx;
        }
        /* skip to next comma or end */
        while (q < end && *q != ',' && *q != ')') {
            q++;
        }
        if (q < end && *q == ',') {
            q++;
            idx++;
        } else {
            break;
        }
    }
    return fallback;
}

int pqproxy_on_parse_ex(pqwire_ctx_t *frontend, pqproxy_stmt_cache_t *cache,
                        const pq_parse_t *parse, int16_t identity_slot,
                        const char *param_name)
{
    int16_t slot = identity_slot;
    if (!frontend || !cache || !parse) {
        return -1;
    }
    if (param_name && param_name[0]) {
        int16_t resolved = pqproxy_resolve_identity_slot(parse->query, param_name,
                                                         identity_slot);
        if (resolved >= 0) {
            slot = resolved;
        }
    }
    if (pqproxy_stmt_cache_put(cache, parse, slot) != 0) {
        return -1;
    }
    return pqwire_send_parse_complete(frontend);
}

int pqproxy_on_parse(pqwire_ctx_t *frontend, pqproxy_stmt_cache_t *cache,
                     const pq_parse_t *parse, int16_t identity_slot)
{
    return pqproxy_on_parse_ex(frontend, cache, parse, identity_slot, NULL);
}

int pqproxy_on_bind(pqwire_ctx_t *backend, const pqproxy_stmt_cache_t *cache,
                    const pq_bind_t *bind, const pqproxy_identity_t *id)
{
    const pqwire_prepared_stmt_t *prep;
    int16_t slot;

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

    if (pqwire_send_parse(backend, "", prep->query,
                          prep->param_type_oids, prep->n_param_types) != 0) {
        return -1;
    }
    /* Prefer slice-based rewrite (no malloc of other params). */
    if (pqwire_send_bind_rewrite_identity(backend, bind, "", "",
                                          (uint16_t)slot, id->router_id, 0) != 0) {
        /* Fallback: owned-param inject path */
        pqwire_param_t params[PQWIRE_MAX_BIND_PARAMS];
        int16_t formats[PQWIRE_MAX_BIND_PARAMS];
        int32_t lengths[PQWIRE_MAX_BIND_PARAMS];
        const uint8_t *values[PQWIRE_MAX_BIND_PARAMS];
        uint16_t i;
        int rc = -1;

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
        rc = pqwire_send_bind(backend, "", "",
                              formats, bind->n_params,
                              lengths, values, bind->n_params,
                              bind->result_formats, bind->n_result_formats);
        for (i = 0; i < bind->n_params; i++) {
            pqwire_param_clear(&params[i]);
        }
        if (rc != 0) {
            return -1;
        }
    }
    if (pqwire_send_execute(backend, "", 0) != 0) {
        return -1;
    }
    return pqwire_send_sync(backend);
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
