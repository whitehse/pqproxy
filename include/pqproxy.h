#ifndef PQPROXY_H
#define PQPROXY_H

#include <stddef.h>
#include <stdint.h>
#include "pqwire.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Verified client identity extracted from mTLS (never from Bind). */
typedef struct {
    char router_id[128];
    char group[64];          /* backend role / pool key, e.g. region_east */
    int16_t identity_slot;   /* Bind parameter index to overwrite; -1 unset */
} pqproxy_identity_t;

/** Per-frontend prepared statement cache entry (wraps pique shape). */
typedef struct {
    pqwire_prepared_stmt_t stmt;
    int in_use;
} pqproxy_stmt_slot_t;

#define PQPROXY_MAX_CACHED_STMTS 64

typedef struct {
    pqproxy_stmt_slot_t slots[PQPROXY_MAX_CACHED_STMTS];
    size_t count;
} pqproxy_stmt_cache_t;

void pqproxy_stmt_cache_init(pqproxy_stmt_cache_t *cache);
int pqproxy_stmt_cache_put(pqproxy_stmt_cache_t *cache, const pq_parse_t *parse,
                           int16_t identity_slot);
const pqwire_prepared_stmt_t *pqproxy_stmt_cache_get(const pqproxy_stmt_cache_t *cache,
                                                     const char *name);

/**
 * Handle a frontend Parse event: cache statement, emit local ParseComplete
 * on frontend_out (server role). Does not touch the backend.
 */
int pqproxy_on_parse(pqwire_ctx_t *frontend, pqproxy_stmt_cache_t *cache,
                     const pq_parse_t *parse, int16_t identity_slot);

/**
 * Handle a frontend Bind: inject identity into parameter slot, emit
 * unnamed Parse+Bind+Execute+Sync on backend (client role).
 * Caller still drains frontend with BindComplete after backend succeeds
 * (or immediately if pipelining policy allows).
 */
int pqproxy_on_bind(pqwire_ctx_t *backend, const pqproxy_stmt_cache_t *cache,
                    const pq_bind_t *bind, const pqproxy_identity_t *id);

/** Clear identity structure. */
void pqproxy_identity_clear(pqproxy_identity_t *id);

/**
 * Stub: map certificate subject string to identity.
 * Real implementation uses OpenSSL X509 / bonsai_pki.
 */
int pqproxy_identity_from_cert_subject(const char *subject, pqproxy_identity_t *out);

#ifdef __cplusplus
}
#endif

#endif /* PQPROXY_H */
