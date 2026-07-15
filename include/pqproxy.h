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
 */
int pqproxy_on_bind(pqwire_ctx_t *backend, const pqproxy_stmt_cache_t *cache,
                    const pq_bind_t *bind, const pqproxy_identity_t *id);

void pqproxy_identity_clear(pqproxy_identity_t *id);

/**
 * Map a certificate subject / identity string to router_id + group.
 * Accepted forms:
 *   - "router_id:group"
 *   - OpenSSL oneline "/CN=router_id/OU=group/..."
 *   - bare CN as router_id with group "default"
 */
int pqproxy_identity_from_cert_subject(const char *subject, pqproxy_identity_t *out);

/**
 * Extract identity from an OpenSSL X509 peer certificate (CN + OU).
 * Returns 0 on success. Requires linking OpenSSL when used.
 */
struct x509_st;
int pqproxy_identity_from_x509(const struct x509_st *cert, pqproxy_identity_t *out);

/* ── server / I/O ────────────────────────────────────────────────────── */

#define PQPROXY_MAX_CONNS   256
#define PQPROXY_IO_BUF      16384
#define PQPROXY_URING_ENTRIES 512

typedef struct {
    const char *listen_host;   /* default "0.0.0.0" */
    uint16_t    listen_port;   /* default 6432 */
    const char *cert_file;     /* server cert PEM (required unless plain) */
    const char *key_file;      /* server key PEM */
    const char *ca_file;       /* client CA for mTLS verify */
    int         plain;         /* 1 = no TLS (dev only) */
    int         require_mtls;  /* 1 = require client cert (default when !plain) */
    int16_t     identity_slot; /* Bind param slot for router_id */
    int         quiet;         /* less stderr logging */

    /* Optional identity-grouped backend pool */
    const char *backend_host;  /* NULL = no pool (local stub only) */
    uint16_t    backend_port;  /* default 5432 */
    const char *backend_user;
    const char *backend_password;
    const char *backend_database;
    int         backend_use_group_as_user;
    const char *backend_groups;      /* comma-separated roles to pre-warm */
    int         backend_lazy_group;  /* default 1 */
    size_t      backend_pool_size;
    int         prefer_tls12_ktls;   /* prefer TLS1.2 AES-GCM for kTLS (default 1) */
} pqproxy_config_t;

void pqproxy_config_defaults(pqproxy_config_t *cfg);

/**
 * Run the proxy accept loop (blocks until fatal error or signal).
 * io_uring for accept/recv/send; OpenSSL memory-BIO mTLS when !plain.
 * Frontend pqwire SERVER role drives Parse intercept locally; backend
 * pool is not yet connected (rewrite queues for future pool).
 *
 * Returns 0 on clean shutdown, non-zero on fatal error.
 */
int pqproxy_run(const pqproxy_config_t *cfg);

#ifdef __cplusplus
}
#endif

#endif /* PQPROXY_H */
