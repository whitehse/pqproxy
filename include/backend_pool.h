#ifndef PQPROXY_BACKEND_POOL_H
#define PQPROXY_BACKEND_POOL_H

#include "pqproxy.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pqproxy_backend_pool pqproxy_backend_pool_t;
typedef struct pqproxy_backend_conn pqproxy_backend_conn_t;

typedef struct {
    const char *host;          /* default 127.0.0.1 */
    uint16_t    port;          /* default 5432 */
    const char *user;          /* fixed user if not use_group_as_user */
    const char *password;      /* optional; empty = trust/peer; used for SCRAM */
    const char *database;      /* default postgres */
    int         use_group_as_user; /* login as identity.group (DB role) */
    const char *groups;        /* comma-separated roles to pre-warm when group login */
    int         lazy_group_connect; /* open new backend as group on demand (default 1) */
    size_t      pool_size;     /* total pre-warmed conns (default 4) */
    int         connect_timeout_ms;
    int         io_timeout_ms;
    int         quiet;
} pqproxy_backend_config_t;

void pqproxy_backend_config_defaults(pqproxy_backend_config_t *cfg);

/**
 * Create and warm pool (blocking connect + Startup + Auth).
 * Returns NULL if host unset or connect fails for all slots.
 * Partial success is ok if at least one connection is alive.
 */
pqproxy_backend_pool_t *pqproxy_backend_pool_create(const pqproxy_backend_config_t *cfg);

void pqproxy_backend_pool_destroy(pqproxy_backend_pool_t *pool);

/** Non-zero if pool has at least one live connection. */
int pqproxy_backend_pool_alive(const pqproxy_backend_pool_t *pool);

/**
 * Checkout an idle connection. If use_group_as_user, prefer a conn whose
 * login user matches group (or any idle if none matched at warm-up).
 * Returns NULL if none available.
 */
pqproxy_backend_conn_t *pqproxy_backend_checkout(pqproxy_backend_pool_t *pool,
                                                 const char *group);

void pqproxy_backend_checkin(pqproxy_backend_pool_t *pool, pqproxy_backend_conn_t *conn);

/** pqwire CLIENT context for this backend (authenticated). */
pqwire_ctx_t *pqproxy_backend_wire(pqproxy_backend_conn_t *conn);

/**
 * Write pending pqwire output to the backend socket, then read responses
 * until ReadyForQuery ('Z'). Copies filtered backend messages into out
 * (skips Authentication/ParameterStatus; optionally skips Parse/Bind complete).
 *
 * Returns 0 on success, -1 on I/O or protocol error.
 */
int pqproxy_backend_flush_pipeline(pqproxy_backend_conn_t *conn,
                                   uint8_t *out, size_t out_cap, size_t *out_len,
                                   int skip_parse_bind_complete);

/**
 * High-level: inject Bind → unnamed pipeline on a checked-out backend,
 * run flush, return filtered response bytes for the frontend.
 */
int pqproxy_backend_exec_bind(pqproxy_backend_pool_t *pool,
                              const pqproxy_stmt_cache_t *cache,
                              const pq_bind_t *bind,
                              const pqproxy_identity_t *id,
                              uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* PQPROXY_BACKEND_POOL_H */
