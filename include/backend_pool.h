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
    int         auto_reconnect;      /* re-warm dead slots (default 1) */
    int         health_check_on_checkout; /* lightweight Sync probe (default 0) */
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
 * (Blocking I/O — used by tests and as fallback.)
 */
int pqproxy_backend_exec_bind(pqproxy_backend_pool_t *pool,
                              const pqproxy_stmt_cache_t *cache,
                              const pq_bind_t *bind,
                              const pqproxy_identity_t *id,
                              uint8_t *out, size_t out_cap, size_t *out_len);

/* ── Async / io_uring-friendly pipeline ──────────────────────────────── */

/**
 * Checkout backend, inject bind pipeline into wire output, fill internal
 * send buffer. Does not perform socket I/O.
 * Returns 0 and *conn_out on success.
 */
int pqproxy_backend_async_begin(pqproxy_backend_pool_t *pool,
                                const pqproxy_stmt_cache_t *cache,
                                const pq_bind_t *bind,
                                const pqproxy_identity_t *id,
                                pqproxy_backend_conn_t **conn_out);

/** Remaining bytes to send to backend socket. */
size_t pqproxy_backend_async_send_pending(const pqproxy_backend_conn_t *conn);

/** Pointer to next send chunk. */
const uint8_t *pqproxy_backend_async_send_ptr(const pqproxy_backend_conn_t *conn,
                                              size_t *len_out);

/** Advance send cursor after a successful write of n bytes. */
void pqproxy_backend_async_send_advance(pqproxy_backend_conn_t *conn, size_t n);

/**
 * Feed one recv buffer of backend data. Appends filtered messages to out
 * (caller-owned buffer). Sets *complete=1 when ReadyForQuery seen.
 * Returns 0 on success, -1 on protocol/hard error.
 */
int pqproxy_backend_async_on_recv(pqproxy_backend_conn_t *conn,
                                  const uint8_t *data, size_t len,
                                  uint8_t *out, size_t out_cap, size_t *out_len,
                                  int *complete);

/** Backend TCP fd (for io_uring registration). */
int pqproxy_backend_fd(const pqproxy_backend_conn_t *conn);

/** Slot index (stable for user_data packing). */
int pqproxy_backend_slot(const pqproxy_backend_conn_t *conn);

/** Finish async op: checkin (call after complete or error). */
void pqproxy_backend_async_finish(pqproxy_backend_pool_t *pool,
                                  pqproxy_backend_conn_t *conn,
                                  int failed);

/** Set non-blocking mode on all live backends (after warm-up). */
int pqproxy_backend_pool_set_nonblock(pqproxy_backend_pool_t *pool);

/**
 * Mark connection dead (close fd/wire) without checkin; used on I/O errors.
 * Does not free the slot — call async_finish or reconnect.
 */
void pqproxy_backend_mark_dead(pqproxy_backend_conn_t *conn);

/**
 * Re-authenticate a dead or failed slot as its previous login_user.
 * Returns 0 on success (conn alive, still busy if it was).
 */
int pqproxy_backend_reconnect(pqproxy_backend_pool_t *pool,
                              pqproxy_backend_conn_t *conn);

/**
 * Walk pool and reconnect any dead, non-busy slots (maintenance tick).
 * Returns number of successfully re-warmed connections.
 */
int pqproxy_backend_pool_maintain(pqproxy_backend_pool_t *pool);

/**
 * Optional health probe: send empty Sync (or Query SELECT 1) and wait RFQ.
 * Blocking. Returns 0 healthy, -1 dead (conn marked dead).
 */
int pqproxy_backend_health_check(pqproxy_backend_pool_t *pool,
                                 pqproxy_backend_conn_t *conn);

/** Count of live connections. */
size_t pqproxy_backend_pool_live_count(const pqproxy_backend_pool_t *pool);

#ifdef __cplusplus
}
#endif

#endif /* PQPROXY_BACKEND_POOL_H */
