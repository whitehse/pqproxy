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
    int         maintain_interval_ms; /* pool re-warm tick; 0=off, default 5000 */
    int         metrics_log_interval_ms; /* stderr metrics; 0=off, default 30000 */
    const char *metrics_http_host;  /* default 127.0.0.1; NULL with port 0 = off */
    uint16_t    metrics_http_port;  /* 0 = disable HTTP /metrics (default 9108) */
    int         fair_schedule;      /* RR among frontends waiting on pool (default 1) */
} pqproxy_config_t;

void pqproxy_config_defaults(pqproxy_config_t *cfg);

/**
 * Runtime metrics (process-wide; updated by the server loop / pool).
 * Snapshot with pqproxy_metrics_get(); all fields are monotonic counters
 * except high-water marks and gauges.
 */
typedef struct {
    uint64_t accepts;
    uint64_t frontend_closes;
    uint64_t backend_pipelines_ok;
    uint64_t backend_pipelines_fail;
    uint64_t fe_queue_enqueued;
    uint64_t fe_queue_full;
    uint64_t fe_queue_high_water;   /* max observed queue depth */
    uint64_t reconnects;            /* successful re-warms */
    uint64_t maintain_ticks;
    uint64_t maintain_rewarmed;
    uint64_t backend_wait_ns_total; /* sum of pipeline wait times */
    uint64_t backend_wait_samples;
    uint64_t backend_wait_ns_max;
    uint64_t fair_waits;            /* frontend parked waiting for backend */
    uint64_t fair_schedules;        /* waiter granted a backend */
    size_t   live_backends;         /* gauge: filled on snapshot */
    size_t   active_frontends;      /* gauge */
    size_t   pool_waiters;          /* gauge: frontends waiting for pool */
} pqproxy_metrics_t;

void pqproxy_metrics_get(pqproxy_metrics_t *out);
/** Format one-line metrics for logs. Returns out. */
char *pqproxy_metrics_format(const pqproxy_metrics_t *m, char *out, size_t out_len);

/**
 * Run the proxy accept loop (blocks until fatal error or signal).
 * io_uring for accept/recv/send; OpenSSL mTLS when !plain.
 * Periodic pool maintain + metrics logging per config intervals.
 *
 * Returns 0 on clean shutdown, non-zero on fatal error.
 */
int pqproxy_run(const pqproxy_config_t *cfg);

#ifdef __cplusplus
}
#endif

#endif /* PQPROXY_H */
