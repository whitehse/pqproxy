#ifndef PQPROXY_METRICS_HTTP_H
#define PQPROXY_METRICS_HTTP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Start a background HTTP server exposing Prometheus text at GET /metrics.
 * Returns 0 on success, -1 on error. Safe to call with port 0 (no-op).
 *
 * Thread is detached; stop with pqproxy_metrics_http_stop().
 */
int pqproxy_metrics_http_start(const char *host, uint16_t port);

/** Stop the metrics HTTP server (best-effort). */
void pqproxy_metrics_http_stop(void);

/** Format Prometheus exposition text into out. Returns bytes written (excl NUL). */
int pqproxy_metrics_prometheus_format(char *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif
