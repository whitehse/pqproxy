/**
 * @file metrics.c
 * @brief Process-wide pqproxy counters (no locks; single event-loop writer).
 */

#include "pqproxy.h"

#include <stdio.h>
#include <string.h>

static pqproxy_metrics_t g_metrics;

void pqproxy_metrics_get(pqproxy_metrics_t *out)
{
    if (!out) {
        return;
    }
    *out = g_metrics;
}

char *pqproxy_metrics_format(const pqproxy_metrics_t *m, char *out, size_t out_len)
{
    uint64_t avg_us = 0;
    if (!m || !out || out_len == 0) {
        return out;
    }
    if (m->backend_wait_samples > 0) {
        avg_us = (m->backend_wait_ns_total / m->backend_wait_samples) / 1000ull;
    }
    snprintf(out, out_len,
             "pqproxy_metrics accepts=%llu closes=%llu "
             "be_ok=%llu be_fail=%llu be_wait_us_avg=%llu be_wait_us_max=%llu "
             "fe_q_enq=%llu fe_q_full=%llu fe_q_hwm=%llu "
             "reconnects=%llu maintain_ticks=%llu rewarmed=%llu "
             "live_be=%zu active_fe=%zu",
             (unsigned long long)m->accepts,
             (unsigned long long)m->frontend_closes,
             (unsigned long long)m->backend_pipelines_ok,
             (unsigned long long)m->backend_pipelines_fail,
             (unsigned long long)avg_us,
             (unsigned long long)(m->backend_wait_ns_max / 1000ull),
             (unsigned long long)m->fe_queue_enqueued,
             (unsigned long long)m->fe_queue_full,
             (unsigned long long)m->fe_queue_high_water,
             (unsigned long long)m->reconnects,
             (unsigned long long)m->maintain_ticks,
             (unsigned long long)m->maintain_rewarmed,
             m->live_backends,
             m->active_frontends);
    return out;
}

/* Internal mutators used by iouring_loop / pool (declared in metrics_internal) */
void pqproxy_metrics_inc_accepts(void) { g_metrics.accepts++; }
void pqproxy_metrics_inc_closes(void) { g_metrics.frontend_closes++; }
void pqproxy_metrics_inc_be_ok(void) { g_metrics.backend_pipelines_ok++; }
void pqproxy_metrics_inc_be_fail(void) { g_metrics.backend_pipelines_fail++; }
void pqproxy_metrics_inc_fe_q_enq(void) { g_metrics.fe_queue_enqueued++; }
void pqproxy_metrics_inc_fe_q_full(void) { g_metrics.fe_queue_full++; }

void pqproxy_metrics_note_fe_q_depth(size_t depth)
{
    if (depth > g_metrics.fe_queue_high_water) {
        g_metrics.fe_queue_high_water = depth;
    }
}

void pqproxy_metrics_inc_reconnects(unsigned n)
{
    g_metrics.reconnects += n;
}

void pqproxy_metrics_inc_maintain(unsigned rewarmed)
{
    g_metrics.maintain_ticks++;
    g_metrics.maintain_rewarmed += rewarmed;
}

void pqproxy_metrics_note_backend_wait_ns(uint64_t ns)
{
    g_metrics.backend_wait_ns_total += ns;
    g_metrics.backend_wait_samples++;
    if (ns > g_metrics.backend_wait_ns_max) {
        g_metrics.backend_wait_ns_max = ns;
    }
}

void pqproxy_metrics_set_gauges(size_t live_be, size_t active_fe)
{
    g_metrics.live_backends = live_be;
    g_metrics.active_frontends = active_fe;
}
