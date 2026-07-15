#ifndef PQPROXY_METRICS_INTERNAL_H
#define PQPROXY_METRICS_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

void pqproxy_metrics_inc_accepts(void);
void pqproxy_metrics_inc_closes(void);
void pqproxy_metrics_inc_be_ok(void);
void pqproxy_metrics_inc_be_fail(void);
void pqproxy_metrics_inc_fe_q_enq(void);
void pqproxy_metrics_inc_fe_q_full(void);
void pqproxy_metrics_note_fe_q_depth(size_t depth);
void pqproxy_metrics_inc_reconnects(unsigned n);
void pqproxy_metrics_inc_maintain(unsigned rewarmed);
void pqproxy_metrics_note_backend_wait_ns(uint64_t ns);
void pqproxy_metrics_set_gauges(size_t live_be, size_t active_fe);

#endif
