#include "pqproxy.h"
#include "metrics_internal.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    pqproxy_metrics_t m;
    char line[512];

    pqproxy_metrics_inc_accepts();
    pqproxy_metrics_inc_accepts();
    pqproxy_metrics_inc_be_ok();
    pqproxy_metrics_note_backend_wait_ns(2000000ull); /* 2ms */
    pqproxy_metrics_note_fe_q_depth(3);
    pqproxy_metrics_note_fe_q_depth(1);
    pqproxy_metrics_inc_fe_q_enq();
    pqproxy_metrics_set_gauges(2, 4);

    pqproxy_metrics_get(&m);
    assert(m.accepts == 2);
    assert(m.backend_pipelines_ok == 1);
    assert(m.fe_queue_high_water == 3);
    assert(m.live_backends == 2);
    assert(m.active_frontends == 4);
    assert(m.backend_wait_samples == 1);

    pqproxy_metrics_format(&m, line, sizeof(line));
    assert(strstr(line, "accepts=2") != NULL);
    assert(strstr(line, "be_ok=1") != NULL);

    pqproxy_metrics_format_json(&m, line, sizeof(line));
    assert(strstr(line, "\"event\":\"metrics\"") != NULL);
    assert(strstr(line, "\"accepts\":2") != NULL);
    assert(strstr(line, "\"be_ok\":1") != NULL);

    {
        pqproxy_config_t cfg;
        pqproxy_config_defaults(&cfg);
        cfg.log_json = 1;
        pqproxy_log(&cfg, "test", "hello");
    }

    printf("metrics test PASSED\n%s\n", line);
    return 0;
}
