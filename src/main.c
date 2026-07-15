#include "pqproxy.h"
#include "config_yaml.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [options]\n"
            "  --config FILE        load YAML config (CLI flags override)\n"
            "  --listen HOST:PORT   default 0.0.0.0:6432\n"
            "  --cert FILE          server certificate PEM\n"
            "  --key FILE           server private key PEM\n"
            "  --ca FILE            client CA PEM (mTLS)\n"
            "  --plain              no TLS (development only)\n"
            "  --no-mtls            TLS without requiring client cert\n"
            "  --identity-slot N    Bind param index for router_id (default 0)\n"
            "  --backend HOST:PORT  PostgreSQL backend for identity pool\n"
            "  --backend-user U     backend login (default postgres)\n"
            "  --backend-password P backend password (empty = trust)\n"
            "  --backend-database D default postgres\n"
            "  --backend-pool N     warmed connections (default 4)\n"
            "  --backend-group-login  login to PG as client group (role)\n"
            "  --backend-groups LIST  comma-separated roles to pre-warm\n"
            "  --no-lazy-group      do not open backends on demand for new groups\n"
            "  --ktls-prefer        prefer TLS1.2 AES-GCM for kTLS (default)\n"
            "  --no-ktls-prefer     allow TLS1.3 (may disable kTLS offload)\n"
            "  --maintain-ms N      backend re-warm interval (default 5000; 0=off)\n"
            "  --metrics-ms N       metrics log interval (default 30000; 0=off)\n"
            "  --metrics-http HOST:PORT  Prometheus scrape (default 127.0.0.1:9108)\n"
            "  --metrics-http-port N     metrics HTTP port only (host stays default)\n"
            "  --no-metrics-http    disable Prometheus /metrics HTTP\n"
            "  --fair               fair RR among frontends waiting on pool (default)\n"
            "  --no-fair            disable fair frontend scheduling\n"
            "  --reject-simple-query  reject simple Query 'Q' (default; extended only)\n"
            "  --allow-simple-query   insecure: forward simple Query without inject\n"
            "  --quiet              less logging\n"
            "  -h, --help           this help\n",
            argv0);
}

static int parse_listen(const char *s, pqproxy_config_t *cfg,
                        pqproxy_config_bundle_t *bundle)
{
    char host[256];
    unsigned port = 0;
    const char *colon;
    char *owned;

    if (!s || !cfg) {
        return -1;
    }
    colon = strrchr(s, ':');
    if (!colon || colon == s) {
        return -1;
    }
    if ((size_t)(colon - s) >= sizeof(host)) {
        return -1;
    }
    memcpy(host, s, (size_t)(colon - s));
    host[colon - s] = '\0';
    port = (unsigned)atoi(colon + 1);
    if (port == 0 || port > 65535) {
        return -1;
    }
    owned = strdup(host);
    if (!owned) {
        return -1;
    }
    if (bundle && bundle->n_owned < PQPROXY_CFG_OWNED_MAX) {
        bundle->owned[bundle->n_owned++] = owned;
    }
    cfg->listen_host = owned;
    cfg->listen_port = (uint16_t)port;
    return 0;
}

int main(int argc, char **argv)
{
    pqproxy_config_bundle_t bundle;
    pqproxy_config_t *cfg;
    int i;
    int rc;
    const char *config_path = NULL;
    char err[256];

    pqproxy_config_bundle_init(&bundle);
    cfg = &bundle.cfg;

    /* First pass: find --config so file loads before other flags */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = argv[++i];
            continue;
        }
    }
    if (config_path) {
        if (pqproxy_config_load_yaml(config_path, &bundle, err, sizeof(err)) != 0) {
            fprintf(stderr, "pqproxy: config: %s\n", err);
            pqproxy_config_bundle_free(&bundle);
            return 2;
        }
        cfg = &bundle.cfg;
    }

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            pqproxy_config_bundle_free(&bundle);
            return 0;
        }
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            i++; /* already applied */
            continue;
        }
        if (strcmp(argv[i], "--plain") == 0) {
            cfg->plain = 1;
            cfg->require_mtls = 0;
            continue;
        }
        if (strcmp(argv[i], "--no-mtls") == 0) {
            cfg->require_mtls = 0;
            continue;
        }
        if (strcmp(argv[i], "--quiet") == 0) {
            cfg->quiet = 1;
            continue;
        }
        if (strcmp(argv[i], "--fair") == 0) {
            cfg->fair_schedule = 1;
            continue;
        }
        if (strcmp(argv[i], "--no-fair") == 0) {
            cfg->fair_schedule = 0;
            continue;
        }
        if (strcmp(argv[i], "--reject-simple-query") == 0) {
            cfg->reject_simple_query = 1;
            continue;
        }
        if (strcmp(argv[i], "--allow-simple-query") == 0) {
            cfg->reject_simple_query = 0;
            fprintf(stderr,
                    "pqproxy: warning: --allow-simple-query forwards 'Q' without "
                    "identity inject (insecure)\n");
            continue;
        }
        if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) {
            if (parse_listen(argv[++i], cfg, &bundle) != 0) {
                fprintf(stderr, "invalid --listen\n");
                pqproxy_config_bundle_free(&bundle);
                return 2;
            }
            continue;
        }
        if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            cfg->cert_file = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            cfg->key_file = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
            cfg->ca_file = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--identity-slot") == 0 && i + 1 < argc) {
            cfg->identity_slot = (int16_t)atoi(argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "--backend") == 0 && i + 1 < argc) {
            char *s = argv[++i];
            char *colon = strrchr(s, ':');
            if (colon) {
                *colon = '\0';
                cfg->backend_host = s;
                cfg->backend_port = (uint16_t)atoi(colon + 1);
            } else {
                cfg->backend_host = s;
                cfg->backend_port = 5432;
            }
            continue;
        }
        if (strcmp(argv[i], "--backend-user") == 0 && i + 1 < argc) {
            cfg->backend_user = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--backend-password") == 0 && i + 1 < argc) {
            cfg->backend_password = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--backend-database") == 0 && i + 1 < argc) {
            cfg->backend_database = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--backend-pool") == 0 && i + 1 < argc) {
            cfg->backend_pool_size = (size_t)atoi(argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "--backend-group-login") == 0) {
            cfg->backend_use_group_as_user = 1;
            continue;
        }
        if (strcmp(argv[i], "--backend-groups") == 0 && i + 1 < argc) {
            cfg->backend_groups = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--no-lazy-group") == 0) {
            cfg->backend_lazy_group = 0;
            continue;
        }
        if (strcmp(argv[i], "--ktls-prefer") == 0) {
            cfg->prefer_tls12_ktls = 1;
            continue;
        }
        if (strcmp(argv[i], "--no-ktls-prefer") == 0) {
            cfg->prefer_tls12_ktls = 0;
            continue;
        }
        if (strcmp(argv[i], "--maintain-ms") == 0 && i + 1 < argc) {
            cfg->maintain_interval_ms = atoi(argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "--metrics-ms") == 0 && i + 1 < argc) {
            cfg->metrics_log_interval_ms = atoi(argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "--no-metrics-http") == 0) {
            cfg->metrics_http_port = 0;
            continue;
        }
        if (strcmp(argv[i], "--metrics-http-port") == 0 && i + 1 < argc) {
            int p = atoi(argv[++i]);
            if (p < 0 || p > 65535) {
                fprintf(stderr, "invalid --metrics-http-port\n");
                pqproxy_config_bundle_free(&bundle);
                return 2;
            }
            cfg->metrics_http_port = (uint16_t)p;
            continue;
        }
        if (strcmp(argv[i], "--metrics-http") == 0 && i + 1 < argc) {
            char *s = argv[++i];
            char *colon = strrchr(s, ':');
            if (colon && colon != s) {
                *colon = '\0';
                cfg->metrics_http_host = s;
                cfg->metrics_http_port = (uint16_t)atoi(colon + 1);
            } else {
                int p = atoi(s);
                if (p > 0 && p <= 65535 && s[0] >= '0' && s[0] <= '9') {
                    cfg->metrics_http_port = (uint16_t)p;
                } else {
                    cfg->metrics_http_host = s;
                }
            }
            continue;
        }
        fprintf(stderr, "unknown argument: %s\n", argv[i]);
        usage(argv[0]);
        pqproxy_config_bundle_free(&bundle);
        return 2;
    }

    if (!cfg->plain && (!cfg->cert_file || !cfg->key_file)) {
        fprintf(stderr, "pqproxy: provide --cert/--key or --plain (or set in --config)\n");
        usage(argv[0]);
        pqproxy_config_bundle_free(&bundle);
        return 2;
    }
    if (!cfg->plain && cfg->require_mtls && !cfg->ca_file) {
        fprintf(stderr, "pqproxy: mTLS requires --ca (or use --no-mtls)\n");
        pqproxy_config_bundle_free(&bundle);
        return 2;
    }

    rc = pqproxy_run(cfg);
    pqproxy_config_bundle_free(&bundle);
    return rc;
}
