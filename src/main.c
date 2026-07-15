#include "pqproxy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [options]\n"
            "  --listen HOST:PORT   default 0.0.0.0:6432\n"
            "  --cert FILE          server certificate PEM\n"
            "  --key FILE           server private key PEM\n"
            "  --ca FILE            client CA PEM (mTLS)\n"
            "  --plain              no TLS (development only)\n"
            "  --no-mtls            TLS without requiring client cert\n"
            "  --identity-slot N    Bind param index for router_id (default 0)\n"
            "  --quiet              less logging\n"
            "  -h, --help           this help\n",
            argv0);
}

static int parse_listen(const char *s, pqproxy_config_t *cfg)
{
    char host[256];
    unsigned port = 0;
    const char *colon;

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
    /* leak-free: store in static or strdup — use strdup for simplicity */
    cfg->listen_host = strdup(host);
    cfg->listen_port = (uint16_t)port;
    return 0;
}

int main(int argc, char **argv)
{
    pqproxy_config_t cfg;
    int i;

    pqproxy_config_defaults(&cfg);

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--plain") == 0) {
            cfg.plain = 1;
            cfg.require_mtls = 0;
            continue;
        }
        if (strcmp(argv[i], "--no-mtls") == 0) {
            cfg.require_mtls = 0;
            continue;
        }
        if (strcmp(argv[i], "--quiet") == 0) {
            cfg.quiet = 1;
            continue;
        }
        if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) {
            if (parse_listen(argv[++i], &cfg) != 0) {
                fprintf(stderr, "invalid --listen\n");
                return 2;
            }
            continue;
        }
        if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            cfg.cert_file = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            cfg.key_file = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
            cfg.ca_file = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--identity-slot") == 0 && i + 1 < argc) {
            cfg.identity_slot = (int16_t)atoi(argv[++i]);
            continue;
        }
        fprintf(stderr, "unknown argument: %s\n", argv[i]);
        usage(argv[0]);
        return 2;
    }

    if (!cfg.plain && (!cfg.cert_file || !cfg.key_file)) {
        fprintf(stderr, "pqproxy: provide --cert/--key or --plain\n");
        usage(argv[0]);
        return 2;
    }
    if (!cfg.plain && cfg.require_mtls && !cfg.ca_file) {
        fprintf(stderr, "pqproxy: mTLS requires --ca (or use --no-mtls)\n");
        return 2;
    }

    return pqproxy_run(&cfg);
}
