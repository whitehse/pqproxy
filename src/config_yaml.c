/**
 * @file config_yaml.c
 * @brief Load pqproxy_config_t from YAML via sibling libyaml.
 */

#include "config_yaml.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "yaml.h"

void pqproxy_config_bundle_init(pqproxy_config_bundle_t *b)
{
    if (!b) {
        return;
    }
    memset(b, 0, sizeof(*b));
    pqproxy_config_defaults(&b->cfg);
}

void pqproxy_config_bundle_free(pqproxy_config_bundle_t *b)
{
    size_t i;
    if (!b) {
        return;
    }
    for (i = 0; i < b->n_owned; i++) {
        free(b->owned[i]);
        b->owned[i] = NULL;
    }
    b->n_owned = 0;
    memset(&b->cfg, 0, sizeof(b->cfg));
}

static char *bundle_strdup(pqproxy_config_bundle_t *b, const char *s)
{
    char *p;
    if (!b || !s) {
        return NULL;
    }
    if (b->n_owned >= PQPROXY_CFG_OWNED_MAX) {
        return NULL;
    }
    p = strdup(s);
    if (!p) {
        return NULL;
    }
    b->owned[b->n_owned++] = p;
    return p;
}

static int parse_bool(const char *s, int *out)
{
    if (!s || !out) {
        return -1;
    }
    if (strcmp(s, "1") == 0 || strcmp(s, "true") == 0 ||
        strcmp(s, "True") == 0 || strcmp(s, "yes") == 0 ||
        strcmp(s, "on") == 0) {
        *out = 1;
        return 0;
    }
    if (strcmp(s, "0") == 0 || strcmp(s, "false") == 0 ||
        strcmp(s, "False") == 0 || strcmp(s, "no") == 0 ||
        strcmp(s, "off") == 0) {
        *out = 0;
        return 0;
    }
    return -1;
}

static int parse_u16(const char *s, uint16_t *out)
{
    long v;
    char *end = NULL;
    if (!s || !out) {
        return -1;
    }
    v = strtol(s, &end, 10);
    if (end == s || v < 0 || v > 65535) {
        return -1;
    }
    *out = (uint16_t)v;
    return 0;
}

static int parse_int(const char *s, int *out)
{
    long v;
    char *end = NULL;
    if (!s || !out) {
        return -1;
    }
    v = strtol(s, &end, 10);
    if (end == s) {
        return -1;
    }
    *out = (int)v;
    return 0;
}

static int parse_size(const char *s, size_t *out)
{
    long v;
    char *end = NULL;
    if (!s || !out) {
        return -1;
    }
    v = strtol(s, &end, 10);
    if (end == s || v < 0) {
        return -1;
    }
    *out = (size_t)v;
    return 0;
}

static int set_hostport(pqproxy_config_bundle_t *b, const char *s,
                        const char **host_out, uint16_t *port_out)
{
    char host[256];
    const char *colon;
    unsigned port;
    char *owned;

    if (!s || !host_out || !port_out) {
        return -1;
    }
    colon = strrchr(s, ':');
    if (!colon || colon == s) {
        owned = bundle_strdup(b, s);
        if (!owned) {
            return -1;
        }
        *host_out = owned;
        return 0;
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
    owned = bundle_strdup(b, host);
    if (!owned) {
        return -1;
    }
    *host_out = owned;
    *port_out = (uint16_t)port;
    return 0;
}

static const char *lookup(yaml_ctx_t *ctx, const char *path)
{
    size_t len = 0;
    const char *v = yaml_lookup_scalar(ctx, path, &len);
    if (!v || len == 0) {
        return NULL;
    }
    return v;
}

static int join_groups_sequence(yaml_ctx_t *ctx, pqproxy_config_bundle_t *b)
{
    size_t n, i;
    char buf[512];
    size_t off = 0;
    char *owned;

    n = yaml_get_child_count(ctx, "backend.groups");
    if (n == 0) {
        return 0;
    }
    buf[0] = '\0';
    for (i = 0; i < n; i++) {
        char path[64];
        const char *val;
        size_t vlen = 0;
        snprintf(path, sizeof(path), "backend.groups.%zu", i);
        val = yaml_lookup_scalar(ctx, path, &vlen);
        if (!val || vlen == 0) {
            /* sequence of mappings? try name field */
            snprintf(path, sizeof(path), "backend.groups.%zu", i);
            continue;
        }
        if (off > 0) {
            if (off + 1 >= sizeof(buf)) {
                return -1;
            }
            buf[off++] = ',';
        }
        if (off + vlen >= sizeof(buf)) {
            return -1;
        }
        memcpy(buf + off, val, vlen);
        off += vlen;
        buf[off] = '\0';
    }
    if (off == 0) {
        return 0;
    }
    owned = bundle_strdup(b, buf);
    if (!owned) {
        return -1;
    }
    b->cfg.backend_groups = owned;
    return 0;
}

static int apply_scalar(pqproxy_config_bundle_t *b, const char *key, const char *val,
                        char *err, size_t err_len)
{
    char *owned;
    int iv;
    uint16_t u16;
    size_t sz;

    if (!key || !val) {
        return 0;
    }

#define FAIL(msg) do { \
        if (err && err_len) { \
            snprintf(err, err_len, "%s: %s", key, msg); \
        } \
        return -1; \
    } while (0)

    if (strcmp(key, "listen.host") == 0 || strcmp(key, "listen_host") == 0) {
        owned = bundle_strdup(b, val);
        if (!owned) {
            FAIL("oom");
        }
        b->cfg.listen_host = owned;
        return 0;
    }
    if (strcmp(key, "listen.port") == 0 || strcmp(key, "listen_port") == 0) {
        if (parse_u16(val, &u16) != 0 || u16 == 0) {
            FAIL("invalid port");
        }
        b->cfg.listen_port = u16;
        return 0;
    }
    if (strcmp(key, "listen") == 0) {
        if (set_hostport(b, val, &b->cfg.listen_host, &b->cfg.listen_port) != 0) {
            FAIL("invalid HOST:PORT");
        }
        return 0;
    }
    if (strcmp(key, "tls.plain") == 0 || strcmp(key, "plain") == 0) {
        if (parse_bool(val, &iv) != 0) {
            FAIL("invalid bool");
        }
        b->cfg.plain = iv;
        if (iv) {
            b->cfg.require_mtls = 0;
        }
        return 0;
    }
    if (strcmp(key, "tls.require_mtls") == 0 || strcmp(key, "require_mtls") == 0) {
        if (parse_bool(val, &iv) != 0) {
            FAIL("invalid bool");
        }
        b->cfg.require_mtls = iv;
        return 0;
    }
    if (strcmp(key, "tls.cert") == 0 || strcmp(key, "cert") == 0) {
        owned = bundle_strdup(b, val);
        if (!owned) {
            FAIL("oom");
        }
        b->cfg.cert_file = owned;
        return 0;
    }
    if (strcmp(key, "tls.key") == 0 || strcmp(key, "key") == 0) {
        owned = bundle_strdup(b, val);
        if (!owned) {
            FAIL("oom");
        }
        b->cfg.key_file = owned;
        return 0;
    }
    if (strcmp(key, "tls.ca") == 0 || strcmp(key, "ca") == 0) {
        owned = bundle_strdup(b, val);
        if (!owned) {
            FAIL("oom");
        }
        b->cfg.ca_file = owned;
        return 0;
    }
    if (strcmp(key, "tls.ktls_prefer") == 0 || strcmp(key, "ktls_prefer") == 0) {
        if (parse_bool(val, &iv) != 0) {
            FAIL("invalid bool");
        }
        b->cfg.prefer_tls12_ktls = iv;
        return 0;
    }
    if (strcmp(key, "identity.slot") == 0 || strcmp(key, "identity_slot") == 0) {
        if (parse_int(val, &iv) != 0 || iv < -1 || iv > 32767) {
            FAIL("invalid slot");
        }
        b->cfg.identity_slot = (int16_t)iv;
        return 0;
    }
    if (strcmp(key, "backend.host") == 0 || strcmp(key, "backend_host") == 0) {
        owned = bundle_strdup(b, val);
        if (!owned) {
            FAIL("oom");
        }
        b->cfg.backend_host = owned;
        return 0;
    }
    if (strcmp(key, "backend.port") == 0 || strcmp(key, "backend_port") == 0) {
        if (parse_u16(val, &u16) != 0) {
            FAIL("invalid port");
        }
        b->cfg.backend_port = u16;
        return 0;
    }
    if (strcmp(key, "backend") == 0) {
        if (set_hostport(b, val, &b->cfg.backend_host, &b->cfg.backend_port) != 0) {
            FAIL("invalid HOST:PORT");
        }
        return 0;
    }
    if (strcmp(key, "backend.user") == 0 || strcmp(key, "backend_user") == 0) {
        owned = bundle_strdup(b, val);
        if (!owned) {
            FAIL("oom");
        }
        b->cfg.backend_user = owned;
        return 0;
    }
    if (strcmp(key, "backend.password") == 0 || strcmp(key, "backend_password") == 0) {
        owned = bundle_strdup(b, val);
        if (!owned) {
            FAIL("oom");
        }
        b->cfg.backend_password = owned;
        return 0;
    }
    if (strcmp(key, "backend.database") == 0 || strcmp(key, "backend_database") == 0) {
        owned = bundle_strdup(b, val);
        if (!owned) {
            FAIL("oom");
        }
        b->cfg.backend_database = owned;
        return 0;
    }
    if (strcmp(key, "backend.pool_size") == 0 || strcmp(key, "backend_pool") == 0) {
        if (parse_size(val, &sz) != 0) {
            FAIL("invalid size");
        }
        b->cfg.backend_pool_size = sz;
        return 0;
    }
    if (strcmp(key, "backend.group_login") == 0 ||
        strcmp(key, "backend_group_login") == 0) {
        if (parse_bool(val, &iv) != 0) {
            FAIL("invalid bool");
        }
        b->cfg.backend_use_group_as_user = iv;
        return 0;
    }
    if (strcmp(key, "backend.groups") == 0 || strcmp(key, "backend_groups") == 0) {
        owned = bundle_strdup(b, val);
        if (!owned) {
            FAIL("oom");
        }
        b->cfg.backend_groups = owned;
        return 0;
    }
    if (strcmp(key, "backend.lazy_group") == 0 || strcmp(key, "lazy_group") == 0) {
        if (parse_bool(val, &iv) != 0) {
            FAIL("invalid bool");
        }
        b->cfg.backend_lazy_group = iv;
        return 0;
    }
    if (strcmp(key, "metrics.log_ms") == 0 || strcmp(key, "metrics_ms") == 0) {
        if (parse_int(val, &iv) != 0 || iv < 0) {
            FAIL("invalid ms");
        }
        b->cfg.metrics_log_interval_ms = iv;
        return 0;
    }
    if (strcmp(key, "metrics.http_host") == 0) {
        owned = bundle_strdup(b, val);
        if (!owned) {
            FAIL("oom");
        }
        b->cfg.metrics_http_host = owned;
        return 0;
    }
    if (strcmp(key, "metrics.http_port") == 0) {
        if (parse_u16(val, &u16) != 0) {
            FAIL("invalid port");
        }
        b->cfg.metrics_http_port = u16;
        return 0;
    }
    if (strcmp(key, "metrics.http") == 0 || strcmp(key, "metrics_http") == 0) {
        if (strcmp(val, "off") == 0 || strcmp(val, "false") == 0 ||
            strcmp(val, "0") == 0) {
            b->cfg.metrics_http_port = 0;
            return 0;
        }
        if (set_hostport(b, val, &b->cfg.metrics_http_host,
                         &b->cfg.metrics_http_port) != 0) {
            FAIL("invalid HOST:PORT");
        }
        return 0;
    }
    if (strcmp(key, "maintain_ms") == 0) {
        if (parse_int(val, &iv) != 0 || iv < 0) {
            FAIL("invalid ms");
        }
        b->cfg.maintain_interval_ms = iv;
        return 0;
    }
    if (strcmp(key, "quiet") == 0) {
        if (parse_bool(val, &iv) != 0) {
            FAIL("invalid bool");
        }
        b->cfg.quiet = iv;
        return 0;
    }
    if (strcmp(key, "fair_schedule") == 0 || strcmp(key, "fair") == 0) {
        if (parse_bool(val, &iv) != 0) {
            FAIL("invalid bool");
        }
        b->cfg.fair_schedule = iv;
        return 0;
    }
    if (strcmp(key, "reject_simple_query") == 0 ||
        strcmp(key, "extended_only") == 0) {
        if (parse_bool(val, &iv) != 0) {
            FAIL("invalid bool");
        }
        b->cfg.reject_simple_query = iv;
        return 0;
    }
    if (strcmp(key, "allow_simple_query") == 0) {
        if (parse_bool(val, &iv) != 0) {
            FAIL("invalid bool");
        }
        b->cfg.reject_simple_query = iv ? 0 : 1;
        return 0;
    }
    if (strcmp(key, "log_json") == 0 || strcmp(key, "structured_log") == 0) {
        if (parse_bool(val, &iv) != 0) {
            FAIL("invalid bool");
        }
        b->cfg.log_json = iv;
        return 0;
    }
#undef FAIL
    return 0; /* unknown keys ignored */
}

static const char *const g_paths[] = {
    "listen",
    "listen.host",
    "listen.port",
    "listen_host",
    "listen_port",
    "tls.plain",
    "tls.require_mtls",
    "tls.cert",
    "tls.key",
    "tls.ca",
    "tls.ktls_prefer",
    "plain",
    "require_mtls",
    "cert",
    "key",
    "ca",
    "ktls_prefer",
    "identity.slot",
    "identity_slot",
    "backend",
    "backend.host",
    "backend.port",
    "backend.user",
    "backend.password",
    "backend.database",
    "backend.pool_size",
    "backend.group_login",
    "backend.groups",
    "backend.lazy_group",
    "backend_host",
    "backend_port",
    "backend_user",
    "backend_password",
    "backend_database",
    "backend_pool",
    "backend_group_login",
    "backend_groups",
    "lazy_group",
    "metrics.log_ms",
    "metrics.http_host",
    "metrics.http_port",
    "metrics.http",
    "metrics_ms",
    "metrics_http",
    "maintain_ms",
    "quiet",
    "fair_schedule",
    "fair",
    "reject_simple_query",
    "extended_only",
    "allow_simple_query",
    "log_json",
    "structured_log",
    NULL
};

static int load_from_ctx(yaml_ctx_t *ctx, pqproxy_config_bundle_t *b,
                         char *err, size_t err_len)
{
    size_t i;
    yaml_event_t ev;

    /* Drain events so knowledge tree is fully populated */
    while (yaml_next_event(ctx, &ev)) {
        if (ev.type == YAML_EVENT_ERROR) {
            if (err && err_len) {
                snprintf(err, err_len, "yaml parse: %s",
                         ev.data.error.message[0] ? ev.data.error.message
                                                  : "error");
            }
            return -1;
        }
    }

    for (i = 0; g_paths[i]; i++) {
        const char *val = lookup(ctx, g_paths[i]);
        if (!val) {
            continue;
        }
        if (apply_scalar(b, g_paths[i], val, err, err_len) != 0) {
            return -1;
        }
    }

    /* Sequence form of backend.groups if scalar not set */
    if (!b->cfg.backend_groups) {
        if (join_groups_sequence(ctx, b) != 0) {
            if (err && err_len) {
                snprintf(err, err_len, "backend.groups sequence too long");
            }
            return -1;
        }
    }
    return 0;
}

int pqproxy_config_load_yaml_buf(const char *yaml, size_t yaml_len,
                                 pqproxy_config_bundle_t *b,
                                 char *err, size_t err_len)
{
    yaml_ctx_t *ctx;
    size_t n;

    if (!yaml || !b) {
        if (err && err_len) {
            snprintf(err, err_len, "null args");
        }
        return -1;
    }
    pqproxy_config_bundle_init(b);
    ctx = yaml_create(YAML_ROLE_PARSER);
    if (!ctx) {
        if (err && err_len) {
            snprintf(err, err_len, "yaml_create failed");
        }
        return -1;
    }
    n = yaml_feed_input(ctx, (const uint8_t *)yaml, yaml_len);
    if (n == 0 && yaml_len > 0) {
        if (err && err_len) {
            snprintf(err, err_len, "yaml_feed_input consumed 0");
        }
        yaml_destroy(ctx);
        pqproxy_config_bundle_free(b);
        return -1;
    }
    if (load_from_ctx(ctx, b, err, err_len) != 0) {
        yaml_destroy(ctx);
        pqproxy_config_bundle_free(b);
        return -1;
    }
    yaml_destroy(ctx);
    return 0;
}

int pqproxy_config_load_yaml(const char *path, pqproxy_config_bundle_t *b,
                             char *err, size_t err_len)
{
    FILE *fp;
    char *buf = NULL;
    size_t cap = 0;
    size_t len = 0;
    char chunk[4096];
    size_t nr;
    int rc;

    if (!path || !b) {
        if (err && err_len) {
            snprintf(err, err_len, "null args");
        }
        return -1;
    }
    fp = fopen(path, "rb");
    if (!fp) {
        if (err && err_len) {
            snprintf(err, err_len, "cannot open %s", path);
        }
        return -1;
    }
    while ((nr = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
        char *nb;
        if (len + nr + 1 > cap) {
            size_t ncap = cap ? cap * 2 : 8192;
            while (ncap < len + nr + 1) {
                ncap *= 2;
            }
            nb = realloc(buf, ncap);
            if (!nb) {
                free(buf);
                fclose(fp);
                if (err && err_len) {
                    snprintf(err, err_len, "oom reading config");
                }
                return -1;
            }
            buf = nb;
            cap = ncap;
        }
        memcpy(buf + len, chunk, nr);
        len += nr;
    }
    fclose(fp);
    if (!buf) {
        /* empty file → defaults */
        pqproxy_config_bundle_init(b);
        return 0;
    }
    buf[len] = '\0';
    rc = pqproxy_config_load_yaml_buf(buf, len, b, err, err_len);
    free(buf);
    return rc;
}
