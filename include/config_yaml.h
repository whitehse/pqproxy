#ifndef PQPROXY_CONFIG_YAML_H
#define PQPROXY_CONFIG_YAML_H

#include "pqproxy.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Owned string storage for a loaded config. CLI/main keep this alive for the
 * process lifetime; free with pqproxy_config_bundle_free().
 */
#define PQPROXY_CFG_OWNED_MAX 32

typedef struct {
    pqproxy_config_t cfg;
    char            *owned[PQPROXY_CFG_OWNED_MAX];
    size_t           n_owned;
} pqproxy_config_bundle_t;

void pqproxy_config_bundle_init(pqproxy_config_bundle_t *b);
void pqproxy_config_bundle_free(pqproxy_config_bundle_t *b);

/**
 * Load YAML from path into *b (starts from defaults, then overlays file).
 * On success returns 0 and fills b->cfg. On failure returns -1 and writes
 * a message into err (if non-NULL).
 *
 * Recognized keys (dot paths):
 *   listen.host, listen.port
 *   tls.plain, tls.require_mtls, tls.cert, tls.key, tls.ca, tls.ktls_prefer
 *   identity.slot
 *   backend.host, backend.port, backend.user, backend.password,
 *   backend.database, backend.pool_size, backend.group_login,
 *   backend.groups (quoted CSV string preferred), backend.lazy_group
 *   metrics.log_ms, metrics.http_host, metrics.http_port, metrics.http (HOST:PORT)
 *   maintain_ms, quiet
 *
 * Also accepts flat aliases: listen, cert, key, ca, plain, identity_slot, …
 */
int pqproxy_config_load_yaml(const char *path, pqproxy_config_bundle_t *b,
                             char *err, size_t err_len);

/**
 * Load YAML from a memory buffer (for tests). Same keys as load_yaml.
 */
int pqproxy_config_load_yaml_buf(const char *yaml, size_t yaml_len,
                                 pqproxy_config_bundle_t *b,
                                 char *err, size_t err_len);

#ifdef __cplusplus
}
#endif

#endif /* PQPROXY_CONFIG_YAML_H */
