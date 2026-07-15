#include "pqproxy.h"

#include <string.h>
#include <stdio.h>

void pqproxy_identity_clear(pqproxy_identity_t *id)
{
    if (!id) {
        return;
    }
    memset(id, 0, sizeof(*id));
    id->identity_slot = -1;
}

int pqproxy_identity_from_cert_subject(const char *subject, pqproxy_identity_t *out)
{
    /* Stub convention: subject "CN=router-<id>/OU=<group>" or "router_id:group" */
    const char *colon;
    if (!subject || !out) {
        return -1;
    }
    pqproxy_identity_clear(out);
    colon = strchr(subject, ':');
    if (colon && colon > subject && colon[1] != '\0') {
        size_t n = (size_t)(colon - subject);
        if (n >= sizeof(out->router_id)) {
            n = sizeof(out->router_id) - 1;
        }
        memcpy(out->router_id, subject, n);
        out->router_id[n] = '\0';
        strncpy(out->group, colon + 1, sizeof(out->group) - 1);
        out->identity_slot = 0; /* default first param */
        return 0;
    }
    strncpy(out->router_id, subject, sizeof(out->router_id) - 1);
    strncpy(out->group, "default", sizeof(out->group) - 1);
    out->identity_slot = 0;
    return 0;
}
