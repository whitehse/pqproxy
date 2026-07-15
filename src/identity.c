#include "pqproxy.h"

#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

void pqproxy_identity_clear(pqproxy_identity_t *id)
{
    if (!id) {
        return;
    }
    memset(id, 0, sizeof(*id));
    id->identity_slot = -1;
}

static void copy_field(char *dst, size_t dstsz, const char *src, size_t n)
{
    if (!dst || dstsz == 0) {
        return;
    }
    if (n >= dstsz) {
        n = dstsz - 1;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/** Extract NID value from subject DN into dst. */
static int dn_get_nid(X509_NAME *name, int nid, char *dst, size_t dstsz)
{
    int idx;
    X509_NAME_ENTRY *ent;
    ASN1_STRING *str;
    const unsigned char *data;
    int len;

    if (!name || !dst || dstsz == 0) {
        return -1;
    }
    idx = X509_NAME_get_index_by_NID(name, nid, -1);
    if (idx < 0) {
        return -1;
    }
    ent = X509_NAME_get_entry(name, idx);
    if (!ent) {
        return -1;
    }
    str = X509_NAME_ENTRY_get_data(ent);
    if (!str) {
        return -1;
    }
    data = ASN1_STRING_get0_data(str);
    len = ASN1_STRING_length(str);
    if (!data || len <= 0) {
        return -1;
    }
    copy_field(dst, dstsz, (const char *)data, (size_t)len);
    return 0;
}

int pqproxy_identity_from_cert_subject(const char *subject, pqproxy_identity_t *out)
{
    const char *colon;
    const char *cn;
    const char *ou;
    const char *slash;

    if (!subject || !out) {
        return -1;
    }
    pqproxy_identity_clear(out);
    out->identity_slot = 0;

    /* Form: router_id:group */
    colon = strchr(subject, ':');
    if (colon && colon > subject && colon[1] != '\0' && subject[0] != '/') {
        /* Avoid treating "https://..." style; only simple tokens */
        int simple = 1;
        const char *p;
        for (p = subject; p < colon; p++) {
            if (*p == '/' || *p == '=') {
                simple = 0;
                break;
            }
        }
        if (simple) {
            copy_field(out->router_id, sizeof(out->router_id), subject,
                       (size_t)(colon - subject));
            strncpy(out->group, colon + 1, sizeof(out->group) - 1);
            return 0;
        }
    }

    /* OpenSSL oneline: /CN=router/OU=group/... */
    cn = strstr(subject, "/CN=");
    if (!cn) {
        cn = strstr(subject, "CN=");
        if (cn == subject || (cn && cn[-1] == '/')) {
            /* ok */
        } else if (cn && cn > subject && cn[-1] != '/') {
            cn = NULL;
        }
    }
    if (cn) {
        const char *start = strchr(cn, '=');
        if (start) {
            start++;
            slash = strchr(start, '/');
            if (slash) {
                copy_field(out->router_id, sizeof(out->router_id), start,
                           (size_t)(slash - start));
            } else {
                strncpy(out->router_id, start, sizeof(out->router_id) - 1);
            }
        }
    }

    ou = strstr(subject, "/OU=");
    if (!ou) {
        ou = strstr(subject, "OU=");
    }
    if (ou) {
        const char *start = strchr(ou, '=');
        if (start) {
            start++;
            slash = strchr(start, '/');
            if (slash) {
                copy_field(out->group, sizeof(out->group), start,
                           (size_t)(slash - start));
            } else {
                strncpy(out->group, start, sizeof(out->group) - 1);
            }
        }
    }

    if (out->router_id[0] == '\0') {
        strncpy(out->router_id, subject, sizeof(out->router_id) - 1);
    }
    if (out->group[0] == '\0') {
        strncpy(out->group, "default", sizeof(out->group) - 1);
    }
    return 0;
}

int pqproxy_identity_from_x509(const X509 *cert, pqproxy_identity_t *out)
{
    X509_NAME *subj;
    char cn[128];
    char ou[64];

    if (!cert || !out) {
        return -1;
    }
    pqproxy_identity_clear(out);
    out->identity_slot = 0;

    subj = X509_get_subject_name(cert);
    if (!subj) {
        return -1;
    }

    cn[0] = '\0';
    ou[0] = '\0';
    (void)dn_get_nid(subj, NID_commonName, cn, sizeof(cn));
    (void)dn_get_nid(subj, NID_organizationalUnitName, ou, sizeof(ou));

    if (cn[0] == '\0') {
        /* Fallback: full oneline subject */
        char *line = X509_NAME_oneline(subj, NULL, 0);
        int rc;
        if (!line) {
            return -1;
        }
        rc = pqproxy_identity_from_cert_subject(line, out);
        OPENSSL_free(line);
        return rc;
    }

    strncpy(out->router_id, cn, sizeof(out->router_id) - 1);
    if (ou[0]) {
        strncpy(out->group, ou, sizeof(out->group) - 1);
    } else {
        strncpy(out->group, "default", sizeof(out->group) - 1);
    }
    return 0;
}
