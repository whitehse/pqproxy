#include "pqproxy.h"

#include <stdio.h>
#include <string.h>

/*
 * pqproxy entry point (scaffold).
 * Full io_uring + mTLS + pool loop is tracked in TODO.md.
 */
int main(int argc, char **argv)
{
    pqproxy_identity_t id;
    (void)argc;
    (void)argv;

    printf("pqproxy 0.1.0 — PostgreSQL L7 identity proxy (scaffold)\n");
    printf("Libraries: pique (libpqwire)\n");
    printf("See AGENTS.md / TODO.md for implementation roadmap.\n");

    if (pqproxy_identity_from_cert_subject("cpe-001:region_east", &id) == 0) {
        printf("example identity: router_id=%s group=%s slot=%d\n",
               id.router_id, id.group, (int)id.identity_slot);
    }

    return 0;
}
