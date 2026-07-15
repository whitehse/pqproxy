#include "pqproxy.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    pqproxy_identity_t id;

    assert(pqproxy_identity_from_cert_subject("router-9:region_east", &id) == 0);
    assert(strcmp(id.router_id, "router-9") == 0);
    assert(strcmp(id.group, "region_east") == 0);

    assert(pqproxy_identity_from_cert_subject(
               "/CN=router-dev-001/OU=region_east", &id) == 0);
    assert(strcmp(id.router_id, "router-dev-001") == 0);
    assert(strcmp(id.group, "region_east") == 0);

    assert(pqproxy_identity_from_cert_subject("/CN=only-cn", &id) == 0);
    assert(strcmp(id.router_id, "only-cn") == 0);
    assert(strcmp(id.group, "default") == 0);

    printf("identity parse test PASSED\n");
    return 0;
}
