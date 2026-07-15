/**
 * Mock PostgreSQL backend: warm-up + one extended-query pipeline round-trip.
 */

#include "backend_pool.h"
#include "pqproxy.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile int g_stop;
static int g_listen_fd = -1;

static int write_all(int fd, const uint8_t *p, size_t n)
{
    size_t o = 0;
    while (o < n) {
        ssize_t w = write(fd, p + o, n - o);
        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w <= 0) {
            return -1;
        }
        o += (size_t)w;
    }
    return 0;
}

static int read_n(int fd, uint8_t *p, size_t n)
{
    size_t o = 0;
    while (o < n) {
        ssize_t r = read(fd, p + o, n - o);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r <= 0) {
            return -1;
        }
        o += (size_t)r;
    }
    return 0;
}

static void handle_client(int cfd)
{
    uint8_t buf[8192];
    uint32_t mlen;

    if (read_n(cfd, buf, 4) != 0) {
        close(cfd);
        return;
    }
    mlen = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
    if (mlen < 8 || mlen > sizeof(buf) ||
        read_n(cfd, buf + 4, mlen - 4) != 0) {
        close(cfd);
        return;
    }

    {
        uint8_t auth[] = {'R', 0, 0, 0, 8, 0, 0, 0, 0};
        uint8_t rfq[] = {'Z', 0, 0, 0, 5, 'I'};
        write_all(cfd, auth, sizeof(auth));
        write_all(cfd, rfq, sizeof(rfq));
    }

    for (;;) {
        ssize_t n = read(cfd, buf, sizeof(buf));
        size_t i;
        if (n <= 0) {
            break;
        }
        for (i = 0; i + 5 <= (size_t)n; i++) {
            if (buf[i] == 'S' && buf[i + 1] == 0 && buf[i + 2] == 0 &&
                buf[i + 3] == 0 && buf[i + 4] == 4) {
                static const uint8_t pc[] = {'1', 0, 0, 0, 4};
                static const uint8_t bc[] = {'2', 0, 0, 0, 4};
                static const uint8_t cc[] = {
                    'C', 0, 0, 0, 15,
                    'I', 'N', 'S', 'E', 'R', 'T', ' ', '0', ' ', '1', 0
                };
                static const uint8_t z[] = {'Z', 0, 0, 0, 5, 'I'};
                write_all(cfd, pc, sizeof(pc));
                write_all(cfd, bc, sizeof(bc));
                write_all(cfd, cc, sizeof(cc));
                write_all(cfd, z, sizeof(z));
                break;
            }
        }
    }
    close(cfd);
}

static void *mock_backend(void *arg)
{
    (void)arg;
    while (!g_stop) {
        struct sockaddr_in a;
        socklen_t al = sizeof(a);
        int cfd = accept(g_listen_fd, (struct sockaddr *)&a, &al);
        if (cfd < 0) {
            break;
        }
        handle_client(cfd);
    }
    return NULL;
}

int main(void)
{
    struct sockaddr_in addr;
    socklen_t al = sizeof(addr);
    pthread_t thr;
    pqproxy_backend_config_t bcfg;
    pqproxy_backend_pool_t *pool;
    pqproxy_stmt_cache_t cache;
    pqproxy_identity_t id;
    pq_parse_t parse;
    pq_bind_t bmsg;
    uint8_t out[4096];
    size_t olen = 0;
    int on = 1;
    uint16_t port;
    int rc;

    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(g_listen_fd >= 0);
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert(bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(listen(g_listen_fd, 8) == 0);
    assert(getsockname(g_listen_fd, (struct sockaddr *)&addr, &al) == 0);
    port = ntohs(addr.sin_port);

    g_stop = 0;
    assert(pthread_create(&thr, NULL, mock_backend, NULL) == 0);
    usleep(20000);

    pqproxy_backend_config_defaults(&bcfg);
    bcfg.host = "127.0.0.1";
    bcfg.port = port;
    bcfg.user = "postgres";
    bcfg.password = "";
    bcfg.database = "postgres";
    bcfg.pool_size = 1;
    bcfg.quiet = 1;
    bcfg.io_timeout_ms = 2000;
    pool = pqproxy_backend_pool_create(&bcfg);
    assert(pool && pqproxy_backend_pool_alive(pool));

    pqproxy_stmt_cache_init(&cache);
    memset(&parse, 0, sizeof(parse));
    strcpy(parse.statement, "st1");
    strcpy(parse.query, "INSERT INTO t(router_id,x) VALUES ($1,$2)");
    assert(pqproxy_stmt_cache_put(&cache, &parse, 0) == 0);
    assert(pqproxy_identity_from_cert_subject("router-9:region_east", &id) == 0);

    memset(&bmsg, 0, sizeof(bmsg));
    strcpy(bmsg.statement, "st1");
    bmsg.n_params = 2;
    bmsg.params[0].length = (int32_t)strlen("forged");
    bmsg.params[0].data = (const uint8_t *)"forged";
    bmsg.params[0].format = 0;
    bmsg.params[1].length = 1;
    bmsg.params[1].data = (const uint8_t *)"x";
    bmsg.params[1].format = 0;

    rc = pqproxy_backend_exec_bind(pool, &cache, &bmsg, &id, out, sizeof(out), &olen);
    assert(rc == 0 && olen > 0);

    {
        size_t i = 0;
        int saw_z = 0, saw_c = 0, saw_one = 0;
        while (i + 5 <= olen) {
            uint32_t m = ((uint32_t)out[i + 1] << 24) | ((uint32_t)out[i + 2] << 16) |
                         ((uint32_t)out[i + 3] << 8) | (uint32_t)out[i + 4];
            if (out[i] == 'Z') {
                saw_z = 1;
            }
            if (out[i] == 'C') {
                saw_c = 1;
            }
            if (out[i] == '1') {
                saw_one = 1;
            }
            i += 1u + m;
        }
        assert(saw_z && saw_c && !saw_one);
    }

    printf("backend pool mock test PASSED\n");

    /* Close pool (and backend fds) before joining mock so its read() unblocks */
    pqproxy_backend_pool_destroy(pool);
    g_stop = 1;
    if (g_listen_fd >= 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
    }
    pthread_join(thr, NULL);
    return 0;
}
