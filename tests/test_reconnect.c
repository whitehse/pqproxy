/**
 * Backend reconnect / maintain with a short-lived mock server.
 */

#include "backend_pool.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile int g_stop;
static int g_listen_fd = -1;
static volatile int g_accepts;

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
    uint8_t buf[4096];
    uint32_t mlen;
    g_accepts++;
    if (read_n(cfd, buf, 4) != 0) {
        close(cfd);
        return;
    }
    mlen = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
    if (mlen >= 8 && mlen < sizeof(buf)) {
        (void)read_n(cfd, buf + 4, mlen - 4);
    }
    {
        uint8_t auth[] = {'R', 0, 0, 0, 8, 0, 0, 0, 0};
        uint8_t rfq[] = {'Z', 0, 0, 0, 5, 'I'};
        write_all(cfd, auth, sizeof(auth));
        write_all(cfd, rfq, sizeof(rfq));
    }
    /* Non-blocking drain until peer closes or stop */
    {
        int fl = fcntl(cfd, F_GETFL, 0);
        if (fl >= 0) {
            fcntl(cfd, F_SETFL, fl | O_NONBLOCK);
        }
    }
    while (!g_stop) {
        ssize_t r = read(cfd, buf, sizeof(buf));
        if (r == 0) {
            break;
        }
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            usleep(1000);
            continue;
        }
        if (r < 0) {
            break;
        }
    }
    close(cfd);
}

static void *mock(void *arg)
{
    (void)arg;
    while (!g_stop) {
        struct sockaddr_in a;
        socklen_t al = sizeof(a);
        int cfd;
        fd_set rfds;
        struct timeval tv;
        FD_ZERO(&rfds);
        FD_SET(g_listen_fd, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 50000;
        if (select(g_listen_fd + 1, &rfds, NULL, NULL, &tv) <= 0) {
            continue;
        }
        cfd = accept(g_listen_fd, (struct sockaddr *)&a, &al);
        if (cfd < 0) {
            continue;
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
    pqproxy_backend_config_t cfg;
    pqproxy_backend_pool_t *pool;
    pqproxy_backend_conn_t *be;
    int on = 1;
    uint16_t port;

    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(listen(g_listen_fd, 8) == 0);
    assert(getsockname(g_listen_fd, (struct sockaddr *)&addr, &al) == 0);
    port = ntohs(addr.sin_port);
    g_stop = 0;
    g_accepts = 0;
    assert(pthread_create(&thr, NULL, mock, NULL) == 0);
    usleep(30000);

    pqproxy_backend_config_defaults(&cfg);
    cfg.host = "127.0.0.1";
    cfg.port = port;
    cfg.user = "u";
    cfg.password = "";
    cfg.pool_size = 1;
    cfg.quiet = 1;
    cfg.auto_reconnect = 1;
    pool = pqproxy_backend_pool_create(&cfg);
    assert(pool);
    assert(pqproxy_backend_pool_live_count(pool) == 1);
    assert(g_accepts >= 1);

    be = pqproxy_backend_checkout(pool, NULL);
    assert(be);
    pqproxy_backend_mark_dead(be);
    assert(pqproxy_backend_reconnect(pool, be) == 0);
    assert(pqproxy_backend_pool_live_count(pool) == 1);
    assert(g_accepts >= 2);
    pqproxy_backend_checkin(pool, be);

    be = pqproxy_backend_checkout(pool, NULL);
    assert(be);
    pqproxy_backend_mark_dead(be);
    pqproxy_backend_checkin(pool, be);
    assert(pqproxy_backend_pool_maintain(pool) >= 1);
    assert(pqproxy_backend_pool_live_count(pool) >= 1);

    printf("reconnect test PASSED (accepts=%d)\n", g_accepts);

    g_stop = 1;
    pqproxy_backend_pool_destroy(pool);
    close(g_listen_fd);
    g_listen_fd = -1;
    pthread_join(thr, NULL);
    return 0;
}
