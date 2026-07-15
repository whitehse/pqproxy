/**
 * Unit test: Prometheus text format + HTTP /metrics and /health endpoints.
 */

#include "metrics_http.h"
#include "metrics_internal.h"
#include "pqproxy.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int pick_port(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    socklen_t alen = sizeof(a);
    int port;

    if (fd < 0) {
        return 19108;
    }
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(fd);
        return 19108;
    }
    if (getsockname(fd, (struct sockaddr *)&a, &alen) != 0) {
        close(fd);
        return 19108;
    }
    port = (int)ntohs(a.sin_port);
    close(fd);
    return port;
}

static int http_get(const char *host, uint16_t port, const char *path,
                    char *resp, size_t resp_len)
{
    int fd;
    struct sockaddr_in a;
    char req[256];
    ssize_t n, total = 0;
    int i;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &a.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    for (i = 0; i < 50; i++) {
        if (connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0) {
            break;
        }
        usleep(20000);
        if (i == 49) {
            close(fd);
            return -1;
        }
        close(fd);
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            return -1;
        }
    }
    snprintf(req, sizeof(req), "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", path, host);
    if (write(fd, req, strlen(req)) < 0) {
        close(fd);
        return -1;
    }
    while (total + 1 < (ssize_t)resp_len) {
        n = read(fd, resp + total, resp_len - 1 - (size_t)total);
        if (n <= 0) {
            break;
        }
        total += n;
    }
    resp[total] = '\0';
    close(fd);
    return (int)total;
}

int main(void)
{
    char body[4096];
    char resp[8192];
    int n;
    int port;
    const char *host = "127.0.0.1";

    pqproxy_metrics_inc_accepts();
    pqproxy_metrics_inc_be_ok();
    pqproxy_metrics_set_gauges(1, 2);

    n = pqproxy_metrics_prometheus_format(body, sizeof(body));
    assert(n > 0);
    assert(strstr(body, "pqproxy_accepts_total") != NULL);
    assert(strstr(body, "pqproxy_backend_pipelines_ok_total") != NULL);
    assert(strstr(body, "pqproxy_live_backends") != NULL);
    printf("prometheus format OK (%d bytes)\n", n);

    /* port 0 is no-op */
    assert(pqproxy_metrics_http_start(host, 0) == 0);

    port = pick_port();
    if (pqproxy_metrics_http_start(host, (uint16_t)port) != 0) {
        fprintf(stderr, "FAIL: metrics_http_start on %s:%d\n", host, port);
        return 1;
    }

    n = http_get(host, (uint16_t)port, "/metrics", resp, sizeof(resp));
    assert(n > 0);
    assert(strstr(resp, "HTTP/1.1 200") != NULL);
    assert(strstr(resp, "pqproxy_accepts_total") != NULL);
    printf("/metrics scrape OK\n");

    n = http_get(host, (uint16_t)port, "/health", resp, sizeof(resp));
    assert(n > 0);
    assert(strstr(resp, "HTTP/1.1 200") != NULL);
    assert(strstr(resp, "ok") != NULL);
    printf("/health OK\n");

    n = http_get(host, (uint16_t)port, "/nope", resp, sizeof(resp));
    assert(n > 0);
    assert(strstr(resp, "404") != NULL);

    pqproxy_metrics_http_stop();
    printf("metrics_http test PASSED\n");
    return 0;
}
