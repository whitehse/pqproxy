/**
 * @file metrics_http.c
 * @brief Minimal Prometheus /metrics HTTP server (dedicated thread).
 */

#define _GNU_SOURCE
#include "metrics_http.h"
#include "pqproxy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile int g_http_run;
static int g_http_fd = -1;
static pthread_t g_http_thr;

int pqproxy_metrics_prometheus_format(char *out, size_t out_len)
{
    pqproxy_metrics_t m;
    uint64_t avg_us = 0;
    int n;

    if (!out || out_len < 64) {
        return -1;
    }
    pqproxy_metrics_get(&m);
    if (m.backend_wait_samples > 0) {
        avg_us = (m.backend_wait_ns_total / m.backend_wait_samples) / 1000ull;
    }

    n = snprintf(out, out_len,
        "# HELP pqproxy_accepts_total Frontend connections accepted\n"
        "# TYPE pqproxy_accepts_total counter\n"
        "pqproxy_accepts_total %llu\n"
        "# HELP pqproxy_frontend_closes_total Frontend connections closed\n"
        "# TYPE pqproxy_frontend_closes_total counter\n"
        "pqproxy_frontend_closes_total %llu\n"
        "# HELP pqproxy_backend_pipelines_ok_total Successful backend pipelines\n"
        "# TYPE pqproxy_backend_pipelines_ok_total counter\n"
        "pqproxy_backend_pipelines_ok_total %llu\n"
        "# HELP pqproxy_backend_pipelines_fail_total Failed backend pipelines\n"
        "# TYPE pqproxy_backend_pipelines_fail_total counter\n"
        "pqproxy_backend_pipelines_fail_total %llu\n"
        "# HELP pqproxy_backend_wait_microseconds_avg Average backend pipeline wait\n"
        "# TYPE pqproxy_backend_wait_microseconds_avg gauge\n"
        "pqproxy_backend_wait_microseconds_avg %llu\n"
        "# HELP pqproxy_backend_wait_microseconds_max Max backend pipeline wait\n"
        "# TYPE pqproxy_backend_wait_microseconds_max gauge\n"
        "pqproxy_backend_wait_microseconds_max %llu\n"
        "# HELP pqproxy_fe_queue_enqueued_total Frontend queue enqueues\n"
        "# TYPE pqproxy_fe_queue_enqueued_total counter\n"
        "pqproxy_fe_queue_enqueued_total %llu\n"
        "# HELP pqproxy_fe_queue_full_total Frontend queue full events\n"
        "# TYPE pqproxy_fe_queue_full_total counter\n"
        "pqproxy_fe_queue_full_total %llu\n"
        "# HELP pqproxy_fe_queue_high_water Max observed frontend queue depth\n"
        "# TYPE pqproxy_fe_queue_high_water gauge\n"
        "pqproxy_fe_queue_high_water %llu\n"
        "# HELP pqproxy_reconnects_total Successful backend reconnects\n"
        "# TYPE pqproxy_reconnects_total counter\n"
        "pqproxy_reconnects_total %llu\n"
        "# HELP pqproxy_maintain_ticks_total Pool maintain ticks\n"
        "# TYPE pqproxy_maintain_ticks_total counter\n"
        "pqproxy_maintain_ticks_total %llu\n"
        "# HELP pqproxy_maintain_rewarmed_total Backends re-warmed by maintain\n"
        "# TYPE pqproxy_maintain_rewarmed_total counter\n"
        "pqproxy_maintain_rewarmed_total %llu\n"
        "# HELP pqproxy_live_backends Live backend connections\n"
        "# TYPE pqproxy_live_backends gauge\n"
        "pqproxy_live_backends %zu\n"
        "# HELP pqproxy_active_frontends Active frontend connections\n"
        "# TYPE pqproxy_active_frontends gauge\n"
        "pqproxy_active_frontends %zu\n",
        (unsigned long long)m.accepts,
        (unsigned long long)m.frontend_closes,
        (unsigned long long)m.backend_pipelines_ok,
        (unsigned long long)m.backend_pipelines_fail,
        (unsigned long long)avg_us,
        (unsigned long long)(m.backend_wait_ns_max / 1000ull),
        (unsigned long long)m.fe_queue_enqueued,
        (unsigned long long)m.fe_queue_full,
        (unsigned long long)m.fe_queue_high_water,
        (unsigned long long)m.reconnects,
        (unsigned long long)m.maintain_ticks,
        (unsigned long long)m.maintain_rewarmed,
        m.live_backends,
        m.active_frontends);
    if (n < 0 || (size_t)n >= out_len) {
        return -1;
    }
    return n;
}

static void *metrics_http_thread(void *arg)
{
    (void)arg;
    while (g_http_run) {
        struct sockaddr_in cli;
        socklen_t clen = sizeof(cli);
        int cfd;
        char req[1024];
        char body[4096];
        char resp[4608];
        ssize_t nr;
        int blen;

        cfd = accept(g_http_fd, (struct sockaddr *)&cli, &clen);
        if (cfd < 0) {
            if (!g_http_run) {
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            usleep(10000);
            continue;
        }
        nr = read(cfd, req, sizeof(req) - 1);
        if (nr <= 0) {
            close(cfd);
            continue;
        }
        req[nr] = '\0';

        if (strncmp(req, "GET /metrics", 12) == 0 ||
            strncmp(req, "GET /metrics ", 13) == 0) {
            blen = pqproxy_metrics_prometheus_format(body, sizeof(body));
            if (blen < 0) {
                const char *err =
                    "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
                (void)write(cfd, err, strlen(err));
            } else {
                int hn = snprintf(resp, sizeof(resp),
                                  "HTTP/1.1 200 OK\r\n"
                                  "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
                                  "Content-Length: %d\r\n"
                                  "Connection: close\r\n"
                                  "\r\n",
                                  blen);
                if (hn > 0 && (size_t)hn + (size_t)blen < sizeof(resp)) {
                    memcpy(resp + hn, body, (size_t)blen);
                    (void)write(cfd, resp, (size_t)hn + (size_t)blen);
                }
            }
        } else if (strncmp(req, "GET /health", 11) == 0 ||
                   strncmp(req, "GET /healthz", 12) == 0) {
            const char *ok =
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                "Content-Length: 3\r\nConnection: close\r\n\r\nok\n";
            (void)write(cfd, ok, strlen(ok));
        } else {
            const char *nf =
                "HTTP/1.1 404 Not Found\r\nContent-Length: 10\r\n"
                "Connection: close\r\n\r\nnot found\n";
            (void)write(cfd, nf, strlen(nf));
        }
        close(cfd);
    }
    return NULL;
}

int pqproxy_metrics_http_start(const char *host, uint16_t port)
{
    struct sockaddr_in addr;
    int on = 1;

    if (port == 0) {
        return 0;
    }
    if (g_http_run) {
        return 0;
    }

    g_http_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (g_http_fd < 0) {
        perror("metrics socket");
        return -1;
    }
    setsockopt(g_http_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (!host || !host[0] || strcmp(host, "0.0.0.0") == 0) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "pqproxy: bad metrics host %s\n", host);
        close(g_http_fd);
        g_http_fd = -1;
        return -1;
    }
    if (bind(g_http_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("metrics bind");
        close(g_http_fd);
        g_http_fd = -1;
        return -1;
    }
    if (listen(g_http_fd, 16) != 0) {
        perror("metrics listen");
        close(g_http_fd);
        g_http_fd = -1;
        return -1;
    }
    g_http_run = 1;
    if (pthread_create(&g_http_thr, NULL, metrics_http_thread, NULL) != 0) {
        g_http_run = 0;
        close(g_http_fd);
        g_http_fd = -1;
        return -1;
    }
    pthread_detach(g_http_thr);
    fprintf(stderr, "pqproxy: metrics HTTP on %s:%u (/metrics)\n",
            host && host[0] ? host : "0.0.0.0", (unsigned)port);
    return 0;
}

void pqproxy_metrics_http_stop(void)
{
    g_http_run = 0;
    if (g_http_fd >= 0) {
        shutdown(g_http_fd, SHUT_RDWR);
        close(g_http_fd);
        g_http_fd = -1;
    }
}
