/**
 * Concurrent frontend load harness against a running pqproxy (plain TCP).
 *
 * Each worker: connect → Startup → AuthOK/RFQ → Parse/Bind/Execute/Sync → Terminate.
 *
 * Usage:
 *   load_harness [--host H] [--port P] [--threads N] [--iters M] [--user U] [--db D]
 *
 * Env defaults: PQPROXY_LOAD_HOST/PORT/THREADS/ITERS (or 127.0.0.1:6432, 8, 20).
 */

#include "pqwire.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    const char *host;
    uint16_t port;
    const char *user;
    const char *db;
    int iters;
    int id;
    int ok;
    int fail;
} worker_arg_t;

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

static int flush_out(int fd, pqwire_ctx_t *ctx)
{
    uint8_t buf[8192];
    size_t n;
    for (;;) {
        n = pqwire_get_output(ctx, buf, sizeof(buf));
        if (n == 0) {
            return 0;
        }
        if (write_all(fd, buf, n) != 0) {
            return -1;
        }
    }
}

/** Read until we see ReadyForQuery 'Z', or Error 'E'. Returns 1 ok, -1 err, 0 timeout-ish. */
static int read_until_ready(int fd, pqwire_ctx_t *ctx)
{
    uint8_t buf[8192];
    int rounds = 0;
    for (;;) {
        protocol_event_t ev;
        while (pqwire_next_event(ctx, &ev) == 1) {
            if (ev.type == PQ_EVENT_READY_FOR_QUERY) {
                return 1;
            }
            if (ev.type == PQ_EVENT_ERROR) {
                return -1;
            }
            if (ev.type == PQ_EVENT_AUTHENTICATION_OK) {
                /* AuthOk is fine; continue for RFQ */
            }
        }
        {
            ssize_t r = read(fd, buf, sizeof(buf));
            if (r < 0 && errno == EINTR) {
                continue;
            }
            if (r <= 0) {
                return -1;
            }
            (void)pqwire_feed_input(ctx, buf, (size_t)r);
        }
        if (++rounds > 200) {
            return -1;
        }
    }
}

/** Drain until we have seen BindComplete or CommandComplete path ends at RFQ. */
static int read_until_pipeline_done(int fd, pqwire_ctx_t *ctx)
{
    return read_until_ready(fd, ctx);
}

static int one_session(const worker_arg_t *wa)
{
    int fd;
    struct sockaddr_in a;
    pqwire_ctx_t *cli;
    int32_t lengths[2];
    const uint8_t *values[2];
    const char *forged = "forged-by-client";
    const char *payload = "load-harness";
    char stmt[32];

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(wa->port);
    if (inet_pton(AF_INET, wa->host, &a.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(fd);
        return -1;
    }

    cli = pqwire_create(PQWIRE_ROLE_CLIENT);
    if (!cli) {
        close(fd);
        return -1;
    }

    if (pqwire_send_startup(cli, wa->user, wa->db) != 0 || flush_out(fd, cli) != 0) {
        pqwire_destroy(cli);
        close(fd);
        return -1;
    }
    if (read_until_ready(fd, cli) != 1) {
        pqwire_destroy(cli);
        close(fd);
        return -1;
    }

    snprintf(stmt, sizeof(stmt), "s%d", wa->id);
    if (pqwire_send_parse(cli, stmt,
                          "INSERT INTO events(router_id, payload) VALUES ($1, $2)",
                          NULL, 0) != 0 ||
        flush_out(fd, cli) != 0) {
        pqwire_destroy(cli);
        close(fd);
        return -1;
    }
    /* ParseComplete only — no RFQ until Sync; drain parse complete */
    {
        uint8_t buf[4096];
        ssize_t r = read(fd, buf, sizeof(buf));
        if (r > 0) {
            (void)pqwire_feed_input(cli, buf, (size_t)r);
        }
    }

    lengths[0] = (int32_t)strlen(forged);
    values[0] = (const uint8_t *)forged;
    lengths[1] = (int32_t)strlen(payload);
    values[1] = (const uint8_t *)payload;

    if (pqwire_send_bind(cli, "", stmt, NULL, 0, lengths, values, 2, NULL, 0) != 0 ||
        pqwire_send_execute(cli, "", 0) != 0 ||
        pqwire_send_sync(cli) != 0 ||
        flush_out(fd, cli) != 0) {
        pqwire_destroy(cli);
        close(fd);
        return -1;
    }
    if (read_until_pipeline_done(fd, cli) != 1) {
        /* Without backend, proxy may still complete with stub CommandComplete+RFQ */
        /* treat partial success leniently only if we got some data — still fail hard */
        pqwire_destroy(cli);
        close(fd);
        return -1;
    }

    (void)pqwire_send_terminate(cli);
    (void)flush_out(fd, cli);
    pqwire_destroy(cli);
    close(fd);
    return 0;
}

static void *worker_main(void *arg)
{
    worker_arg_t *wa = arg;
    int i;
    wa->ok = 0;
    wa->fail = 0;
    for (i = 0; i < wa->iters; i++) {
        if (one_session(wa) == 0) {
            wa->ok++;
        } else {
            wa->fail++;
        }
    }
    return NULL;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [--host H] [--port P] [--threads N] [--iters M] "
            "[--user U] [--db D]\n",
            argv0);
}

int main(int argc, char **argv)
{
    const char *host = getenv("PQPROXY_LOAD_HOST");
    const char *port_s = getenv("PQPROXY_LOAD_PORT");
    const char *thr_s = getenv("PQPROXY_LOAD_THREADS");
    const char *it_s = getenv("PQPROXY_LOAD_ITERS");
    const char *user = "app";
    const char *db = "postgres";
    int nthreads = thr_s ? atoi(thr_s) : 8;
    int iters = it_s ? atoi(it_s) : 20;
    uint16_t port = port_s ? (uint16_t)atoi(port_s) : 6432;
    int i;
    int total_ok = 0, total_fail = 0;
    pthread_t *ths;
    worker_arg_t *args;

    if (!host || !host[0]) {
        host = "127.0.0.1";
    }

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            host = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            nthreads = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc) {
            iters = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--user") == 0 && i + 1 < argc) {
            user = argv[++i];
        } else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    if (nthreads < 1) {
        nthreads = 1;
    }
    if (nthreads > 128) {
        nthreads = 128;
    }
    if (iters < 1) {
        iters = 1;
    }

    ths = calloc((size_t)nthreads, sizeof(*ths));
    args = calloc((size_t)nthreads, sizeof(*args));
    if (!ths || !args) {
        free(ths);
        free(args);
        return 1;
    }

    fprintf(stderr, "load_harness: %s:%u threads=%d iters=%d\n",
            host, (unsigned)port, nthreads, iters);

    for (i = 0; i < nthreads; i++) {
        args[i].host = host;
        args[i].port = port;
        args[i].user = user;
        args[i].db = db;
        args[i].iters = iters;
        args[i].id = i;
        if (pthread_create(&ths[i], NULL, worker_main, &args[i]) != 0) {
            fprintf(stderr, "pthread_create failed\n");
            return 1;
        }
    }
    for (i = 0; i < nthreads; i++) {
        pthread_join(ths[i], NULL);
        total_ok += args[i].ok;
        total_fail += args[i].fail;
    }

    free(ths);
    free(args);

    fprintf(stderr, "load_harness: ok=%d fail=%d\n", total_ok, total_fail);
    if (total_fail > 0 || total_ok == 0) {
        return 1;
    }
    printf("load_harness PASSED ok=%d\n", total_ok);
    return 0;
}
