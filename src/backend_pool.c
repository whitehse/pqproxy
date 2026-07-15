/**
 * @file backend_pool.c
 * @brief Identity-grouped PostgreSQL backend connection pool.
 *
 * Blocking warm-up and request/response I/O (SO_RCVTIMEO). Frontend path
 * stays on io_uring; pool operations run on the event-loop thread when a
 * frontend needs a backend round-trip.
 */

#define _GNU_SOURCE
#include "backend_pool.h"
#include "scram_client.h"
#include "metrics_internal.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define PQ_AUTH_OK           0
#define PQ_AUTH_CLEARTEXT    3
#define PQ_AUTH_SASL         10
#define PQ_AUTH_SASL_CONT    11
#define PQ_AUTH_SASL_FINAL   12

#define MAX_BACKEND_GROUPS   16
#define MAX_GROUP_NAME       64

#define BE_SEND_CAP  32768
#define BE_RECV_CAP  16384

struct pqproxy_backend_conn {
    int             fd;
    pqwire_ctx_t   *wire;
    char            login_user[128];
    int             busy;
    int             alive;
    int             slot;
    /* Async pipeline state */
    uint8_t         send_buf[BE_SEND_CAP];
    size_t          send_len;
    size_t          send_off;
    uint8_t         recv_acc[BE_RECV_CAP];
    size_t          recv_acc_len;
    int             skip_parse_bind;
};

struct pqproxy_backend_pool {
    pqproxy_backend_config_t cfg;
    char            host[256];
    char            user[128];
    char            password[128];
    char            database[128];
    char            groups[MAX_BACKEND_GROUPS][MAX_GROUP_NAME];
    size_t          n_groups;
    int             use_group_as_user;
    int             lazy_connect;
    size_t          max_conns;
    pqproxy_backend_conn_t *conns;
    size_t          n;
};

void pqproxy_backend_config_defaults(pqproxy_backend_config_t *cfg)
{
    if (!cfg) {
        return;
    }
    memset(cfg, 0, sizeof(*cfg));
    cfg->host = "127.0.0.1";
    cfg->port = 5432;
    cfg->user = "postgres";
    cfg->password = "";
    cfg->database = "postgres";
    cfg->pool_size = 4;
    cfg->connect_timeout_ms = 3000;
    cfg->io_timeout_ms = 5000;
    cfg->use_group_as_user = 0;
    cfg->groups = NULL;
    cfg->lazy_group_connect = 1;
    cfg->auto_reconnect = 1;
    cfg->health_check_on_checkout = 0;
}

static size_t parse_groups(const char *csv, char out[][MAX_GROUP_NAME], size_t maxn)
{
    size_t n = 0;
    const char *p;
    if (!csv || !csv[0]) {
        return 0;
    }
    p = csv;
    while (*p && n < maxn) {
        size_t len = 0;
        while (p[len] && p[len] != ',') {
            len++;
        }
        while (len > 0 && (p[0] == ' ' || p[0] == '\t')) {
            p++;
            len--;
        }
        {
            size_t end = len;
            while (end > 0 && (p[end - 1] == ' ' || p[end - 1] == '\t')) {
                end--;
            }
            if (end > 0 && end < MAX_GROUP_NAME) {
                memcpy(out[n], p, end);
                out[n][end] = '\0';
                n++;
            }
        }
        p += len;
        if (*p == ',') {
            p++;
        }
    }
    return n;
}

static int set_timeouts(int fd, int ms)
{
    struct timeval tv;
    if (ms <= 0) {
        ms = 5000;
    }
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
        return -1;
    }
    return 0;
}

static int tcp_connect(const char *host, uint16_t port, int timeout_ms)
{
    struct addrinfo hints, *res = NULL, *rp;
    char portstr[16];
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        return -1;
    }
    for (rp = res; rp; rp = rp->ai_next) {
        int on = 1;
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }
        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
        (void)set_timeouts(fd, timeout_ms);
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int write_all(int fd, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int read_msg(int fd, uint8_t *buf, size_t cap, size_t *out_len)
{
    /* Typed PG message: type(1) + len(4 BE includes self) */
    uint8_t hdr[5];
    size_t need;
    uint32_t mlen;
    size_t got = 0;

    while (got < 5) {
        ssize_t n = read(fd, hdr + got, 5 - got);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        got += (size_t)n;
    }
    mlen = ((uint32_t)hdr[1] << 24) | ((uint32_t)hdr[2] << 16) |
           ((uint32_t)hdr[3] << 8) | (uint32_t)hdr[4];
    if (mlen < 4 || mlen > 16u * 1024u * 1024u) {
        return -1;
    }
    need = 1u + (size_t)mlen;
    if (need > cap) {
        return -1;
    }
    memcpy(buf, hdr, 5);
    got = 5;
    while (got < need) {
        ssize_t n = read(fd, buf + got, need - got);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        got += (size_t)n;
    }
    *out_len = need;
    return 0;
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xFF);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}

/** SASLInitialResponse: 'p' + mechanism\\0 + int32(data_len) + data */
static int send_sasl_initial(int fd, const char *mech, const char *data)
{
    size_t mlen = strlen(mech) + 1;
    size_t dlen = data ? strlen(data) : 0;
    size_t body = mlen + 4 + dlen;
    uint8_t *msg = malloc(5 + body);
    if (!msg) {
        return -1;
    }
    msg[0] = 'p';
    put_be32(msg + 1, (uint32_t)(4 + body));
    memcpy(msg + 5, mech, mlen);
    put_be32(msg + 5 + mlen, (uint32_t)dlen);
    if (dlen) {
        memcpy(msg + 5 + mlen + 4, data, dlen);
    }
    {
        int rc = write_all(fd, msg, 5 + body);
        free(msg);
        return rc;
    }
}

/** SASLResponse: 'p' + raw client-final bytes */
static int send_sasl_response(int fd, const char *data)
{
    size_t dlen = data ? strlen(data) : 0;
    uint8_t *msg = malloc(5 + dlen);
    if (!msg) {
        return -1;
    }
    msg[0] = 'p';
    put_be32(msg + 1, (uint32_t)(4 + dlen));
    if (dlen) {
        memcpy(msg + 5, data, dlen);
    }
    {
        int rc = write_all(fd, msg, 5 + dlen);
        free(msg);
        return rc;
    }
}

/**
 * Backend auth: trust / cleartext / SCRAM-SHA-256.
 */
static int backend_authenticate(pqproxy_backend_conn_t *c, const char *user,
                                const char *password, const char *database,
                                int quiet)
{
    uint8_t buf[8192];
    size_t n;
    int saw_rfq = 0;
    int rounds = 0;
    pq_scram_t scram;
    int scram_active = 0;
    char gs2[320];
    char bare[288];
    char final_msg[512];

    if (pqwire_send_startup(c->wire, user, database) != 0) {
        return -1;
    }
    n = pqwire_get_output(c->wire, buf, sizeof(buf));
    if (n == 0 || write_all(c->fd, buf, n) != 0) {
        return -1;
    }

    while (!saw_rfq && rounds++ < 64) {
        size_t mlen = 0;
        protocol_event_t ev;
        if (read_msg(c->fd, buf, sizeof(buf), &mlen) != 0) {
            return -1;
        }
        (void)pqwire_feed_input(c->wire, buf, mlen);

        if (mlen >= 9 && buf[0] == 'R') {
            uint32_t atype = ((uint32_t)buf[5] << 24) | ((uint32_t)buf[6] << 16) |
                             ((uint32_t)buf[7] << 8) | (uint32_t)buf[8];
            const char *payload = (const char *)(buf + 9);
            size_t plen = mlen - 9;

            if (atype == PQ_AUTH_OK) {
                /* continue until RFQ */
            } else if (atype == PQ_AUTH_CLEARTEXT) {
                size_t pwlen = password ? strlen(password) + 1 : 1;
                uint8_t pmsg[512];
                if (5 + pwlen > sizeof(pmsg)) {
                    return -1;
                }
                pmsg[0] = 'p';
                put_be32(pmsg + 1, (uint32_t)(4 + pwlen));
                if (password) {
                    memcpy(pmsg + 5, password, pwlen);
                } else {
                    pmsg[5] = 0;
                }
                if (write_all(c->fd, pmsg, 5 + pwlen) != 0) {
                    return -1;
                }
            } else if (atype == PQ_AUTH_SASL) {
                /* mechanisms list; require SCRAM-SHA-256 */
                if (!password) {
                    password = "";
                }
                if (!memmem(payload, plen, "SCRAM-SHA-256", 13)) {
                    if (!quiet) {
                        fprintf(stderr, "pqproxy: backend SASL without SCRAM-SHA-256\n");
                    }
                    return -1;
                }
                if (pq_scram_init(&scram, user) != 0 ||
                    pq_scram_client_first(&scram, gs2, sizeof(gs2), bare, sizeof(bare)) != 0) {
                    return -1;
                }
                if (send_sasl_initial(c->fd, "SCRAM-SHA-256", gs2) != 0) {
                    return -1;
                }
                scram_active = 1;
            } else if (atype == PQ_AUTH_SASL_CONT && scram_active) {
                char server_first[512];
                if (plen >= sizeof(server_first)) {
                    return -1;
                }
                memcpy(server_first, payload, plen);
                server_first[plen] = '\0';
                if (pq_scram_handle_server_first(&scram, server_first, password) != 0) {
                    if (!quiet) {
                        fprintf(stderr, "pqproxy: SCRAM server-first failed\n");
                    }
                    return -1;
                }
                if (pq_scram_client_final(&scram, final_msg, sizeof(final_msg)) != 0 ||
                    send_sasl_response(c->fd, final_msg) != 0) {
                    return -1;
                }
            } else if (atype == PQ_AUTH_SASL_FINAL && scram_active) {
                char server_final[512];
                if (plen >= sizeof(server_final)) {
                    return -1;
                }
                memcpy(server_final, payload, plen);
                server_final[plen] = '\0';
                if (pq_scram_verify_server_final(&scram, server_final) != 0) {
                    if (!quiet) {
                        fprintf(stderr, "pqproxy: SCRAM server signature mismatch\n");
                    }
                    return -1;
                }
            } else if (atype != PQ_AUTH_OK && !quiet) {
                fprintf(stderr, "pqproxy: unsupported auth type %u\n", atype);
            }
        }

        while (pqwire_next_event(c->wire, &ev) == 1) {
            if (ev.type == PQ_EVENT_READY_FOR_QUERY) {
                saw_rfq = 1;
            }
            if (ev.type == PQ_EVENT_ERROR_RESPONSE) {
                if (!quiet) {
                    fprintf(stderr, "pqproxy: backend auth error: %s\n",
                            ev.payload.error.message);
                }
                return -1;
            }
        }
    }
    return saw_rfq ? 0 : -1;
}

static void conn_teardown_io(pqproxy_backend_conn_t *c)
{
    if (!c) {
        return;
    }
    if (c->wire) {
        pqwire_destroy(c->wire);
        c->wire = NULL;
    }
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
    c->alive = 0;
    c->send_len = c->send_off = 0;
    c->recv_acc_len = 0;
}

static int warm_one(pqproxy_backend_pool_t *pool, pqproxy_backend_conn_t *c,
                    const char *login_user)
{
    conn_teardown_io(c);
    c->fd = tcp_connect(pool->host, pool->cfg.port, pool->cfg.connect_timeout_ms);
    if (c->fd < 0) {
        return -1;
    }
    (void)set_timeouts(c->fd, pool->cfg.io_timeout_ms);
    c->wire = pqwire_create(PQWIRE_ROLE_CLIENT);
    if (!c->wire) {
        close(c->fd);
        c->fd = -1;
        return -1;
    }
    strncpy(c->login_user, login_user, sizeof(c->login_user) - 1);
    if (backend_authenticate(c, login_user, pool->password, pool->database,
                             pool->cfg.quiet) != 0) {
        conn_teardown_io(c);
        return -1;
    }
    c->alive = 1;
    c->busy = 0;
    /* Leave blocking for sync tests/flush; async path calls set_nonblock. */
    return 0;
}

void pqproxy_backend_mark_dead(pqproxy_backend_conn_t *conn)
{
    conn_teardown_io(conn);
}

int pqproxy_backend_reconnect(pqproxy_backend_pool_t *pool,
                              pqproxy_backend_conn_t *conn)
{
    char user[128];
    int was_busy;
    if (!pool || !conn) {
        return -1;
    }
    was_busy = conn->busy;
    if (conn->login_user[0]) {
        strncpy(user, conn->login_user, sizeof(user) - 1);
        user[sizeof(user) - 1] = '\0';
    } else {
        strncpy(user, pool->user, sizeof(user) - 1);
        user[sizeof(user) - 1] = '\0';
    }
    if (warm_one(pool, conn, user) != 0) {
        if (!pool->cfg.quiet) {
            fprintf(stderr, "pqproxy: reconnect failed user=%s slot=%d\n",
                    user, conn->slot);
        }
        return -1;
    }
    conn->busy = was_busy;
    if (!pool->cfg.quiet) {
        fprintf(stderr, "pqproxy: reconnected backend user=%s slot=%d\n",
                user, conn->slot);
    }
    return 0;
}

int pqproxy_backend_pool_maintain(pqproxy_backend_pool_t *pool)
{
    size_t i;
    int n = 0;
    if (!pool || !pool->cfg.auto_reconnect) {
        return 0;
    }
    for (i = 0; i < pool->max_conns; i++) {
        pqproxy_backend_conn_t *c = &pool->conns[i];
        if (c->busy) {
            continue;
        }
        if (!c->alive && c->login_user[0]) {
            if (pqproxy_backend_reconnect(pool, c) == 0) {
                n++;
            }
        }
    }
    if (n > 0) {
        pqproxy_metrics_inc_reconnects((unsigned)n);
    }
    pqproxy_metrics_inc_maintain((unsigned)n);
    return n;
}

int pqproxy_backend_health_check(pqproxy_backend_pool_t *pool,
                                 pqproxy_backend_conn_t *conn)
{
    uint8_t out[2048];
    size_t olen = 0;
    uint8_t dump[256];
    if (!pool || !conn || !conn->alive || !conn->wire) {
        return -1;
    }
    /* Temporarily blocking for probe */
    (void)set_timeouts(conn->fd, pool->cfg.io_timeout_ms > 0
                                     ? pool->cfg.io_timeout_ms : 3000);
    while (pqwire_get_output(conn->wire, dump, sizeof(dump)) > 0) {
    }
    if (pqwire_send_query(conn->wire, "SELECT 1") != 0) {
        conn_teardown_io(conn);
        return -1;
    }
    if (pqproxy_backend_flush_pipeline(conn, out, sizeof(out), &olen, 0) != 0) {
        conn_teardown_io(conn);
        return -1;
    }
    {
        int flags = fcntl(conn->fd, F_GETFL, 0);
        if (flags >= 0) {
            (void)fcntl(conn->fd, F_SETFL, flags | O_NONBLOCK);
        }
    }
    return 0;
}

size_t pqproxy_backend_pool_live_count(const pqproxy_backend_pool_t *pool)
{
    size_t i, n = 0;
    if (!pool) {
        return 0;
    }
    for (i = 0; i < pool->max_conns; i++) {
        if (pool->conns[i].alive) {
            n++;
        }
    }
    return n;
}

pqproxy_backend_pool_t *pqproxy_backend_pool_create(const pqproxy_backend_config_t *cfg)
{
    pqproxy_backend_pool_t *pool;
    size_t i, ok = 0;
    const char *user;

    if (!cfg || !cfg->host || !cfg->host[0]) {
        return NULL;
    }
    pool = calloc(1, sizeof(*pool));
    if (!pool) {
        return NULL;
    }
    pool->cfg = *cfg;
    strncpy(pool->host, cfg->host, sizeof(pool->host) - 1);
    user = cfg->user && cfg->user[0] ? cfg->user : "postgres";
    strncpy(pool->user, user, sizeof(pool->user) - 1);
    if (cfg->password) {
        strncpy(pool->password, cfg->password, sizeof(pool->password) - 1);
    }
    strncpy(pool->database,
            cfg->database && cfg->database[0] ? cfg->database : "postgres",
            sizeof(pool->database) - 1);
    pool->use_group_as_user = cfg->use_group_as_user;
    pool->lazy_connect = cfg->lazy_group_connect;
    pool->n_groups = parse_groups(cfg->groups, pool->groups, MAX_BACKEND_GROUPS);

    pool->n = cfg->pool_size ? cfg->pool_size : 4;
    if (pool->use_group_as_user && pool->n_groups > 0) {
        /* At least one connection per group */
        if (pool->n < pool->n_groups) {
            pool->n = pool->n_groups;
        }
    }
    pool->max_conns = pool->n + (pool->lazy_connect ? 16 : 0);
    if (pool->max_conns > 64) {
        pool->max_conns = 64;
    }
    if (pool->n > pool->max_conns) {
        pool->n = pool->max_conns;
    }
    pool->conns = calloc(pool->max_conns, sizeof(pqproxy_backend_conn_t));
    if (!pool->conns) {
        free(pool);
        return NULL;
    }
    for (i = 0; i < pool->max_conns; i++) {
        pool->conns[i].slot = (int)i;
        pool->conns[i].fd = -1;
    }

    if (pool->use_group_as_user && pool->n_groups > 0) {
        size_t per = pool->n / pool->n_groups;
        size_t extra = pool->n % pool->n_groups;
        size_t slot = 0;
        size_t g;
        if (per == 0) {
            per = 1;
        }
        for (g = 0; g < pool->n_groups && slot < pool->n; g++) {
            size_t count = per + (g < extra ? 1 : 0);
            size_t j;
            for (j = 0; j < count && slot < pool->n; j++, slot++) {
                if (warm_one(pool, &pool->conns[slot], pool->groups[g]) == 0) {
                    ok++;
                } else if (!cfg->quiet) {
                    fprintf(stderr,
                            "pqproxy: warm-up failed group=%s slot=%zu\n",
                            pool->groups[g], slot);
                }
            }
        }
    } else {
        for (i = 0; i < pool->n; i++) {
            if (warm_one(pool, &pool->conns[i], pool->user) == 0) {
                ok++;
            } else if (!cfg->quiet) {
                fprintf(stderr, "pqproxy: backend warm-up failed slot=%zu\n", i);
            }
        }
    }
    if (ok == 0) {
        pqproxy_backend_pool_destroy(pool);
        return NULL;
    }
    if (!cfg->quiet) {
        fprintf(stderr,
                "pqproxy: backend pool %s:%u alive=%zu/%zu user=%s db=%s "
                "group_login=%d groups=%zu\n",
                pool->host, (unsigned)pool->cfg.port, ok, pool->n, pool->user,
                pool->database, pool->use_group_as_user, pool->n_groups);
    }
    return pool;
}

void pqproxy_backend_pool_destroy(pqproxy_backend_pool_t *pool)
{
    size_t i;
    if (!pool) {
        return;
    }
    if (pool->conns) {
        for (i = 0; i < pool->max_conns; i++) {
            if (pool->conns[i].wire) {
                pqwire_destroy(pool->conns[i].wire);
            }
            if (pool->conns[i].fd >= 0) {
                close(pool->conns[i].fd);
            }
        }
        free(pool->conns);
    }
    free(pool);
}

int pqproxy_backend_pool_alive(const pqproxy_backend_pool_t *pool)
{
    size_t i;
    if (!pool) {
        return 0;
    }
    for (i = 0; i < pool->max_conns; i++) {
        if (pool->conns[i].alive) {
            return 1;
        }
    }
    return 0;
}

static pqproxy_backend_conn_t *checkout_try(pqproxy_backend_pool_t *pool,
                                            pqproxy_backend_conn_t *c)
{
    if (!c || !c->alive || c->busy) {
        return NULL;
    }
    if (pool->cfg.health_check_on_checkout) {
        c->busy = 1;
        if (pqproxy_backend_health_check(pool, c) != 0) {
            c->busy = 0;
            if (pool->cfg.auto_reconnect &&
                pqproxy_backend_reconnect(pool, c) == 0) {
                c->busy = 1;
                return c;
            }
            return NULL;
        }
        return c;
    }
    c->busy = 1;
    return c;
}

pqproxy_backend_conn_t *pqproxy_backend_checkout(pqproxy_backend_pool_t *pool,
                                                 const char *group)
{
    size_t i;
    pqproxy_backend_conn_t *fallback = NULL;
    if (!pool) {
        return NULL;
    }
    /* Opportunistic re-warm of idle dead slots */
    if (pool->cfg.auto_reconnect) {
        (void)pqproxy_backend_pool_maintain(pool);
    }
    for (i = 0; i < pool->max_conns; i++) {
        pqproxy_backend_conn_t *c = &pool->conns[i];
        if (!c->alive || c->busy) {
            continue;
        }
        if (group && group[0] && strcmp(c->login_user, group) == 0) {
            pqproxy_backend_conn_t *got = checkout_try(pool, c);
            if (got) {
                return got;
            }
            continue;
        }
        if (!pool->use_group_as_user && !fallback) {
            fallback = c;
        }
        if (pool->use_group_as_user && !fallback) {
            fallback = c;
        }
    }
    if (pool->use_group_as_user && group && group[0]) {
        for (i = 0; i < pool->max_conns; i++) {
            pqproxy_backend_conn_t *c = &pool->conns[i];
            if (c->alive && !c->busy && strcmp(c->login_user, group) == 0) {
                pqproxy_backend_conn_t *got = checkout_try(pool, c);
                if (got) {
                    return got;
                }
            }
        }
        if (pool->lazy_connect) {
            for (i = 0; i < pool->max_conns; i++) {
                pqproxy_backend_conn_t *c = &pool->conns[i];
                if (!c->alive) {
                    if (warm_one(pool, c, group) == 0) {
                        c->busy = 1;
                        if (!pool->cfg.quiet) {
                            fprintf(stderr, "pqproxy: lazy backend login as %s\n",
                                    group);
                        }
                        return c;
                    }
                    break;
                }
            }
        }
        return NULL;
    }
    if (fallback) {
        return checkout_try(pool, fallback);
    }
    return NULL;
}

void pqproxy_backend_checkin(pqproxy_backend_pool_t *pool, pqproxy_backend_conn_t *conn)
{
    (void)pool;
    if (conn) {
        conn->busy = 0;
    }
}

pqwire_ctx_t *pqproxy_backend_wire(pqproxy_backend_conn_t *conn)
{
    return conn ? conn->wire : NULL;
}

int pqproxy_backend_flush_pipeline(pqproxy_backend_conn_t *conn,
                                   uint8_t *out, size_t out_cap, size_t *out_len,
                                   int skip_parse_bind_complete)
{
    uint8_t buf[16384];
    size_t n;
    size_t olen = 0;
    int saw_rfq = 0;
    int rounds = 0;

    if (!conn || !conn->alive || !conn->wire || !out || !out_len) {
        return -1;
    }
    *out_len = 0;

    /* Send all queued wire output */
    for (;;) {
        n = pqwire_get_output(conn->wire, buf, sizeof(buf));
        if (n == 0) {
            break;
        }
        if (write_all(conn->fd, buf, n) != 0) {
            conn->alive = 0;
            return -1;
        }
    }

    while (!saw_rfq && rounds++ < 256) {
        size_t mlen = 0;
        if (read_msg(conn->fd, buf, sizeof(buf), &mlen) != 0) {
            conn->alive = 0;
            return -1;
        }
        (void)pqwire_feed_input(conn->wire, buf, mlen);

        /* Drain events (for state) */
        {
            protocol_event_t ev;
            while (pqwire_next_event(conn->wire, &ev) == 1) {
                if (ev.type == PQ_EVENT_READY_FOR_QUERY) {
                    saw_rfq = 1;
                }
                if (ev.type == PQ_EVENT_ERROR_RESPONSE) {
                    /* still forward raw message below */
                }
            }
        }

        if (skip_parse_bind_complete && (buf[0] == '1' || buf[0] == '2')) {
            continue; /* frontend already got local Parse/Bind complete */
        }
        /* Skip noisy backend ParameterStatus / Notice during pipeline */
        if (buf[0] == 'S' || buf[0] == 'N' || buf[0] == 'K') {
            continue;
        }
        if (olen + mlen > out_cap) {
            return -1;
        }
        memcpy(out + olen, buf, mlen);
        olen += mlen;
        if (buf[0] == 'Z') {
            saw_rfq = 1;
        }
    }
    *out_len = olen;
    return saw_rfq ? 0 : -1;
}

int pqproxy_backend_exec_bind(pqproxy_backend_pool_t *pool,
                              const pqproxy_stmt_cache_t *cache,
                              const pq_bind_t *bind,
                              const pqproxy_identity_t *id,
                              uint8_t *out, size_t out_cap, size_t *out_len)
{
    pqproxy_backend_conn_t *be;
    int rc;

    if (!pool || !cache || !bind || !id || !out || !out_len) {
        return -1;
    }
    *out_len = 0;
    be = pqproxy_backend_checkout(pool, id->group);
    if (!be) {
        return -1;
    }
    /* Drain any leftover output; do not pqwire_reset (clears READY auth state). */
    {
        uint8_t dump[1024];
        while (pqwire_get_output(be->wire, dump, sizeof(dump)) > 0) {
        }
    }

    if (pqproxy_on_bind(be->wire, cache, bind, id) != 0) {
        pqproxy_backend_checkin(pool, be);
        return -1;
    }
    rc = pqproxy_backend_flush_pipeline(be, out, out_cap, out_len, 1);
    pqproxy_backend_checkin(pool, be);
    return rc;
}

/* ── Async helpers ───────────────────────────────────────────────────── */

static int be_filter_append(pqproxy_backend_conn_t *conn, const uint8_t *msg,
                            size_t mlen, uint8_t *out, size_t out_cap,
                            size_t *out_len, int *saw_rfq)
{
    char type;
    if (!msg || mlen < 5) {
        return -1;
    }
    type = (char)msg[0];
    (void)pqwire_feed_input(conn->wire, msg, mlen);
    {
        protocol_event_t ev;
        while (pqwire_next_event(conn->wire, &ev) == 1) {
            if (ev.type == PQ_EVENT_READY_FOR_QUERY && saw_rfq) {
                *saw_rfq = 1;
            }
        }
    }
    if (conn->skip_parse_bind && (type == '1' || type == '2')) {
        return 0;
    }
    if (type == 'S' || type == 'N' || type == 'K') {
        return 0;
    }
    if (*out_len + mlen > out_cap) {
        return -1;
    }
    memcpy(out + *out_len, msg, mlen);
    *out_len += mlen;
    if (type == 'Z' && saw_rfq) {
        *saw_rfq = 1;
    }
    return 0;
}

int pqproxy_backend_async_begin(pqproxy_backend_pool_t *pool,
                                const pqproxy_stmt_cache_t *cache,
                                const pq_bind_t *bind,
                                const pqproxy_identity_t *id,
                                pqproxy_backend_conn_t **conn_out)
{
    pqproxy_backend_conn_t *be;
    uint8_t chunk[4096];
    size_t n;

    if (!pool || !cache || !bind || !id || !conn_out) {
        return -1;
    }
    *conn_out = NULL;
    be = pqproxy_backend_checkout(pool, id->group);
    if (!be) {
        return -1;
    }
    {
        uint8_t dump[1024];
        while (pqwire_get_output(be->wire, dump, sizeof(dump)) > 0) {
        }
    }
    be->send_len = be->send_off = 0;
    be->recv_acc_len = 0;
    be->skip_parse_bind = 1;

    if (pqproxy_on_bind(be->wire, cache, bind, id) != 0) {
        pqproxy_backend_checkin(pool, be);
        return -1;
    }
    for (;;) {
        n = pqwire_get_output(be->wire, chunk, sizeof(chunk));
        if (n == 0) {
            break;
        }
        if (be->send_len + n > BE_SEND_CAP) {
            pqproxy_backend_checkin(pool, be);
            return -1;
        }
        memcpy(be->send_buf + be->send_len, chunk, n);
        be->send_len += n;
    }
    if (be->send_len == 0) {
        pqproxy_backend_checkin(pool, be);
        return -1;
    }
    *conn_out = be;
    return 0;
}

size_t pqproxy_backend_async_send_pending(const pqproxy_backend_conn_t *conn)
{
    if (!conn || conn->send_off >= conn->send_len) {
        return 0;
    }
    return conn->send_len - conn->send_off;
}

const uint8_t *pqproxy_backend_async_send_ptr(const pqproxy_backend_conn_t *conn,
                                              size_t *len_out)
{
    if (!conn || !len_out) {
        return NULL;
    }
    if (conn->send_off >= conn->send_len) {
        *len_out = 0;
        return NULL;
    }
    *len_out = conn->send_len - conn->send_off;
    return conn->send_buf + conn->send_off;
}

void pqproxy_backend_async_send_advance(pqproxy_backend_conn_t *conn, size_t n)
{
    if (!conn) {
        return;
    }
    conn->send_off += n;
    if (conn->send_off > conn->send_len) {
        conn->send_off = conn->send_len;
    }
}

int pqproxy_backend_async_on_recv(pqproxy_backend_conn_t *conn,
                                  const uint8_t *data, size_t len,
                                  uint8_t *out, size_t out_cap, size_t *out_len,
                                  int *complete)
{
    size_t off;
    int saw_rfq = 0;

    if (!conn || !data || !out || !out_len || !complete) {
        return -1;
    }
    *complete = 0;
    if (conn->recv_acc_len + len > BE_RECV_CAP) {
        return -1;
    }
    memcpy(conn->recv_acc + conn->recv_acc_len, data, len);
    conn->recv_acc_len += len;

    off = 0;
    while (off + 5 <= conn->recv_acc_len) {
        uint32_t mlen = ((uint32_t)conn->recv_acc[off + 1] << 24) |
                        ((uint32_t)conn->recv_acc[off + 2] << 16) |
                        ((uint32_t)conn->recv_acc[off + 3] << 8) |
                        (uint32_t)conn->recv_acc[off + 4];
        size_t total;
        if (mlen < 4) {
            return -1;
        }
        total = 1u + (size_t)mlen;
        if (off + total > conn->recv_acc_len) {
            break;
        }
        if (be_filter_append(conn, conn->recv_acc + off, total, out, out_cap,
                             out_len, &saw_rfq) != 0) {
            return -1;
        }
        off += total;
        if (saw_rfq) {
            *complete = 1;
            break;
        }
    }
    if (off > 0) {
        memmove(conn->recv_acc, conn->recv_acc + off, conn->recv_acc_len - off);
        conn->recv_acc_len -= off;
    }
    return 0;
}

int pqproxy_backend_fd(const pqproxy_backend_conn_t *conn)
{
    return conn ? conn->fd : -1;
}

int pqproxy_backend_slot(const pqproxy_backend_conn_t *conn)
{
    return conn ? conn->slot : -1;
}

void pqproxy_backend_async_finish(pqproxy_backend_pool_t *pool,
                                  pqproxy_backend_conn_t *conn,
                                  int failed)
{
    if (!conn) {
        return;
    }
    if (failed) {
        char user[128];
        strncpy(user, conn->login_user, sizeof(user) - 1);
        user[sizeof(user) - 1] = '\0';
        conn_teardown_io(conn);
        if (user[0]) {
            strncpy(conn->login_user, user, sizeof(conn->login_user) - 1);
        }
        /* Eager reconnect so next checkout can succeed */
        if (pool && pool->cfg.auto_reconnect && conn->login_user[0]) {
            if (pqproxy_backend_reconnect(pool, conn) == 0) {
                pqproxy_metrics_inc_reconnects(1);
            }
            conn->busy = 0; /* reconnect leaves busy as was; force free */
        }
    }
    conn->send_len = conn->send_off = 0;
    conn->recv_acc_len = 0;
    pqproxy_backend_checkin(pool, conn);
}

int pqproxy_backend_pool_set_nonblock(pqproxy_backend_pool_t *pool)
{
    size_t i;
    if (!pool) {
        return -1;
    }
    for (i = 0; i < pool->max_conns; i++) {
        int flags;
        if (!pool->conns[i].alive || pool->conns[i].fd < 0) {
            continue;
        }
        flags = fcntl(pool->conns[i].fd, F_GETFL, 0);
        if (flags < 0) {
            return -1;
        }
        if (fcntl(pool->conns[i].fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            return -1;
        }
    }
    return 0;
}
