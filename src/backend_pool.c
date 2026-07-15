/**
 * @file backend_pool.c
 * @brief Identity-grouped PostgreSQL backend connection pool.
 *
 * Blocking warm-up and request/response I/O (SO_RCVTIMEO). Frontend path
 * stays on io_uring; pool operations run on the event-loop thread when a
 * frontend needs a backend round-trip.
 */

#include "backend_pool.h"

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

struct pqproxy_backend_conn {
    int             fd;
    pqwire_ctx_t   *wire;
    char            login_user[128];
    int             busy;
    int             alive;
    int             slot;
};

struct pqproxy_backend_pool {
    pqproxy_backend_config_t cfg;
    char            host[256];
    char            user[128];
    char            password[128];
    char            database[128];
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

/**
 * Minimal backend auth: Startup → wait for AuthOk (R, int32=0) or cleartext
 * request (R, int32=3) with password, then ReadyForQuery.
 * SCRAM full negotiation is deferred; empty password expects trust.
 */
static int backend_authenticate(pqproxy_backend_conn_t *c, const char *user,
                                const char *password, const char *database,
                                int quiet)
{
    uint8_t buf[8192];
    size_t n;
    int saw_auth_ok = 0;
    int saw_rfq = 0;
    int rounds = 0;

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

        /* Cleartext password request: type R, body auth type 3 */
        if (mlen >= 9 && buf[0] == 'R') {
            uint32_t atype = ((uint32_t)buf[5] << 24) | ((uint32_t)buf[6] << 16) |
                             ((uint32_t)buf[7] << 8) | (uint32_t)buf[8];
            if (atype == 3 && password && password[0]) {
                /* PasswordMessage 'p' */
                size_t plen = strlen(password) + 1;
                uint8_t pmsg[512];
                if (5 + plen > sizeof(pmsg)) {
                    return -1;
                }
                pmsg[0] = 'p';
                pmsg[1] = (uint8_t)(((plen + 4) >> 24) & 0xFF);
                pmsg[2] = (uint8_t)(((plen + 4) >> 16) & 0xFF);
                pmsg[3] = (uint8_t)(((plen + 4) >> 8) & 0xFF);
                pmsg[4] = (uint8_t)((plen + 4) & 0xFF);
                memcpy(pmsg + 5, password, plen);
                if (write_all(c->fd, pmsg, 5 + plen) != 0) {
                    return -1;
                }
            } else if (atype == 10 && !quiet) {
                fprintf(stderr,
                        "pqproxy: backend requested SCRAM; use trust or "
                        "cleartext for pool warm-up v1\n");
            }
        }

        while (pqwire_next_event(c->wire, &ev) == 1) {
            if (ev.type == PQ_EVENT_AUTHENTICATION_OK) {
                saw_auth_ok = 1;
            }
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
        (void)saw_auth_ok;
    }
    return saw_rfq ? 0 : -1;
}

static int warm_one(pqproxy_backend_pool_t *pool, pqproxy_backend_conn_t *c,
                    const char *login_user)
{
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
        pqwire_destroy(c->wire);
        c->wire = NULL;
        close(c->fd);
        c->fd = -1;
        return -1;
    }
    c->alive = 1;
    c->busy = 0;
    return 0;
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
    pool->n = cfg->pool_size ? cfg->pool_size : 4;
    if (pool->n > 64) {
        pool->n = 64;
    }
    pool->conns = calloc(pool->n, sizeof(pqproxy_backend_conn_t));
    if (!pool->conns) {
        free(pool);
        return NULL;
    }

    for (i = 0; i < pool->n; i++) {
        pool->conns[i].slot = (int)i;
        /* v1: all conns login as fixed user; group mapping is checkout preference */
        if (warm_one(pool, &pool->conns[i], pool->user) == 0) {
            ok++;
        } else if (!cfg->quiet) {
            fprintf(stderr, "pqproxy: backend warm-up failed slot=%zu\n", i);
        }
    }
    if (ok == 0) {
        pqproxy_backend_pool_destroy(pool);
        return NULL;
    }
    if (!cfg->quiet) {
        fprintf(stderr, "pqproxy: backend pool %s:%u alive=%zu/%zu user=%s db=%s\n",
                pool->host, (unsigned)pool->cfg.port, ok, pool->n, pool->user,
                pool->database);
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
        for (i = 0; i < pool->n; i++) {
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
    for (i = 0; i < pool->n; i++) {
        if (pool->conns[i].alive) {
            return 1;
        }
    }
    return 0;
}

pqproxy_backend_conn_t *pqproxy_backend_checkout(pqproxy_backend_pool_t *pool,
                                                 const char *group)
{
    size_t i;
    pqproxy_backend_conn_t *fallback = NULL;
    if (!pool) {
        return NULL;
    }
    for (i = 0; i < pool->n; i++) {
        pqproxy_backend_conn_t *c = &pool->conns[i];
        if (!c->alive || c->busy) {
            continue;
        }
        if (group && group[0] && strcmp(c->login_user, group) == 0) {
            c->busy = 1;
            return c;
        }
        if (!fallback) {
            fallback = c;
        }
    }
    if (fallback) {
        fallback->busy = 1;
    }
    return fallback;
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
