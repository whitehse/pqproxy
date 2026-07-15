/**
 * @file iouring_loop.c
 * @brief io_uring accept loop: plain RECV/SEND or TLS (SSL_set_fd + POLL) + backend pool.
 */

#include "pqproxy_internal.h"
#include "metrics_internal.h"
#include "metrics_http.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

#include <liburing.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

enum {
    OP_ACCEPT  = 1,
    OP_RECV    = 2, /* frontend plain TCP */
    OP_SEND    = 3, /* frontend plain TCP */
    OP_POLL    = 4, /* frontend TLS readiness */
    OP_BE_SEND = 5, /* backend write (slot = frontend slot) */
    OP_BE_RECV = 6  /* backend read  (slot = frontend slot) */
};

typedef enum {
    CS_FREE = 0,
    CS_TLS_HS,
    CS_ACTIVE,
    CS_CLOSING
} conn_state_t;

typedef enum {
    BE_IDLE = 0,
    BE_SENDING,
    BE_READING,
    BE_WAITING_POOL  /* queued for fair backend checkout */
} be_wait_t;

/* Queued frontend work while a backend pipeline is in flight */
#define FE_Q_MAX 32
typedef enum {
    FEQ_NONE = 0,
    FEQ_PARSE,
    FEQ_BIND,
    FEQ_EXECUTE,
    FEQ_SYNC,
    FEQ_QUERY,
    FEQ_TERMINATE
} feq_kind_t;

typedef struct {
    feq_kind_t kind;
    pq_parse_t parse;
    /* Owned bind params for FEQ_BIND */
    char       bind_stmt[PQWIRE_MAX_STMT_NAME];
    char       bind_portal[PQWIRE_MAX_PORTAL_NAME];
    uint16_t   n_params;
    pqwire_param_t params[PQWIRE_MAX_BIND_PARAMS];
    uint16_t   n_result_formats;
    int16_t    result_formats[PQWIRE_MAX_BIND_PARAMS];
    char       query_sql[PQWIRE_MAX_QUERY_LEN];
} feq_item_t;

typedef struct {
    int             fd;
    conn_state_t    state;
    SSL            *ssl;       /* non-NULL => TLS via SSL_set_fd */
    int             ktls_on;
    pqwire_ctx_t   *frontend;
    pqproxy_identity_t id;
    pqproxy_stmt_cache_t cache;
    int             identity_ready;

    uint8_t         recv_buf[PQPROXY_IO_BUF];
    uint8_t         plain_buf[PQPROXY_IO_BUF];
    uint8_t         send_buf[PQPROXY_IO_BUF];
    size_t          send_len;
    size_t          send_off;
    int             send_pending;
    int             recv_pending;
    int             poll_pending;
    int             want_poll_out;

    /* Async backend pipeline */
    pqproxy_backend_conn_t *be;
    be_wait_t       be_wait;
    int             be_send_pending;
    int             be_recv_pending;
    int             got_execute;
    int             got_sync;
    uint64_t        be_start_ns; /* mono ns when pipeline started */
    uint8_t         be_resp[PQPROXY_IO_BUF];
    size_t          be_resp_len;
    uint8_t         be_recv_buf[PQPROXY_IO_BUF];

    /* Request queue (during BE_SENDING/READING) */
    feq_item_t      fe_q[FE_Q_MAX];
    size_t          fe_q_head;
    size_t          fe_q_tail;
    size_t          fe_q_count;
    int             draining_queue; /* re-entrancy guard */

    int             slot;
} conn_t;

typedef struct {
    const pqproxy_config_t *cfg;
    SSL_CTX                *tls_ctx;
    pqproxy_backend_pool_t *pool;
    int                     async_backend; /* 1 = io_uring backend path */
    int                     fair_schedule; /* RR waiters when pool busy */
    struct io_uring         ring;
    int                     listen_fd;
    conn_t                  conns[PQPROXY_MAX_CONNS];
    struct sockaddr_storage client_addr;
    socklen_t               client_addr_len;
    volatile sig_atomic_t   stop;
    uint64_t                last_maintain_ms;
    uint64_t                last_metrics_ms;
    /* Fair pool wait ring: frontend slots waiting for a free backend */
    int                     waiters[PQPROXY_MAX_CONNS];
    size_t                  wait_head;
    size_t                  wait_tail;
    size_t                  wait_count;
} server_t;

static uint64_t mono_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static uint64_t mono_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static size_t count_active_frontends(const server_t *srv)
{
    int i;
    size_t n = 0;
    for (i = 0; i < PQPROXY_MAX_CONNS; i++) {
        if (srv->conns[i].state != CS_FREE) {
            n++;
        }
    }
    return n;
}

static void server_tick(server_t *srv)
{
    uint64_t now = mono_ms();
    int interval = srv->cfg->maintain_interval_ms;
    int mlog = srv->cfg->metrics_log_interval_ms;

    if (srv->pool && interval > 0 &&
        (now - srv->last_maintain_ms) >= (uint64_t)interval) {
        int n = pqproxy_backend_pool_maintain(srv->pool);
        srv->last_maintain_ms = now;
        if (n > 0 && !srv->cfg->quiet) {
            fprintf(stderr, "pqproxy: maintain rewarmed %d backend(s)\n", n);
        }
    }
    if (mlog > 0 && (now - srv->last_metrics_ms) >= (uint64_t)mlog) {
        pqproxy_metrics_t m;
        char line[640];
        size_t live = srv->pool ? pqproxy_backend_pool_live_count(srv->pool) : 0;
        pqproxy_metrics_set_gauges(live, count_active_frontends(srv));
        pqproxy_metrics_get(&m);
        pqproxy_metrics_format(&m, line, sizeof(line));
        fprintf(stderr, "%s\n", line);
        srv->last_metrics_ms = now;
    }
}

static server_t *g_server;

static void feq_clear_all(conn_t *c);
static int drain_fe_queue(server_t *srv, conn_t *c);
static int queue_plain_send(server_t *srv, conn_t *c, const uint8_t *data, size_t len);
static int waiters_push(server_t *srv, conn_t *c);
static void waiters_remove(server_t *srv, int slot);
static int fair_schedule_waiters(server_t *srv);
static int park_for_backend(server_t *srv, conn_t *c);
static int after_backend_release(server_t *srv, conn_t *c);

static void on_signal(int sig)
{
    (void)sig;
    if (g_server) {
        g_server->stop = 1;
    }
}

static uint64_t pack_ud(int op, int slot)
{
    return ((uint64_t)(uint32_t)op << 32) | (uint32_t)slot;
}

static void unpack_ud(uint64_t ud, int *op, int *slot)
{
    *op = (int)(ud >> 32);
    *slot = (int)(ud & 0xFFFFFFFFu);
}

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int create_listen_socket(const pqproxy_config_t *cfg)
{
    int fd;
    int on = 1;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
        perror("setsockopt REUSEADDR");
        close(fd);
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cfg->listen_port);
    if (!cfg->listen_host || strcmp(cfg->listen_host, "0.0.0.0") == 0) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (inet_pton(AF_INET, cfg->listen_host, &addr.sin_addr) != 1) {
        fprintf(stderr, "pqproxy: invalid listen host %s\n", cfg->listen_host);
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    if (listen(fd, 128) != 0) {
        perror("listen");
        close(fd);
        return -1;
    }
    if (set_nonblock(fd) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static conn_t *alloc_conn(server_t *srv)
{
    int i;
    for (i = 0; i < PQPROXY_MAX_CONNS; i++) {
        if (srv->conns[i].state == CS_FREE) {
            conn_t *c = &srv->conns[i];
            memset(c, 0, sizeof(*c));
            c->slot = i;
            c->fd = -1;
            pqproxy_identity_clear(&c->id);
            pqproxy_stmt_cache_init(&c->cache);
            return c;
        }
    }
    return NULL;
}

static void close_conn(server_t *srv, conn_t *c)
{
    if (!c || c->state == CS_FREE) {
        return;
    }
    waiters_remove(srv, c->slot);
    if (c->be && srv->pool) {
        pqproxy_backend_async_finish(srv->pool, c->be, 1);
        c->be = NULL;
        /* Free backend may unblock another frontend */
        (void)fair_schedule_waiters(srv);
    }
    if (c->ssl) {
        SSL_free(c->ssl);
        c->ssl = NULL;
    }
    if (c->frontend) {
        pqwire_destroy(c->frontend);
        c->frontend = NULL;
    }
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
    c->state = CS_FREE;
    c->send_pending = c->recv_pending = c->poll_pending = 0;
    c->be_send_pending = c->be_recv_pending = 0;
    c->be_wait = BE_IDLE;
    c->be_start_ns = 0;
    feq_clear_all(c);
    pqproxy_metrics_inc_closes();
}

static int submit_recv(server_t *srv, conn_t *c)
{
    struct io_uring_sqe *sqe;
    if (c->ssl || c->recv_pending || c->state == CS_CLOSING || c->state == CS_FREE) {
        return 0;
    }
    sqe = io_uring_get_sqe(&srv->ring);
    if (!sqe) {
        return -1;
    }
    io_uring_prep_recv(sqe, c->fd, c->recv_buf, sizeof(c->recv_buf), 0);
    io_uring_sqe_set_data64(sqe, pack_ud(OP_RECV, c->slot));
    c->recv_pending = 1;
    return 0;
}

static int submit_send(server_t *srv, conn_t *c)
{
    struct io_uring_sqe *sqe;
    size_t n;
    if (c->ssl || c->send_pending || c->send_off >= c->send_len) {
        return 0;
    }
    n = c->send_len - c->send_off;
    sqe = io_uring_get_sqe(&srv->ring);
    if (!sqe) {
        return -1;
    }
    io_uring_prep_send(sqe, c->fd, c->send_buf + c->send_off, n, 0);
    io_uring_sqe_set_data64(sqe, pack_ud(OP_SEND, c->slot));
    c->send_pending = 1;
    return 0;
}

static int submit_poll(server_t *srv, conn_t *c)
{
    struct io_uring_sqe *sqe;
    short events;
    if (!c->ssl || c->poll_pending || c->state == CS_FREE) {
        return 0;
    }
    events = POLLIN;
    if (c->want_poll_out || c->send_len > c->send_off) {
        events = (short)(events | POLLOUT);
    }
    sqe = io_uring_get_sqe(&srv->ring);
    if (!sqe) {
        return -1;
    }
    io_uring_prep_poll_add(sqe, c->fd, events);
    io_uring_sqe_set_data64(sqe, pack_ud(OP_POLL, c->slot));
    c->poll_pending = 1;
    return 0;
}

static int queue_plain_send(server_t *srv, conn_t *c, const uint8_t *data, size_t len)
{
    if (len == 0) {
        return 0;
    }
    if (c->ssl) {
        /* Buffer plaintext; drained via SSL_write on POLLOUT */
        if (c->send_len + len > sizeof(c->send_buf)) {
            if (c->send_off == c->send_len) {
                c->send_off = c->send_len = 0;
            }
            if (c->send_len + len > sizeof(c->send_buf)) {
                return -1;
            }
        }
        memcpy(c->send_buf + c->send_len, data, len);
        c->send_len += len;
        c->want_poll_out = 1;
        return submit_poll(srv, c);
    }
    if (c->send_len + len > sizeof(c->send_buf)) {
        if (c->send_off == c->send_len) {
            c->send_off = c->send_len = 0;
        }
        if (c->send_len + len > sizeof(c->send_buf)) {
            return -1;
        }
    }
    memcpy(c->send_buf + c->send_len, data, len);
    c->send_len += len;
    return submit_send(srv, c);
}



static void feq_clear_item(feq_item_t *it)
{
    uint16_t i;
    if (!it) {
        return;
    }
    for (i = 0; i < it->n_params; i++) {
        pqwire_param_clear(&it->params[i]);
    }
    memset(it, 0, sizeof(*it));
}

static void feq_clear_all(conn_t *c)
{
    size_t i;
    for (i = 0; i < FE_Q_MAX; i++) {
        feq_clear_item(&c->fe_q[i]);
    }
    c->fe_q_head = c->fe_q_tail = c->fe_q_count = 0;
}

static int feq_push(conn_t *c, const feq_item_t *item)
{
    if (!c || !item || c->fe_q_count >= FE_Q_MAX) {
        pqproxy_metrics_inc_fe_q_full();
        return -1;
    }
    c->fe_q[c->fe_q_tail] = *item; /* params ownership transferred */
    c->fe_q_tail = (c->fe_q_tail + 1) % FE_Q_MAX;
    c->fe_q_count++;
    pqproxy_metrics_inc_fe_q_enq();
    pqproxy_metrics_note_fe_q_depth(c->fe_q_count);
    return 0;
}

static int feq_pop(conn_t *c, feq_item_t *out)
{
    if (!c || !out || c->fe_q_count == 0) {
        return 0;
    }
    *out = c->fe_q[c->fe_q_head];
    memset(&c->fe_q[c->fe_q_head], 0, sizeof(c->fe_q[0]));
    c->fe_q_head = (c->fe_q_head + 1) % FE_Q_MAX;
    c->fe_q_count--;
    return 1;
}

static int feq_push_parse(conn_t *c, const pq_parse_t *parse)
{
    feq_item_t it;
    memset(&it, 0, sizeof(it));
    it.kind = FEQ_PARSE;
    it.parse = *parse;
    return feq_push(c, &it);
}

static int feq_push_bind(conn_t *c, const pq_bind_t *bind)
{
    feq_item_t it;
    uint16_t i;
    memset(&it, 0, sizeof(it));
    it.kind = FEQ_BIND;
    strncpy(it.bind_stmt, bind->statement, sizeof(it.bind_stmt) - 1);
    strncpy(it.bind_portal, bind->portal, sizeof(it.bind_portal) - 1);
    it.n_params = bind->n_params;
    if (it.n_params > PQWIRE_MAX_BIND_PARAMS) {
        it.n_params = PQWIRE_MAX_BIND_PARAMS;
    }
    for (i = 0; i < it.n_params; i++) {
        const pq_bind_param_view_t *v = &bind->params[i];
        it.params[i].format = v->format;
        if (v->length < 0) {
            pqwire_param_set_null(&it.params[i]);
        } else if (v->format == 1) {
            if (pqwire_param_set_binary(&it.params[i], v->data, (size_t)v->length) != 0) {
                feq_clear_item(&it);
                return -1;
            }
        } else {
            char *tmp = malloc((size_t)v->length + 1);
            if (!tmp) {
                feq_clear_item(&it);
                return -1;
            }
            memcpy(tmp, v->data, (size_t)v->length);
            tmp[v->length] = '\0';
            if (pqwire_param_set_text(&it.params[i], tmp) != 0) {
                free(tmp);
                feq_clear_item(&it);
                return -1;
            }
            free(tmp);
        }
    }
    it.n_result_formats = bind->n_result_formats;
    if (it.n_result_formats > PQWIRE_MAX_BIND_PARAMS) {
        it.n_result_formats = PQWIRE_MAX_BIND_PARAMS;
    }
    for (i = 0; i < it.n_result_formats; i++) {
        it.result_formats[i] = bind->result_formats[i];
    }
    return feq_push(c, &it);
}


static int drain_frontend_out(server_t *srv, conn_t *c)
{
    uint8_t out[PQPROXY_IO_BUF];
    size_t n;
    for (;;) {
        n = pqwire_get_output(c->frontend, out, sizeof(out));
        if (n == 0) {
            break;
        }
        if (queue_plain_send(srv, c, out, n) != 0) {
            return -1;
        }
    }
    return 0;
}

static int waiters_push(server_t *srv, conn_t *c)
{
    size_t i;
    if (!srv || !c || !srv->fair_schedule) {
        return -1;
    }
    /* already waiting? */
    for (i = 0; i < srv->wait_count; i++) {
        size_t idx = (srv->wait_head + i) % PQPROXY_MAX_CONNS;
        if (srv->waiters[idx] == c->slot) {
            return 0;
        }
    }
    if (srv->wait_count >= PQPROXY_MAX_CONNS) {
        return -1;
    }
    srv->waiters[srv->wait_tail] = c->slot;
    srv->wait_tail = (srv->wait_tail + 1) % PQPROXY_MAX_CONNS;
    srv->wait_count++;
    pqproxy_metrics_inc_fair_waits();
    pqproxy_metrics_set_pool_waiters(srv->wait_count);
    return 0;
}

static void waiters_remove(server_t *srv, int slot)
{
    size_t i, n;
    size_t new_head, new_count;
    int tmp[PQPROXY_MAX_CONNS];
    if (!srv || srv->wait_count == 0) {
        return;
    }
    n = 0;
    for (i = 0; i < srv->wait_count; i++) {
        size_t idx = (srv->wait_head + i) % PQPROXY_MAX_CONNS;
        if (srv->waiters[idx] != slot) {
            tmp[n++] = srv->waiters[idx];
        }
    }
    if (n == srv->wait_count) {
        return;
    }
    new_head = 0;
    new_count = n;
    for (i = 0; i < n; i++) {
        srv->waiters[i] = tmp[i];
    }
    srv->wait_head = new_head;
    srv->wait_tail = new_count % PQPROXY_MAX_CONNS;
    srv->wait_count = new_count;
    pqproxy_metrics_set_pool_waiters(srv->wait_count);
}

/** Park frontend until a backend becomes available (fair RR). */
static int park_for_backend(server_t *srv, conn_t *c)
{
    c->be_wait = BE_WAITING_POOL;
    if (waiters_push(srv, c) != 0) {
        c->be_wait = BE_IDLE;
        return -1;
    }
    return 0;
}

static int fair_schedule_waiters(server_t *srv)
{
    size_t attempts;
    int started = 0;
    if (!srv || !srv->fair_schedule || !srv->pool || !srv->async_backend) {
        return 0;
    }
    attempts = srv->wait_count;
    while (attempts-- > 0 && srv->wait_count > 0) {
        int slot = srv->waiters[srv->wait_head];
        conn_t *wc;
        srv->wait_head = (srv->wait_head + 1) % PQPROXY_MAX_CONNS;
        srv->wait_count--;
        pqproxy_metrics_set_pool_waiters(srv->wait_count);

        if (slot < 0 || slot >= PQPROXY_MAX_CONNS) {
            continue;
        }
        wc = &srv->conns[slot];
        if (wc->state == CS_FREE || wc->be_wait != BE_WAITING_POOL) {
            continue;
        }
        /* Try to start next queued work (typically FEQ_BIND). */
        if (wc->fe_q_count == 0) {
            wc->be_wait = BE_IDLE;
            continue;
        }
        wc->be_wait = BE_IDLE;
        if (drain_fe_queue(srv, wc) != 0) {
            continue;
        }
        if (wc->be_wait == BE_SENDING || wc->be_wait == BE_READING) {
            pqproxy_metrics_inc_fair_schedules();
            started++;
            /* One grant per free backend release; pool may have more free. */
            continue;
        }
        if (wc->be_wait == BE_IDLE && wc->fe_q_count > 0) {
            /* Still needs a backend — re-queue at tail */
            (void)park_for_backend(srv, wc);
        }
    }
    return started;
}

/**
 * After releasing a backend: prefer other waiters (fairness), then drain self.
 */
static int after_backend_release(server_t *srv, conn_t *c)
{
    c->be_wait = BE_IDLE;
    c->got_execute = c->got_sync = 0;
    if (srv->fair_schedule && srv->wait_count > 0) {
        (void)fair_schedule_waiters(srv);
    }
    if (c->be_wait == BE_IDLE && c->fe_q_count > 0) {
        return drain_fe_queue(srv, c);
    }
    return drain_frontend_out(srv, c);
}

static int submit_be_send(server_t *srv, conn_t *c);
static int submit_be_recv(server_t *srv, conn_t *c);

/**
 * Backend pipeline finished (RFQ). On ErrorResponse: skip local BindComplete,
 * deliver Error+RFQ to FE, drop queued FE work for this pipeline, count fail.
 */
static int backend_async_complete(server_t *srv, conn_t *c)
{
    const pqwire_pipeline_status_t *st;
    int had_error = 0;

    if (c->be_start_ns) {
        pqproxy_metrics_note_backend_wait_ns(mono_ns() - c->be_start_ns);
        c->be_start_ns = 0;
    }

    st = c->be ? pqproxy_backend_pipeline_status(c->be) : NULL;
    if (st && st->saw_error) {
        had_error = 1;
        pqproxy_metrics_inc_be_fail();
        /* Mid-pipeline failure: discard queued FE work for this transaction. */
        feq_clear_all(c);
        c->got_execute = 0;
    } else {
        pqproxy_metrics_inc_be_ok();
    }

    if (!had_error) {
        if (pqwire_send_bind_complete(c->frontend) != 0) {
            return -1;
        }
    }
    /* Error path: be_resp already contains ErrorResponse (+ usually RFQ).
     * Success path: CommandComplete/DataRow/... (+ RFQ when Sync was sent). */
    if (c->got_sync && c->be_resp_len > 0) {
        if (queue_plain_send(srv, c, c->be_resp, c->be_resp_len) != 0) {
            return -1;
        }
        c->be_resp_len = 0;
    } else if (had_error && c->be_resp_len > 0) {
        /* Client has not Synced yet — still push Error+RFQ so FE is clean. */
        if (queue_plain_send(srv, c, c->be_resp, c->be_resp_len) != 0) {
            return -1;
        }
        c->be_resp_len = 0;
        c->got_sync = 0;
    } else if (c->got_sync && c->be_resp_len == 0) {
        if (pqwire_send_ready_for_query(c->frontend) != 0) {
            return -1;
        }
    }
    if (drain_frontend_out(srv, c) != 0) {
        return -1;
    }
    if (c->be) {
        /* Backend wire already marked READY via pipeline feed helpers. */
        pqproxy_backend_async_finish(srv->pool, c->be, 0);
        c->be = NULL;
    }
    return after_backend_release(srv, c);
}

static int backend_async_fail(server_t *srv, conn_t *c)
{
    if (c->be_start_ns) {
        pqproxy_metrics_note_backend_wait_ns(mono_ns() - c->be_start_ns);
        c->be_start_ns = 0;
    }
    pqproxy_metrics_inc_be_fail();
    if (c->be) {
        pqproxy_backend_async_finish(srv->pool, c->be, 1);
        c->be = NULL;
    }
    c->be_resp_len = 0;
    (void)pqwire_send_error_response(c->frontend, "ERROR", "08006",
                                     "backend pipeline failed");
    (void)pqwire_send_ready_for_query(c->frontend);
    if (drain_frontend_out(srv, c) != 0) {
        return -1;
    }
    return after_backend_release(srv, c);
}

static int submit_be_send(server_t *srv, conn_t *c)
{
    struct io_uring_sqe *sqe;
    const uint8_t *ptr;
    size_t n;
    int bfd;

    if (!c->be || c->be_send_pending) {
        return 0;
    }
    ptr = pqproxy_backend_async_send_ptr(c->be, &n);
    if (!ptr || n == 0) {
        c->be_wait = BE_READING;
        return submit_be_recv(srv, c);
    }
    bfd = pqproxy_backend_fd(c->be);
    sqe = io_uring_get_sqe(&srv->ring);
    if (!sqe) {
        return -1;
    }
    io_uring_prep_send(sqe, bfd, ptr, n, 0);
    io_uring_sqe_set_data64(sqe, pack_ud(OP_BE_SEND, c->slot));
    c->be_send_pending = 1;
    c->be_wait = BE_SENDING;
    return 0;
}

static int submit_be_recv(server_t *srv, conn_t *c)
{
    struct io_uring_sqe *sqe;
    int bfd;
    if (!c->be || c->be_recv_pending) {
        return 0;
    }
    bfd = pqproxy_backend_fd(c->be);
    sqe = io_uring_get_sqe(&srv->ring);
    if (!sqe) {
        return -1;
    }
    io_uring_prep_recv(sqe, bfd, c->be_recv_buf, sizeof(c->be_recv_buf), 0);
    io_uring_sqe_set_data64(sqe, pack_ud(OP_BE_RECV, c->slot));
    c->be_recv_pending = 1;
    c->be_wait = BE_READING;
    return 0;
}

static int on_be_send_cqe(server_t *srv, conn_t *c, int res)
{
    c->be_send_pending = 0;
    if (res < 0) {
        if (res == -EAGAIN || res == -EWOULDBLOCK) {
            return submit_be_send(srv, c);
        }
        return backend_async_fail(srv, c);
    }
    pqproxy_backend_async_send_advance(c->be, (size_t)res);
    return submit_be_send(srv, c);
}

static int on_be_recv_cqe(server_t *srv, conn_t *c, int res)
{
    int complete = 0;
    c->be_recv_pending = 0;
    if (res <= 0) {
        return backend_async_fail(srv, c);
    }
    if (pqproxy_backend_async_on_recv(c->be, c->be_recv_buf, (size_t)res,
                                      c->be_resp, sizeof(c->be_resp),
                                      &c->be_resp_len, &complete) != 0) {
        return backend_async_fail(srv, c);
    }
    if (complete) {
        return backend_async_complete(srv, c);
    }
    return submit_be_recv(srv, c);
}


static int start_async_bind_from_event(server_t *srv, conn_t *c, const pq_bind_t *bind)
{
    pqproxy_backend_conn_t *be = NULL;
    if (pqproxy_backend_async_begin(srv->pool, &c->cache, bind, &c->id, &be) != 0) {
        return -1;
    }
    c->be = be;
    c->be_resp_len = 0;
    c->be_start_ns = mono_ns();
    if (submit_be_send(srv, c) != 0) {
        return backend_async_fail(srv, c);
    }
    return 0;
}

static int start_async_bind_from_queue(server_t *srv, conn_t *c, feq_item_t *it)
{
    /* Reconstruct pq_bind_t views into on_bind via temporary wire path:
     * use pqproxy_on_bind-compatible path by building a synthetic bind view. */
    pq_bind_t bind;
    pq_bind_param_view_t views[PQWIRE_MAX_BIND_PARAMS];
    uint16_t i;
    pqproxy_backend_conn_t *be = NULL;
    int16_t formats[PQWIRE_MAX_BIND_PARAMS];
    int32_t lengths[PQWIRE_MAX_BIND_PARAMS];
    const uint8_t *values[PQWIRE_MAX_BIND_PARAMS];
    const pqwire_prepared_stmt_t *prep;

    memset(&bind, 0, sizeof(bind));
    strncpy(bind.statement, it->bind_stmt, sizeof(bind.statement) - 1);
    strncpy(bind.portal, it->bind_portal, sizeof(bind.portal) - 1);
    bind.n_params = it->n_params;
    for (i = 0; i < it->n_params; i++) {
        views[i].length = it->params[i].length;
        views[i].data = it->params[i].data;
        views[i].format = it->params[i].format;
        bind.params[i] = views[i];
        formats[i] = it->params[i].format;
        lengths[i] = it->params[i].length;
        values[i] = it->params[i].data;
    }
    bind.n_formats = it->n_params;
    for (i = 0; i < it->n_params; i++) {
        bind.formats[i] = formats[i];
    }
    bind.n_result_formats = it->n_result_formats;
    for (i = 0; i < it->n_result_formats; i++) {
        bind.result_formats[i] = it->result_formats[i];
    }

    prep = pqproxy_stmt_cache_get(&c->cache, bind.statement);
    if (!prep) {
        return -1;
    }
    /* Prefer async_begin which calls on_bind */
    if (pqproxy_backend_async_begin(srv->pool, &c->cache, &bind, &c->id, &be) != 0) {
        return -1;
    }
    c->be = be;
    c->be_resp_len = 0;
    c->got_execute = c->got_sync = 0;
    c->be_start_ns = mono_ns();
    (void)lengths;
    (void)values;
    if (submit_be_send(srv, c) != 0) {
        return backend_async_fail(srv, c);
    }
    return 0;
}

static int drain_fe_queue(server_t *srv, conn_t *c)
{
    feq_item_t it;
    if (c->draining_queue) {
        return 0;
    }
    c->draining_queue = 1;
    while (c->be_wait == BE_IDLE && feq_pop(c, &it) == 1) {
        int rc = 0;
        switch (it.kind) {
        case FEQ_PARSE:
            rc = pqproxy_on_parse(c->frontend, &c->cache, &it.parse,
                                  c->id.identity_slot >= 0
                                      ? c->id.identity_slot
                                      : srv->cfg->identity_slot);
            if (rc != 0) {
                (void)pqwire_send_error_response(c->frontend, "ERROR", "26000",
                                                 "prepared statement cache full");
                (void)pqwire_send_ready_for_query(c->frontend);
            }
            break;
        case FEQ_BIND:
            if (srv->pool && c->identity_ready && srv->async_backend) {
                if (start_async_bind_from_queue(srv, c, &it) == 0) {
                    feq_clear_item(&it);
                    c->draining_queue = 0;
                    return drain_frontend_out(srv, c);
                }
                /* Pool busy: re-queue bind at head and park for fair RR. */
                if (srv->fair_schedule) {
                    /* Push back to front of queue */
                    if (c->fe_q_count < FE_Q_MAX) {
                        c->fe_q_head = (c->fe_q_head + FE_Q_MAX - 1) % FE_Q_MAX;
                        c->fe_q[c->fe_q_head] = it;
                        c->fe_q_count++;
                        memset(&it, 0, sizeof(it)); /* ownership kept in queue */
                        (void)park_for_backend(srv, c);
                        c->draining_queue = 0;
                        return drain_frontend_out(srv, c);
                    }
                }
            }
            if (srv->pool && c->identity_ready) {
                /* Blocking fallback via reconstructed bind */
                pq_bind_t bind;
                uint16_t i;
                size_t rlen = 0;
                memset(&bind, 0, sizeof(bind));
                strncpy(bind.statement, it.bind_stmt, sizeof(bind.statement) - 1);
                bind.n_params = it.n_params;
                for (i = 0; i < it.n_params; i++) {
                    bind.params[i].length = it.params[i].length;
                    bind.params[i].data = it.params[i].data;
                    bind.params[i].format = it.params[i].format;
                    bind.formats[i] = it.params[i].format;
                }
                bind.n_formats = it.n_params;
                bind.n_result_formats = it.n_result_formats;
                for (i = 0; i < it.n_result_formats; i++) {
                    bind.result_formats[i] = it.result_formats[i];
                }
                if (pqproxy_backend_exec_bind(srv->pool, &c->cache, &bind, &c->id,
                                              c->be_resp, sizeof(c->be_resp),
                                              &rlen) == 0) {
                    c->be_resp_len = rlen;
                    (void)pqwire_send_bind_complete(c->frontend);
                } else {
                    (void)pqwire_send_bind_complete(c->frontend);
                }
            } else {
                (void)pqwire_send_bind_complete(c->frontend);
            }
            break;
        case FEQ_EXECUTE:
            if (!srv->pool || c->be_resp_len == 0) {
                (void)pqwire_send_command_complete(c->frontend, "SELECT 0");
            }
            break;
        case FEQ_SYNC:
            if (c->be_resp_len > 0) {
                (void)queue_plain_send(srv, c, c->be_resp, c->be_resp_len);
                c->be_resp_len = 0;
            } else {
                (void)pqwire_send_ready_for_query(c->frontend);
            }
            break;
        case FEQ_QUERY:
            if (srv->cfg->reject_simple_query || !srv->pool || !c->identity_ready) {
                (void)pqproxy_on_simple_query(c->frontend,
                                              srv->cfg->reject_simple_query,
                                              it.query_sql);
            } else {
                size_t rlen = 0;
                pqwire_pipeline_status_t st;
                if (pqproxy_backend_exec_query(srv->pool, c->id.group, it.query_sql,
                                               c->be_resp, sizeof(c->be_resp),
                                               &rlen, &st) == 0 && rlen > 0) {
                    (void)queue_plain_send(srv, c, c->be_resp, rlen);
                } else {
                    (void)pqwire_send_error_response(
                        c->frontend, "ERROR", "08006",
                        "simple Query backend forward failed");
                    (void)pqwire_send_ready_for_query(c->frontend);
                }
            }
            break;
        case FEQ_TERMINATE:
            c->state = CS_CLOSING;
            break;
        default:
            break;
        }
        feq_clear_item(&it);
        if (c->be_wait != BE_IDLE) {
            break;
        }
    }
    c->draining_queue = 0;
    return drain_frontend_out(srv, c);
}

static int process_frontend(server_t *srv, conn_t *c)
{
    protocol_event_t ev;

    while (pqwire_next_event(c->frontend, &ev) == 1) {
        switch (ev.type) {
        case PQ_EVENT_STARTUP:
            if (!srv->cfg->quiet) {
                fprintf(stderr, "pqproxy: startup user=%s db=%s id=%s group=%s\n",
                        ev.payload.startup.user ? ev.payload.startup.user : "?",
                        ev.payload.startup.database ? ev.payload.startup.database : "?",
                        c->id.router_id[0] ? c->id.router_id : "(none)",
                        c->id.group[0] ? c->id.group : "(none)");
            }
            if (pqwire_send_auth_ok(c->frontend) != 0 ||
                pqwire_send_ready_for_query(c->frontend) != 0) {
                return -1;
            }
            break;

        case PQ_EVENT_PARSE:
            if (c->be_wait != BE_IDLE) {
                if (feq_push_parse(c, &ev.payload.parse) != 0) {
                    (void)pqwire_send_error_response(c->frontend, "ERROR", "53300",
                                                     "frontend request queue full");
                }
                break;
            }
            if (pqproxy_on_parse(c->frontend, &c->cache, &ev.payload.parse,
                                 c->id.identity_slot >= 0
                                     ? c->id.identity_slot
                                     : srv->cfg->identity_slot) != 0) {
                (void)pqwire_send_error_response(c->frontend, "ERROR", "26000",
                                                 "prepared statement cache full");
                (void)pqwire_send_ready_for_query(c->frontend);
            }
            break;

        case PQ_EVENT_BIND:
            if (c->be_wait != BE_IDLE) {
                if (feq_push_bind(c, &ev.payload.bind) != 0) {
                    (void)pqwire_send_error_response(c->frontend, "ERROR", "53300",
                                                     "frontend request queue full");
                    (void)pqwire_send_ready_for_query(c->frontend);
                }
                break;
            }
            c->be_resp_len = 0;
            c->got_execute = c->got_sync = 0;
            if (srv->pool && c->identity_ready && srv->async_backend) {
                if (start_async_bind_from_event(srv, c, &ev.payload.bind) == 0) {
                    break;
                }
                if (srv->fair_schedule) {
                    if (feq_push_bind(c, &ev.payload.bind) == 0 &&
                        park_for_backend(srv, c) == 0) {
                        break;
                    }
                }
                if (!srv->cfg->quiet) {
                    fprintf(stderr, "pqproxy: async backend begin failed; try sync\n");
                }
            }
            if (srv->pool && c->identity_ready) {
                size_t rlen = 0;
                if (pqproxy_backend_exec_bind(srv->pool, &c->cache, &ev.payload.bind,
                                              &c->id, c->be_resp, sizeof(c->be_resp),
                                              &rlen) == 0) {
                    c->be_resp_len = rlen;
                    if (pqwire_send_bind_complete(c->frontend) != 0) {
                        return -1;
                    }
                    break;
                }
                if (!srv->cfg->quiet) {
                    fprintf(stderr, "pqproxy: backend bind failed; local stub\n");
                }
            }
            if (pqwire_send_bind_complete(c->frontend) != 0) {
                return -1;
            }
            break;

        case PQ_EVENT_EXECUTE:
            if (c->be_wait != BE_IDLE) {
                feq_item_t it;
                memset(&it, 0, sizeof(it));
                it.kind = FEQ_EXECUTE;
                if (feq_push(c, &it) != 0) {
                    c->got_execute = 1;
                }
                break;
            }
            if (!srv->pool || c->be_resp_len == 0) {
                if (pqwire_send_command_complete(c->frontend, "SELECT 0") != 0) {
                    return -1;
                }
            }
            break;

        case PQ_EVENT_SYNC:
            if (c->be_wait != BE_IDLE) {
                feq_item_t it;
                memset(&it, 0, sizeof(it));
                it.kind = FEQ_SYNC;
                (void)feq_push(c, &it);
                c->got_sync = 1;
                break;
            }
            if (c->be_resp_len > 0) {
                if (queue_plain_send(srv, c, c->be_resp, c->be_resp_len) != 0) {
                    return -1;
                }
                c->be_resp_len = 0;
            } else if (pqwire_send_ready_for_query(c->frontend) != 0) {
                return -1;
            }
            break;

        case PQ_EVENT_TERMINATE:
            c->state = CS_CLOSING;
            break;

        case PQ_EVENT_QUERY:
            if (c->be_wait != BE_IDLE) {
                feq_item_t it;
                memset(&it, 0, sizeof(it));
                it.kind = FEQ_QUERY;
                if (ev.payload.query.sql) {
                    strncpy(it.query_sql, ev.payload.query.sql,
                            sizeof(it.query_sql) - 1);
                }
                if (feq_push(c, &it) != 0) {
                    (void)pqwire_send_error_response(c->frontend, "ERROR", "53300",
                                                     "frontend request queue full");
                    (void)pqwire_send_ready_for_query(c->frontend);
                }
                break;
            }
            if (srv->cfg->reject_simple_query || !srv->pool || !c->identity_ready) {
                if (pqproxy_on_simple_query(c->frontend, srv->cfg->reject_simple_query,
                                            ev.payload.query.sql) != 0) {
                    return -1;
                }
            } else {
                size_t rlen = 0;
                pqwire_pipeline_status_t st;
                if (pqproxy_backend_exec_query(
                        srv->pool, c->id.group,
                        ev.payload.query.sql ? ev.payload.query.sql : "",
                        c->be_resp, sizeof(c->be_resp), &rlen, &st) == 0 &&
                    rlen > 0) {
                    if (queue_plain_send(srv, c, c->be_resp, rlen) != 0) {
                        return -1;
                    }
                } else if (pqwire_send_error_response(
                               c->frontend, "ERROR", "08006",
                               "simple Query backend forward failed") != 0 ||
                           pqwire_send_ready_for_query(c->frontend) != 0) {
                    return -1;
                }
            }
            break;

        default:
            break;
        }
    }

    return drain_frontend_out(srv, c);
}


static int feed_plain(server_t *srv, conn_t *c, const uint8_t *data, size_t len)
{
    if (len == 0) {
        return 0;
    }
    (void)pqwire_feed_input(c->frontend, data, len);
    return process_frontend(srv, c);
}

static int tls_on_handshake_done(server_t *srv, conn_t *c)
{
    c->state = CS_ACTIVE;
    c->ktls_on = pqproxy_ktls_note_after_handshake(c->ssl, srv->cfg->quiet) > 0;
    if (srv->cfg->require_mtls) {
        if (pqproxy_tls_identity(c->ssl, &c->id) != 0) {
            fprintf(stderr, "pqproxy: no peer cert identity\n");
            return -1;
        }
        c->id.identity_slot = srv->cfg->identity_slot;
        c->identity_ready = 1;
        if (!srv->cfg->quiet) {
            fprintf(stderr, "pqproxy: mTLS id router=%s group=%s\n",
                    c->id.router_id, c->id.group);
        }
    } else if (pqproxy_tls_identity(c->ssl, &c->id) == 0) {
        c->id.identity_slot = srv->cfg->identity_slot;
        c->identity_ready = 1;
    }
    return 0;
}

static int tls_drive_write(server_t *srv, conn_t *c)
{
    while (c->send_off < c->send_len) {
        size_t wr = 0;
        int rc = pqproxy_tls_write_plain(c->ssl, c->send_buf + c->send_off,
                                         c->send_len - c->send_off, &wr);
        if (rc < 0) {
            return -1;
        }
        if (rc == 0) {
            c->want_poll_out = 1;
            return 0;
        }
        c->send_off += wr;
        /* kTLS often arms on first post-handshake SSL_write */
        if (!c->ktls_on) {
            int tx = 0, rx = 0;
            (void)pqproxy_ktls_query(c->ssl, &tx, &rx);
            if (tx || rx) {
                c->ktls_on = 1;
                if (!srv->cfg->quiet) {
                    fprintf(stderr, "pqproxy: kTLS armed tx=%d rx=%d\n", tx, rx);
                }
            }
        }
    }
    c->send_off = c->send_len = 0;
    c->want_poll_out = 0;
    return 0;
}

static int tls_drive_read(server_t *srv, conn_t *c)
{
    for (;;) {
        size_t plain_n = 0;
        int rc = pqproxy_tls_read_plain(c->ssl, c->plain_buf, sizeof(c->plain_buf),
                                        &plain_n);
        if (rc == 1 && plain_n > 0) {
            if (feed_plain(srv, c, c->plain_buf, plain_n) != 0) {
                return -1;
            }
            continue;
        }
        if (rc == -2) {
            c->state = CS_CLOSING;
            return 0;
        }
        if (rc < 0) {
            return -1;
        }
        /* 0 = want I/O */
        break;
    }
    return 0;
}

static int on_tls_poll(server_t *srv, conn_t *c, int revents)
{
    if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
        return -1;
    }

    if (c->state == CS_TLS_HS) {
        int rc = pqproxy_tls_handshake(c->ssl);
        if (rc < 0) {
            fprintf(stderr, "pqproxy: TLS handshake failed slot=%d\n", c->slot);
            ERR_print_errors_fp(stderr);
            return -1;
        }
        if (rc == 0) {
            int err = SSL_get_error(c->ssl, 0);
            c->want_poll_out = (err == SSL_ERROR_WANT_WRITE);
            return submit_poll(srv, c);
        }
        if (tls_on_handshake_done(srv, c) != 0) {
            return -1;
        }
        /* fall through to read app data */
    }

    if (revents & POLLOUT) {
        if (tls_drive_write(srv, c) != 0) {
            return -1;
        }
    }
    if (revents & POLLIN) {
        if (tls_drive_read(srv, c) != 0) {
            return -1;
        }
    }
    /* Also try write after read (responses queued) */
    if (c->send_len > c->send_off) {
        if (tls_drive_write(srv, c) != 0) {
            return -1;
        }
    }
    if (c->state == CS_CLOSING && c->send_len == 0) {
        return -1;
    }
    return submit_poll(srv, c);
}

static int on_recv_plain(server_t *srv, conn_t *c, size_t n)
{
    if (n == 0) {
        c->state = CS_CLOSING;
        return 0;
    }
    return feed_plain(srv, c, c->recv_buf, n);
}

static int accept_one(server_t *srv, int fd)
{
    conn_t *c;
    int on = 1;

    if (fd < 0) {
        return -1;
    }
    c = alloc_conn(srv);
    if (!c) {
        fprintf(stderr, "pqproxy: connection pool full\n");
        close(fd);
        return 0;
    }
    pqproxy_metrics_inc_accepts();
    c->fd = fd;
    (void)set_nonblock(fd);
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

    c->frontend = pqwire_create(PQWIRE_ROLE_SERVER);
    if (!c->frontend) {
        close_conn(srv, c);
        return -1;
    }

    if (srv->tls_ctx) {
        c->ssl = pqproxy_tls_conn_new_fd(srv->tls_ctx, fd);
        if (!c->ssl) {
            close_conn(srv, c);
            return -1;
        }
        c->state = CS_TLS_HS;
        /* Kick handshake (may WANT_READ immediately) */
        {
            int rc = pqproxy_tls_handshake(c->ssl);
            if (rc == 1) {
                if (tls_on_handshake_done(srv, c) != 0) {
                    close_conn(srv, c);
                    return -1;
                }
            } else if (rc < 0) {
                close_conn(srv, c);
                return -1;
            }
        }
        if (submit_poll(srv, c) != 0) {
            close_conn(srv, c);
            return -1;
        }
    } else {
        c->state = CS_ACTIVE;
        (void)pqproxy_identity_from_cert_subject("plain-dev:default", &c->id);
        c->id.identity_slot = srv->cfg->identity_slot;
        c->identity_ready = 1;
        if (submit_recv(srv, c) != 0) {
            close_conn(srv, c);
            return -1;
        }
    }
    return 0;
}

static int submit_accept(server_t *srv)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&srv->ring);
    if (!sqe) {
        return -1;
    }
    srv->client_addr_len = sizeof(srv->client_addr);
    io_uring_prep_accept(sqe, srv->listen_fd,
                         (struct sockaddr *)&srv->client_addr,
                         &srv->client_addr_len, SOCK_CLOEXEC);
    io_uring_sqe_set_data64(sqe, pack_ud(OP_ACCEPT, 0));
    return 0;
}

void pqproxy_config_defaults(pqproxy_config_t *cfg)
{
    if (!cfg) {
        return;
    }
    memset(cfg, 0, sizeof(*cfg));
    cfg->listen_host = "0.0.0.0";
    cfg->listen_port = 6432;
    cfg->require_mtls = 1;
    cfg->identity_slot = 0;
    cfg->backend_port = 5432;
    cfg->backend_pool_size = 4;
    cfg->backend_lazy_group = 1;
    cfg->prefer_tls12_ktls = 1;
    cfg->maintain_interval_ms = 5000;
    cfg->metrics_log_interval_ms = 30000;
    cfg->metrics_http_host = "127.0.0.1";
    cfg->metrics_http_port = 9108;
    cfg->fair_schedule = 1;
    cfg->reject_simple_query = 1;
}

int pqproxy_run(const pqproxy_config_t *cfg)
{
    server_t *srv;
    int rc;
    int i;
    struct io_uring_cqe *cqe;

    if (!cfg) {
        return 1;
    }

    srv = calloc(1, sizeof(*srv));
    if (!srv) {
        fprintf(stderr, "pqproxy: out of memory\n");
        return 1;
    }
    srv->cfg = cfg;
    srv->fair_schedule = cfg->fair_schedule;
    g_server = srv;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    if (!cfg->plain) {
        srv->tls_ctx = pqproxy_tls_ctx_create(cfg);
        if (!srv->tls_ctx) {
            free(srv);
            g_server = NULL;
            return 1;
        }
    } else {
        fprintf(stderr, "pqproxy: WARNING plain mode (no TLS) — dev only\n");
    }

    if (cfg->backend_host && cfg->backend_host[0]) {
        pqproxy_backend_config_t bcfg;
        pqproxy_backend_config_defaults(&bcfg);
        bcfg.host = cfg->backend_host;
        bcfg.port = cfg->backend_port ? cfg->backend_port : 5432;
        bcfg.user = cfg->backend_user ? cfg->backend_user : "postgres";
        bcfg.password = cfg->backend_password ? cfg->backend_password : "";
        bcfg.database = cfg->backend_database ? cfg->backend_database : "postgres";
        bcfg.use_group_as_user = cfg->backend_use_group_as_user;
        bcfg.groups = cfg->backend_groups;
        bcfg.lazy_group_connect = cfg->backend_lazy_group;
        bcfg.pool_size = cfg->backend_pool_size ? cfg->backend_pool_size : 4;
        bcfg.quiet = cfg->quiet;
        srv->pool = pqproxy_backend_pool_create(&bcfg);
        if (!srv->pool && !cfg->quiet) {
            fprintf(stderr, "pqproxy: backend pool unavailable; rewrite local-only\n");
        }
        if (srv->pool) {
            if (pqproxy_backend_pool_set_nonblock(srv->pool) == 0) {
                srv->async_backend = 1;
            } else if (!cfg->quiet) {
                fprintf(stderr, "pqproxy: backend nonblock failed; using sync I/O\n");
            }
        }
    }

    srv->listen_fd = create_listen_socket(cfg);
    if (srv->listen_fd < 0) {
        pqproxy_backend_pool_destroy(srv->pool);
        pqproxy_tls_ctx_free(srv->tls_ctx);
        free(srv);
        g_server = NULL;
        return 1;
    }

    rc = io_uring_queue_init(PQPROXY_URING_ENTRIES, &srv->ring, 0);
    if (rc < 0) {
        fprintf(stderr, "pqproxy: io_uring_queue_init: %s\n", strerror(-rc));
        close(srv->listen_fd);
        pqproxy_backend_pool_destroy(srv->pool);
        pqproxy_tls_ctx_free(srv->tls_ctx);
        free(srv);
        g_server = NULL;
        return 1;
    }

    if (submit_accept(srv) != 0) {
        io_uring_queue_exit(&srv->ring);
        close(srv->listen_fd);
        pqproxy_backend_pool_destroy(srv->pool);
        pqproxy_tls_ctx_free(srv->tls_ctx);
        free(srv);
        g_server = NULL;
        return 1;
    }
    io_uring_submit(&srv->ring);

    fprintf(stderr, "pqproxy: listening on %s:%u (%s%s%s)\n",
            cfg->listen_host ? cfg->listen_host : "0.0.0.0",
            (unsigned)cfg->listen_port,
            cfg->plain ? "plain" : (cfg->require_mtls ? "mTLS" : "TLS"),
            srv->pool ? "+backend" : "",
            srv->async_backend ? "/async" : "");

    if (cfg->metrics_http_port > 0) {
        if (pqproxy_metrics_http_start(cfg->metrics_http_host, cfg->metrics_http_port) != 0 &&
            !cfg->quiet) {
            fprintf(stderr, "pqproxy: metrics HTTP failed to start (continuing)\n");
        }
    }

    srv->last_maintain_ms = mono_ms();
    srv->last_metrics_ms = srv->last_maintain_ms;

    while (!srv->stop) {
        {
            /* Wake periodically for maintain + metrics even without I/O */
            int wait_ms = 1000;
            struct __kernel_timespec ts;
            if (srv->cfg->maintain_interval_ms > 0 &&
                srv->cfg->maintain_interval_ms < wait_ms) {
                wait_ms = srv->cfg->maintain_interval_ms;
            }
            if (srv->cfg->metrics_log_interval_ms > 0 &&
                srv->cfg->metrics_log_interval_ms < wait_ms) {
                wait_ms = srv->cfg->metrics_log_interval_ms;
            }
            if (wait_ms < 100) {
                wait_ms = 100;
            }
            ts.tv_sec = wait_ms / 1000;
            ts.tv_nsec = (long)(wait_ms % 1000) * 1000000L;
            rc = io_uring_wait_cqe_timeout(&srv->ring, &cqe, &ts);
        }
        if (rc == -ETIME || rc == -EAGAIN) {
            server_tick(srv);
            continue;
        }
        if (rc < 0) {
            if (rc == -EINTR) {
                continue;
            }
            fprintf(stderr, "pqproxy: wait_cqe: %s\n", strerror(-rc));
            break;
        }
        server_tick(srv);

        {
            int op, slot;
            int res = cqe->res;
            unpack_ud(cqe->user_data, &op, &slot);
            io_uring_cqe_seen(&srv->ring, cqe);

            if (op == OP_ACCEPT) {
                if (res >= 0) {
                    (void)accept_one(srv, res);
                } else if (res != -EAGAIN && res != -ECONNABORTED) {
                    fprintf(stderr, "pqproxy: accept: %s\n", strerror(-res));
                }
                (void)submit_accept(srv);
            } else if (op == OP_RECV) {
                conn_t *c = (slot >= 0 && slot < PQPROXY_MAX_CONNS)
                                ? &srv->conns[slot]
                                : NULL;
                if (c && c->state != CS_FREE) {
                    c->recv_pending = 0;
                    if (res < 0) {
                        close_conn(srv, c);
                    } else {
                        if (on_recv_plain(srv, c, (size_t)res) != 0 ||
                            c->state == CS_CLOSING) {
                            close_conn(srv, c);
                        } else if (submit_recv(srv, c) != 0) {
                            close_conn(srv, c);
                        }
                    }
                }
            } else if (op == OP_SEND) {
                conn_t *c = (slot >= 0 && slot < PQPROXY_MAX_CONNS)
                                ? &srv->conns[slot]
                                : NULL;
                if (c && c->state != CS_FREE) {
                    c->send_pending = 0;
                    if (res < 0) {
                        close_conn(srv, c);
                    } else {
                        c->send_off += (size_t)res;
                        if (c->send_off >= c->send_len) {
                            c->send_off = c->send_len = 0;
                        } else {
                            (void)submit_send(srv, c);
                        }
                        if (c->state == CS_CLOSING && c->send_len == 0) {
                            close_conn(srv, c);
                        }
                    }
                }
            } else if (op == OP_POLL) {
                conn_t *c = (slot >= 0 && slot < PQPROXY_MAX_CONNS)
                                ? &srv->conns[slot]
                                : NULL;
                if (c && c->state != CS_FREE) {
                    c->poll_pending = 0;
                    if (res < 0) {
                        close_conn(srv, c);
                    } else if (on_tls_poll(srv, c, res) != 0) {
                        close_conn(srv, c);
                    }
                }
            } else if (op == OP_BE_SEND) {
                conn_t *c = (slot >= 0 && slot < PQPROXY_MAX_CONNS)
                                ? &srv->conns[slot]
                                : NULL;
                if (c && c->state != CS_FREE && c->be) {
                    if (on_be_send_cqe(srv, c, res) != 0) {
                        close_conn(srv, c);
                    }
                }
            } else if (op == OP_BE_RECV) {
                conn_t *c = (slot >= 0 && slot < PQPROXY_MAX_CONNS)
                                ? &srv->conns[slot]
                                : NULL;
                if (c && c->state != CS_FREE && c->be) {
                    if (on_be_recv_cqe(srv, c, res) != 0) {
                        close_conn(srv, c);
                    }
                }
            }
        }
        io_uring_submit(&srv->ring);
    }

    pqproxy_metrics_http_stop();
    for (i = 0; i < PQPROXY_MAX_CONNS; i++) {
        close_conn(srv, &srv->conns[i]);
    }
    io_uring_queue_exit(&srv->ring);
    close(srv->listen_fd);
    pqproxy_backend_pool_destroy(srv->pool);
    pqproxy_tls_ctx_free(srv->tls_ctx);
    g_server = NULL;
    free(srv);
    fprintf(stderr, "pqproxy: shutdown\n");
    return 0;
}
