/**
 * @file iouring_loop.c
 * @brief io_uring accept/recv/send loop with optional mTLS and pqwire frontend.
 */

#include "pqproxy_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <liburing.h>

enum {
    OP_ACCEPT = 1,
    OP_RECV   = 2,
    OP_SEND   = 3
};

typedef enum {
    CS_FREE = 0,
    CS_TLS_HS,
    CS_ACTIVE,
    CS_CLOSING
} conn_state_t;

typedef struct {
    int             fd;
    conn_state_t    state;
    SSL            *ssl;
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

    int             slot; /* index in pool */
} conn_t;

typedef struct {
    const pqproxy_config_t *cfg;
    SSL_CTX            *tls_ctx;
    struct io_uring     ring;
    int                 listen_fd;
    conn_t              conns[PQPROXY_MAX_CONNS];
    struct sockaddr_in  client_addr;
    socklen_t           client_addr_len;
    volatile sig_atomic_t stop;
} server_t;

static server_t *g_server;

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
        perror("fcntl listen");
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
    c->send_pending = 0;
    c->recv_pending = 0;
    (void)srv;
}

static int submit_recv(server_t *srv, conn_t *c)
{
    struct io_uring_sqe *sqe;
    if (c->recv_pending || c->state == CS_CLOSING || c->state == CS_FREE) {
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
    if (c->send_pending || c->send_off >= c->send_len) {
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

static int queue_ciphertext(server_t *srv, conn_t *c)
{
    size_t n = 0;
    uint8_t tmp[PQPROXY_IO_BUF];
    int rc;

    if (!c->ssl) {
        return 0;
    }
    rc = pqproxy_tls_drain_encrypted(c->ssl, tmp, sizeof(tmp), &n);
    if (rc < 0) {
        return -1;
    }
    if (n == 0) {
        return 0;
    }
    if (c->send_len + n > sizeof(c->send_buf)) {
        /* Drop oldest by resetting if stuck; better: backpressure */
        if (c->send_off == c->send_len) {
            c->send_off = c->send_len = 0;
        }
        if (c->send_len + n > sizeof(c->send_buf)) {
            fprintf(stderr, "pqproxy: send buffer full slot=%d\n", c->slot);
            return -1;
        }
    }
    memcpy(c->send_buf + c->send_len, tmp, n);
    c->send_len += n;
    return submit_send(srv, c);
}

static int queue_plain_send(server_t *srv, conn_t *c, const uint8_t *data, size_t len)
{
    if (len == 0) {
        return 0;
    }
    if (c->ssl) {
        size_t wr = 0;
        size_t off = 0;
        while (off < len) {
            int rc = pqproxy_tls_write_plain(c->ssl, data + off, len - off, &wr);
            if (rc < 0) {
                return -1;
            }
            if (rc == 0) {
                break;
            }
            off += wr;
            if (queue_ciphertext(srv, c) != 0) {
                return -1;
            }
        }
        return 0;
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

/**
 * Process pqwire frontend events for one connection.
 * Local Parse intercept; BindComplete/Ready stubs until backend pool exists.
 */
static int process_frontend(server_t *srv, conn_t *c)
{
    protocol_event_t ev;
    uint8_t out[PQPROXY_IO_BUF];
    size_t n;

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
            /* Trust mTLS identity; skip PG password auth for now */
            if (pqwire_send_auth_ok(c->frontend) != 0 ||
                pqwire_send_ready_for_query(c->frontend) != 0) {
                return -1;
            }
            break;

        case PQ_EVENT_PARSE:
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
            /*
             * Backend pool not wired yet: still inject identity into a
             * throwaway client context to validate rewrite, then ack frontend.
             */
            {
                pqwire_ctx_t *be = pqwire_create(PQWIRE_ROLE_CLIENT);
                if (!be) {
                    return -1;
                }
                if (c->identity_ready) {
                    (void)pqproxy_on_bind(be, &c->cache, &ev.payload.bind, &c->id);
                }
                pqwire_destroy(be);
            }
            if (pqwire_send_bind_complete(c->frontend) != 0) {
                return -1;
            }
            break;

        case PQ_EVENT_EXECUTE:
            /* No backend result set yet — empty complete */
            if (pqwire_send_command_complete(c->frontend, "SELECT 0") != 0) {
                return -1;
            }
            break;

        case PQ_EVENT_SYNC:
            if (pqwire_send_ready_for_query(c->frontend) != 0) {
                return -1;
            }
            break;

        case PQ_EVENT_TERMINATE:
            c->state = CS_CLOSING;
            break;

        case PQ_EVENT_QUERY:
            if (pqwire_send_error_response(
                    c->frontend, "ERROR", "0A000",
                    "simple Query disabled; use extended protocol") != 0 ||
                pqwire_send_ready_for_query(c->frontend) != 0) {
                return -1;
            }
            break;

        default:
            break;
        }
    }

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

static int feed_plain(server_t *srv, conn_t *c, const uint8_t *data, size_t len)
{
    if (len == 0) {
        return 0;
    }
    (void)pqwire_feed_input(c->frontend, data, len);
    return process_frontend(srv, c);
}

static int on_recv_data(server_t *srv, conn_t *c, size_t n)
{
    if (n == 0) {
        c->state = CS_CLOSING;
        return 0;
    }

    if (c->ssl) {
        size_t plain_n = 0;
        int rc;

        if (pqproxy_tls_feed_encrypted(c->ssl, c->recv_buf, n) != 0) {
            return -1;
        }

        if (c->state == CS_TLS_HS) {
            rc = pqproxy_tls_handshake(c->ssl);
            if (queue_ciphertext(srv, c) != 0) {
                return -1;
            }
            if (rc < 0) {
                fprintf(stderr, "pqproxy: TLS handshake failed slot=%d\n", c->slot);
                return -1;
            }
            if (rc == 1) {
                c->state = CS_ACTIVE;
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
                } else {
                    /* Optional client cert */
                    if (pqproxy_tls_identity(c->ssl, &c->id) == 0) {
                        c->id.identity_slot = srv->cfg->identity_slot;
                        c->identity_ready = 1;
                    }
                }
                /* Drain any app data that arrived with Finished */
            } else {
                return 0;
            }
        }

        /* Read all available plaintext */
        for (;;) {
            rc = pqproxy_tls_read_plain(c->ssl, c->plain_buf, sizeof(c->plain_buf),
                                        &plain_n);
            if (queue_ciphertext(srv, c) != 0) {
                return -1;
            }
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
            break;
        }
        return 0;
    }

    /* plain TCP */
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
    c->fd = fd;
    (void)set_nonblock(fd);
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

    c->frontend = pqwire_create(PQWIRE_ROLE_SERVER);
    if (!c->frontend) {
        close_conn(srv, c);
        return -1;
    }

    if (srv->tls_ctx) {
        c->ssl = pqproxy_tls_conn_new(srv->tls_ctx);
        if (!c->ssl) {
            close_conn(srv, c);
            return -1;
        }
        c->state = CS_TLS_HS;
        /* Kick handshake in case server writes first (usually needs client hello) */
        (void)pqproxy_tls_handshake(c->ssl);
        (void)queue_ciphertext(srv, c);
    } else {
        c->state = CS_ACTIVE;
        /* Dev plain mode: synthetic identity */
        (void)pqproxy_identity_from_cert_subject("plain-dev:default", &c->id);
        c->id.identity_slot = srv->cfg->identity_slot;
        c->identity_ready = 1;
    }

    if (submit_recv(srv, c) != 0) {
        close_conn(srv, c);
        return -1;
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

    /* Heap-allocate: connection pool with fixed buffers is too large for stack. */
    srv = calloc(1, sizeof(*srv));
    if (!srv) {
        fprintf(stderr, "pqproxy: out of memory for server\n");
        return 1;
    }
    srv->cfg = cfg;
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

    srv->listen_fd = create_listen_socket(cfg);
    if (srv->listen_fd < 0) {
        pqproxy_tls_ctx_free(srv->tls_ctx);
        free(srv);
        g_server = NULL;
        return 1;
    }

    rc = io_uring_queue_init(PQPROXY_URING_ENTRIES, &srv->ring, 0);
    if (rc < 0) {
        fprintf(stderr, "pqproxy: io_uring_queue_init: %s\n", strerror(-rc));
        close(srv->listen_fd);
        pqproxy_tls_ctx_free(srv->tls_ctx);
        free(srv);
        g_server = NULL;
        return 1;
    }

    if (submit_accept(srv) != 0) {
        fprintf(stderr, "pqproxy: submit accept failed\n");
        io_uring_queue_exit(&srv->ring);
        close(srv->listen_fd);
        pqproxy_tls_ctx_free(srv->tls_ctx);
        free(srv);
        g_server = NULL;
        return 1;
    }
    io_uring_submit(&srv->ring);

    fprintf(stderr, "pqproxy: listening on %s:%u (%s)\n",
            cfg->listen_host ? cfg->listen_host : "0.0.0.0",
            (unsigned)cfg->listen_port,
            cfg->plain ? "plain" : (cfg->require_mtls ? "mTLS" : "TLS"));

    while (!srv->stop) {
        rc = io_uring_wait_cqe(&srv->ring, &cqe);
        if (rc < 0) {
            if (rc == -EINTR) {
                continue;
            }
            fprintf(stderr, "pqproxy: wait_cqe: %s\n", strerror(-rc));
            break;
        }

        {
            int op, slot;
            int res = cqe->res;
            unpack_ud(cqe->user_data, &op, &slot);
            io_uring_cqe_seen(&srv->ring, cqe);

            if (op == OP_ACCEPT) {
                if (res >= 0) {
                    if (accept_one(srv, res) != 0) {
                        /* continue serving others */
                    }
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
                        if (res != -ECONNRESET && res != -EPIPE) {
                            fprintf(stderr, "pqproxy: recv: %s\n", strerror(-res));
                        }
                        close_conn(srv, c);
                    } else {
                        if (on_recv_data(srv, c, (size_t)res) != 0 ||
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
                            if (c->ssl) {
                                (void)queue_ciphertext(srv, c);
                            }
                        } else {
                            (void)submit_send(srv, c);
                        }
                        if (c->state == CS_CLOSING && c->send_len == 0) {
                            close_conn(srv, c);
                        }
                    }
                }
            }
        }
        io_uring_submit(&srv->ring);
    }

    for (i = 0; i < PQPROXY_MAX_CONNS; i++) {
        close_conn(srv, &srv->conns[i]);
    }
    io_uring_queue_exit(&srv->ring);
    close(srv->listen_fd);
    pqproxy_tls_ctx_free(srv->tls_ctx);
    g_server = NULL;
    free(srv);
    fprintf(stderr, "pqproxy: shutdown\n");
    return 0;
}
