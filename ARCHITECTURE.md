# ARCHITECTURE.md — pqproxy

## Goal

Guarantee row-level security for tens of thousands of CPE clients without
per-client backend connections, by:

1. Terminating mTLS and extracting `router_id` + tenant/group
2. Multiplexing onto a pre-authenticated pool keyed by group role
3. Injecting the verified identity into every Bind that hits the database

## Module boundaries

```
src/
  main.c              — CLI (--listen, --cert/--key/--ca, --plain)
  iouring_loop.c      — io_uring accept/recv/send + conn pool + pqwire frontend
  tls_mtls.c          — OpenSSL SSL_CTX, memory-BIO mTLS, peer cert extract
  rewrite_engine.c    — Parse cache, Bind inject, unnamed pipeline
  identity.c          — subject/X509 → router_id + group
include/
  pqproxy.h           — public app types + pqproxy_run()
  pqproxy_internal.h  — TLS helpers
scripts/
  gen_dev_certs.sh    — local mTLS PKI
```

## Data flow

```
CPE ──mTLS──▶ frontend_conn (pqwire SERVER)
                 │ PQ_EVENT_PARSE  → cache stmt locally; send ParseComplete
                 │ PQ_EVENT_BIND   → inject router_id; map to unnamed
                 │ PQ_EVENT_EXECUTE/SYNC → pipeline to backend pool
                 ▼
              backend_pool (pqwire CLIENT) ──▶ PostgreSQL (role = group)
```

## Security boundary

- **Macro**: PostgreSQL role = organizational group (`region_east`, …) + RLS on `current_user`
- **Micro**: `router_id` parameter always overwritten from mTLS; never from client Bind values

## Library usage (pique)

| API | Role |
|-----|------|
| `pqwire_create(PQWIRE_ROLE_SERVER)` | Frontend parser |
| `pqwire_create(PQWIRE_ROLE_CLIENT)` | Backend driver |
| `pqwire_feed_input` / `next_event` / `get_output` | Drive state machines |
| `pqwire_send_parse_complete` | Local ack after intercepting Parse |
| `pqwire_prepared_from_parse` | Statement cache entry |
| `pqwire_bind_inject_identity` | Overwrite identity slot |
| `pqwire_send_unnamed_pipeline` | Backend flush of P/B/E/S |

## Deliberate absences (in this app vs design prompt)

- Initial scaffold has no real io_uring/kTLS yet — see TODO.md
- No production pool balancer yet — interface only
- TLS identity parsing is stubbed until bonsai_pki or OpenSSL X509 helpers land

## Invariants

- No shared named prepared statements on backend connections
- No `set_config` for per-router GUC (avoid WAL/cache thrash)
- Write path prefers append-only / `ON CONFLICT DO NOTHING` semantics (app policy)
