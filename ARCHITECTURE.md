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
  main.c              — CLI (--listen, --cert/--key/--ca, --plain, --metrics-http, …)
  iouring_loop.c      — io_uring accept/recv/send + conn pool + pqwire frontend
  tls_mtls.c          — OpenSSL SSL_CTX, mTLS, peer cert extract
  ktls.c              — kTLS offload probe
  backend_pool.c      — identity-grouped warm pool + SCRAM/async pipelines
  metrics.c           — process counters / gauges
  metrics_http.c      — Prometheus /metrics + /health HTTP thread
  rewrite_engine.c    — Parse cache, Bind inject, unnamed pipeline
  identity.c          — subject/X509 → router_id + group
include/
  pqproxy.h           — public app types + pqproxy_run()
  metrics_http.h      — scrape endpoint start/stop + exposition format
scripts/
  gen_dev_certs.sh    — local mTLS PKI
  run_e2e_proxy.sh    — full TCP e2e (PG + proxy + load + metrics + mTLS smoke)
  run_rls_integration.sh / run_live_scram_test.sh
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

## Observability

- Stderr metrics line on `--metrics-ms` interval
- Prometheus text on `GET /metrics` (`--metrics-http HOST:PORT`, default `127.0.0.1:9108`; `--no-metrics-http` to disable)
- Concurrent load: `build/load_harness --host … --port … --threads N --iters M`

## Deliberate absences (vs full design prompt)

- Fair multi-frontend scheduling on a shared backend (see TODO.md)
- YAML config / systemd unit examples
- Dashboard (Grafana) panels

## Invariants

- No shared named prepared statements on backend connections
- No `set_config` for per-router GUC (avoid WAL/cache thrash)
- Write path prefers append-only / `ON CONFLICT DO NOTHING` semantics (app policy)
