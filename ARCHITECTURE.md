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
  main.c              — CLI (--config, --listen, --cert/--key/--ca, --plain, --fair, …)
  config_yaml.c       — YAML config load via sibling libyaml
  iouring_loop.c      — io_uring accept/recv/send + fair FE wait + pqwire frontend
  tls_mtls.c          — OpenSSL SSL_CTX, mTLS, peer cert extract
  ktls.c              — kTLS offload probe
  backend_pool.c      — identity-grouped warm pool + RR checkout + SCRAM/async
  metrics.c           — process counters / gauges
  metrics_http.c      — Prometheus /metrics + /health HTTP thread
  rewrite_engine.c    — Parse cache, Bind inject, unnamed pipeline
  identity.c          — subject/X509 → router_id + group
include/
  pqproxy.h           — public app types + pqproxy_run()
  config_yaml.h       — YAML bundle load/free
  metrics_http.h      — scrape endpoint start/stop + exposition format
config/
  pqproxy.example.yaml / pqproxy.dev.yaml
deploy/
  pqproxy.service     — systemd unit
  grafana/            — dashboard + Prometheus scrape snippet
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
- Grafana: import `deploy/grafana/pqproxy-dashboard.json`

## Fair scheduling

When many frontends share a limited backend pool:

1. **RR checkout** — `backend_pool` rotates the starting slot so slot 0 is not sticky
2. **Wait ring** — if async checkout fails, the frontend parks (`BE_WAITING_POOL`) instead of stubbing
3. **RR grant** — on backend release, waiters are resumed in FIFO order before the releasing frontend drains more binds

Disable with `--no-fair` / `fair_schedule: false`.

## Pipeline error recovery

Backend responses are classified with pique `pqwire_pipeline_*` helpers:

1. Messages are drained until ReadyForQuery (`Z`), even after ErrorResponse (`E`)
2. On SQL error: skip local BindComplete, forward Error+RFQ to the frontend, clear the FE request queue, count `backend_pipelines_fail`
3. Backend CLIENT wire is marked READY via `pqwire_note_ready` without a full `pqwire_reset` (auth state retained)

## Simple Query policy

Simple Query (`Q`) cannot carry Bind-slot identity inject. Default is **reject**
(`reject_simple_query: true`, SQLSTATE `0A000`). `--allow-simple-query` forwards
to the backend without inject (insecure; development only).

## Prepared statement cache

Per-frontend open-addressing hash table (FNV-1a) of up to
`PQPROXY_MAX_CACHED_STMTS` (64) prepared statement names.

## Configuration

- YAML via `--config FILE` (sibling **libyaml**); CLI flags override file values
- Example files under `config/`; systemd unit under `deploy/pqproxy.service`

## Invariants

- No shared named prepared statements on backend connections
- No `set_config` for per-router GUC (avoid WAL/cache thrash)
- Write path prefers append-only / `ON CONFLICT DO NOTHING` semantics (app policy)
