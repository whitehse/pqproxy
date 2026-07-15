# TODO.md — pqproxy

Further work to explore. Ordered roughly by dependency.

## Scaffold / foundation

- [x] Repository layout under `~/apps/pqproxy`
- [x] AGENTS.md + ARCHITECTURE.md mapping to pique
- [x] CMake skeleton linking `../../pique`
- [x] Stub `rewrite_engine` using pique inject/pipeline APIs
- [x] CLI flags for listen/TLS/plain
- [x] Config schema (YAML via libyaml): listen addr, pool sizes, group map, identity slot
- [x] Structured logging (stderr JSON via `--log-json` / `log_json`)

## I/O and TLS

- [x] io_uring accept/recv/send (plain) and POLL (TLS) path
- [x] OpenSSL mTLS via `SSL_set_fd` + client cert required
- [x] Extract router_id / group from cert (CN + OU)
- [x] `SSL_OP_ENABLE_KTLS` + log ktls_tx/rx when kernel arms offload
- [x] Prefer TLS 1.2 AES-GCM for kTLS (`--ktls-prefer`, default on)
- [ ] Zerocopy sendfile / further kTLS TX path tuning
- [ ] MSG_ZEROCOPY / buffer slice writes to backends

## Connection pool

- [x] Backend pool warm-up + checkout/checkin (`backend_pool.c`)
- [x] Trust/cleartext auth at warm-up; CLI `--backend*` flags
- [x] Bind → inject → pipeline → filter responses to frontend
- [x] Mock dialectic test (`test_backend_pool`)
- [x] Full SCRAM-SHA-256 warm-up (`scram_client.c`, OpenSSL PBKDF2/HMAC)
- [x] Per-group login (`--backend-group-login`, `--backend-groups`, lazy open)
- [x] Fair scheduling when many frontends share one backend (RR checkout + FE wait ring)
- [x] Async backend I/O on io_uring (OP_BE_SEND/RECV, nonblock pool)
- [x] Live SCRAM against ephemeral Postgres (`scram_live_pg` / run_live_scram_test.sh)
- [x] Health check / reconnect on backend ErrorResponse / EOF
- [x] Frontend request queue while backend pipeline in flight

## Rewrite engine

- [x] Interface sketch: intercept Parse, inject Bind, unnamed pipeline
- [x] Per-frontend hash table of prepared statements (open-addressing FNV-1a)
- [ ] Configurable identity parameter slot (by name or index)
- [x] Pipeline error recovery: drain to ReadyForQuery, skip BindComplete on Error, clear FE queue
- [x] Reject simple Query ('Q') by default (`reject_simple_query` / `--allow-simple-query`)
- [x] Dialectic unit tests without live Postgres (hash cache, policy, pipeline status)

## Hardening / ops

- [x] Load test harness (many concurrent fake CPE clients) — `tests/load_harness.c`
- [x] Metrics: active frontends, pool wait, inject failures (counters + gauges)
- [x] systemd unit + example configs (`deploy/pqproxy.service`, `config/*.yaml`)
- [x] Integration test against real Postgres RLS policies (`rls_integration`, `e2e_proxy_rls`)

## Library follow-ups (track in pique/TODO.md too)

- [x] pique: mid-pipeline error helpers (`pqwire_pipeline_*`, `pqwire_msg_peek`)
- [ ] pique: zero-copy Bind rewrite
- [ ] bonsai_pki: cert identity helpers for mTLS

## Ops / observability

- [x] Periodic pool maintain via io_uring wait timeout (`--maintain-ms`)
- [x] Process metrics counters + log line (`--metrics-ms`)
- [x] RLS/inject integration against ephemeral Postgres (`rls_integration`)
- [x] Prometheus /metrics HTTP (`metrics_http.c`, `--metrics-http`, default `:9108`)
- [x] Full TCP e2e: pqproxy + backend + load + metrics + mTLS smoke (`run_e2e_proxy.sh`)
- [x] Dashboard examples (`deploy/grafana/pqproxy-dashboard.json`)
