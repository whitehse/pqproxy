# TODO.md — pqproxy

Further work to explore. Ordered roughly by dependency.

## Scaffold / foundation

- [x] Repository layout under `~/apps/pqproxy`
- [x] AGENTS.md + ARCHITECTURE.md mapping to pique
- [x] CMake skeleton linking `../../pique`
- [x] Stub `rewrite_engine` using pique inject/pipeline APIs
- [x] CLI flags for listen/TLS/plain
- [ ] Config schema (YAML via libyaml): listen addr, pool sizes, group map, identity slot
- [ ] Structured logging (stderr JSON or syslog) — app-side only

## I/O and TLS

- [x] io_uring accept/recv/send (plain) and POLL (TLS) path
- [x] OpenSSL mTLS via `SSL_set_fd` + client cert required
- [x] Extract router_id / group from cert (CN + OU)
- [x] `SSL_OP_ENABLE_KTLS` + log ktls_tx/rx when kernel arms offload
- [ ] Broader kTLS coverage (TLS 1.2 AES-GCM profile, zerocopy sendfile)
- [ ] MSG_ZEROCOPY / buffer slice writes to backends

## Connection pool

- [x] Backend pool warm-up + checkout/checkin (`backend_pool.c`)
- [x] Trust/cleartext auth at warm-up; CLI `--backend*` flags
- [x] Bind → inject → pipeline → filter responses to frontend
- [x] Mock dialectic test (`test_backend_pool`)
- [ ] Full SCRAM-SHA-256 warm-up (when backends require it)
- [ ] Per-group login (`--backend-use-group-as-user`) multi-role pools
- [ ] Fair scheduling when many frontends share one backend
- [ ] Health check / reconnect on backend ErrorResponse / EOF

## Rewrite engine

- [x] Interface sketch: intercept Parse, inject Bind, unnamed pipeline
- [ ] Per-frontend hash table of prepared statements
- [ ] Configurable identity parameter slot (by name or index)
- [ ] Pipeline error recovery: drain to ReadyForQuery, reset frontend state
- [ ] Reject or rewrite dangerous simple Query ('Q') when policy requires extended only
- [ ] Dialectic unit tests without live Postgres

## Hardening / ops

- [ ] Load test harness (many concurrent fake CPE clients)
- [ ] Metrics: active frontends, pool wait, inject failures
- [ ] systemd unit + example configs
- [ ] Integration test against real Postgres RLS policies

## Library follow-ups (track in pique/TODO.md too)

- [ ] pique: mid-pipeline error helpers
- [ ] pique: zero-copy Bind rewrite
- [ ] bonsai_pki: cert identity helpers for mTLS
