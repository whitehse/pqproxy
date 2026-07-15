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

- [ ] io_uring accept/read/write/sendmsg path (fixed buffers)
- [ ] OpenSSL accept + client cert required
- [ ] Extract router_id / tenant from cert (SAN URI or CN convention)
- [ ] kTLS `SOL_TLS` TX/RX after handshake
- [ ] MSG_ZEROCOPY / buffer slice writes to backends

## Connection pool

- [ ] Identity-grouped pool: group → N long-lived backend conns
- [ ] Backend SCRAM auth at pool warm-up (pique client role)
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
