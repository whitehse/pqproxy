# AGENTS.md — pqproxy

## What this is

**pqproxy** is a high-performance Layer-7 PostgreSQL protocol proxy.

- Authenticate CPE routers via client mTLS certificates
- Map identities to an **identity-grouped** backend connection pool
- Inject verified `router_id` into Extended Query Bind parameters
- Rewrite named prepared statements to the **unnamed** Parse/Bind/Execute/Sync pipeline
- Target stack: Linux **io_uring**, OpenSSL handshake → **kTLS** offload

Design source: `~/new_design2.txt`.

## Language / build

- C11, CMake ≥ 3.20
- Static link to sibling **pique** (`libpqwire`)
- Optional: libyaml for config

```bash
cmake -B build -S . -DPIQUE_ROOT=$HOME/pique
cmake --build build
ctest --test-dir build
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md). Domain intent and library boundaries are there.

## Directives

- **Must** keep identity injection in the app (or pure helpers in pique); never trust client-supplied router_id.
- **Must** use pique dual contexts: frontend `PQWIRE_ROLE_SERVER`, backend `PQWIRE_ROLE_CLIENT`.
- **Must not** put io_uring/OpenSSL/kTLS inside pique — app owns I/O.
- **Prefer** `pqwire_bind_inject_identity` + `pqwire_send_unnamed_pipeline` over ad-hoc Bind surgery.
- **Prefer** fixed-size per-connection buffers on the hot path (design: no malloc in steady state).

## Definition of done

- [x] Builds with `-Wall -Wextra -Wpedantic -Werror`
- [x] Unit/dialectic tests for rewrite engine without a real database
- [x] Integration path documented (mTLS fixture + local Postgres; `run_e2e_proxy.sh`)
- [x] TODO.md items updated when architecture changes

## Related libraries

| Path | Use |
|------|-----|
| `~/pique` | Wire protocol parse/serialize, inject helpers |
| `~/libyaml` | Config file parsing |
| `~/bonsai_pki` | Future mTLS identity extraction helpers |
