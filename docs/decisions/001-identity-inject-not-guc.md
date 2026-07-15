# ADR 001: Identity inject via Bind, not set_config / GUC

## Status

Accepted

## Context

Tens of thousands of CPE share a small identity-grouped PostgreSQL pool.
Per-router `set_config` would thrash WAL and plan caches; named prepared
statements collide across frontends on a shared backend.

## Decision

- Intercept frontend Parse locally; cache per-frontend (hash table).
- On Bind, overwrite the identity parameter slot with mTLS-derived
  `router_id` and pipeline unnamed Parse/Bind/Execute/Sync to the backend.
- PostgreSQL role = group (macro RLS); Bind slot = micro identity.

## Consequences

- Simple Query (`Q`) cannot inject safely → rejected by default.
- Requires pique extended-query helpers and mid-pipeline ErrorResponse recovery.
