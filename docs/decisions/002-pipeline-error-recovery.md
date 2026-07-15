# ADR 002: Drain backend to ReadyForQuery on ErrorResponse

## Status

Accepted

## Context

Extended-query pipelines may fail mid-flight (constraint, missing relation).
PostgreSQL sends ErrorResponse then ignores further messages until Sync,
then ReadyForQuery. The proxy must leave both FE and BE in a clean state.

## Decision

- Use pique `pqwire_pipeline_*` helpers to observe messages until RFQ.
- On error: do not emit local BindComplete; forward Error+RFQ; clear the
  frontend request queue; count `backend_pipelines_fail`.
- Mark backend CLIENT wire READY via `pqwire_note_ready` without
  `pqwire_reset` (preserve SCRAM/auth state for pool reuse).

## Consequences

- Metrics distinguish I/O failure (async_fail / reconnect) from SQL error.
- FE queue items after a failed pipeline are discarded, not replayed blindly.
