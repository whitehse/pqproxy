#!/usr/bin/env bash
# Ephemeral Postgres + RLS table; run test_rls_proxy against SCRAM auth.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${ROOT}/build"
BIN="${BUILD}/test_rls_proxy"

if [[ "${PQPROXY_SKIP_LIVE_PG:-}" == "1" ]]; then
  echo "SKIP: PQPROXY_SKIP_LIVE_PG=1"
  exit 0
fi

if [[ ! -x "$BIN" ]]; then
  cmake -B "$BUILD" -S "$ROOT"
  cmake --build "$BUILD" --target test_rls_proxy
fi

PG_BIN=""
for d in /usr/lib/postgresql/*/bin; do
  if [[ -x "$d/initdb" && -x "$d/pg_ctl" ]]; then
    PG_BIN="$d"
  fi
done
if [[ -z "$PG_BIN" ]]; then
  echo "SKIP: no PostgreSQL initdb"
  exit 0
fi

WORKDIR="$(mktemp -d /tmp/pqproxy-rls-XXXXXX)"
cleanup() {
  if [[ -f "$WORKDIR/pgdata/postmaster.pid" ]]; then
    "$PG_BIN/pg_ctl" -D "$WORKDIR/pgdata" -m fast stop >/dev/null 2>&1 || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

export PATH="$PG_BIN:$PATH"
PW="rls-secret-$$"
echo "$PW" > "$WORKDIR/pwfile"
chmod 600 "$WORKDIR/pwfile"
PORT=$((56000 + RANDOM % 900))

"$PG_BIN/initdb" -D "$WORKDIR/pgdata" -A scram-sha-256 --pwfile="$WORKDIR/pwfile" \
  --username=proxyadmin -E UTF8 --locale=C >/dev/null

cat >> "$WORKDIR/pgdata/postgresql.conf" <<EOF
listen_addresses = '127.0.0.1'
port = $PORT
unix_socket_directories = '$WORKDIR'
logging_collector = off
EOF

cat > "$WORKDIR/pgdata/pg_hba.conf" <<EOF
host    all    all    127.0.0.1/32    scram-sha-256
local   all    all                    scram-sha-256
EOF

"$PG_BIN/pg_ctl" -D "$WORKDIR/pgdata" -l "$WORKDIR/pg.log" -w start

for i in $(seq 1 50); do
  "$PG_BIN/pg_isready" -h 127.0.0.1 -p "$PORT" -U proxyadmin >/dev/null 2>&1 && break
  sleep 0.1
done

export PGPASSWORD="$PW"
"$PG_BIN/psql" -h 127.0.0.1 -p "$PORT" -U proxyadmin -d postgres -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE region_east LOGIN PASSWORD 'rls-secret-role';
CREATE TABLE events (
  id bigserial PRIMARY KEY,
  router_id text NOT NULL,
  payload text NOT NULL
);
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
-- Macro boundary: only rows owned by current_user (session role)
CREATE POLICY events_owner ON events
  FOR ALL TO region_east
  USING (router_id LIKE current_user || ':%' OR router_id = current_setting('app.router_id', true))
  WITH CHECK (router_id = current_setting('app.router_id', true));
GRANT SELECT, INSERT ON events TO region_east;
GRANT USAGE, SELECT ON SEQUENCE events_id_seq TO region_east;
SQL

# Use proxyadmin password for pool but connect as region_east via group login
export PQPROXY_TEST_PG_HOST=127.0.0.1
export PQPROXY_TEST_PG_PORT=$PORT
export PQPROXY_TEST_PG_USER=region_east
export PQPROXY_TEST_PG_PASSWORD=rls-secret-role
export PQPROXY_TEST_PG_DB=postgres

echo "Running RLS inject integration on 127.0.0.1:$PORT ..."
"$BIN"
echo "RLS integration OK"
