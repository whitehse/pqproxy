#!/usr/bin/env bash
# Spin an ephemeral PostgreSQL with SCRAM-SHA-256 and run test_scram_live.
# CI-friendly: no root, no system cluster changes.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${ROOT}/build"
BIN="${BUILD}/test_scram_live"

if [[ "${PQPROXY_SKIP_LIVE_PG:-}" == "1" ]]; then
  echo "SKIP: PQPROXY_SKIP_LIVE_PG=1"
  exit 0
fi

if [[ ! -x "$BIN" ]]; then
  echo "Building test_scram_live..."
  cmake -B "$BUILD" -S "$ROOT"
  cmake --build "$BUILD" --target test_scram_live
fi

# Locate PG binaries (Debian layout)
PG_BIN=""
for d in /usr/lib/postgresql/*/bin; do
  if [[ -x "$d/initdb" && -x "$d/pg_ctl" && -x "$d/postgres" ]]; then
    PG_BIN="$d"
  fi
done
if [[ -z "$PG_BIN" ]]; then
  if command -v initdb >/dev/null 2>&1; then
    PG_BIN="$(dirname "$(command -v initdb)")"
  fi
fi
if [[ -z "$PG_BIN" || ! -x "$PG_BIN/initdb" ]]; then
  echo "SKIP: no PostgreSQL initdb found"
  exit 0
fi

WORKDIR="$(mktemp -d /tmp/pqproxy-scram-XXXXXX)"
cleanup() {
  if [[ -f "$WORKDIR/pgdata/postmaster.pid" ]]; then
    "$PG_BIN/pg_ctl" -D "$WORKDIR/pgdata" -m fast stop >/dev/null 2>&1 || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

export PATH="$PG_BIN:$PATH"
PW="scram-test-secret-$$"
echo "$PW" > "$WORKDIR/pwfile"
chmod 600 "$WORKDIR/pwfile"

# Free high port
PORT=$((55432 + RANDOM % 1000))

"$PG_BIN/initdb" -D "$WORKDIR/pgdata" -A scram-sha-256 --pwfile="$WORKDIR/pwfile" \
  --username=scramuser -E UTF8 --locale=C >/dev/null

cat >> "$WORKDIR/pgdata/postgresql.conf" <<EOF
listen_addresses = '127.0.0.1'
port = $PORT
unix_socket_directories = '$WORKDIR'
logging_collector = off
EOF

cat > "$WORKDIR/pgdata/pg_hba.conf" <<EOF
# TYPE  DATABASE  USER  ADDRESS       METHOD
host    all       all   127.0.0.1/32  scram-sha-256
local   all       all                 scram-sha-256
EOF

"$PG_BIN/pg_ctl" -D "$WORKDIR/pgdata" -l "$WORKDIR/pg.log" -w start

# Wait ready
for i in $(seq 1 50); do
  if "$PG_BIN/pg_isready" -h 127.0.0.1 -p "$PORT" -U scramuser >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

export PQPROXY_TEST_PG_HOST=127.0.0.1
export PQPROXY_TEST_PG_PORT=$PORT
export PQPROXY_TEST_PG_USER=scramuser
export PQPROXY_TEST_PG_PASSWORD="$PW"
export PQPROXY_TEST_PG_DB=postgres

echo "Running live SCRAM pool test against 127.0.0.1:$PORT ..."
"$BIN"
echo "live SCRAM test OK"
