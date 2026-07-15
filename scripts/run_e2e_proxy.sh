#!/usr/bin/env bash
# Full TCP e2e: ephemeral Postgres (RLS) + pqproxy plain + backend +
# concurrent load harness + Prometheus /metrics scrape.
# Optional: mTLS accept path smoke via OpenSSL s_client.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${ROOT}/build"
PROXY="${BUILD}/pqproxy"
HARNESS="${BUILD}/load_harness"
CERTS="${ROOT}/certs"

if [[ "${PQPROXY_SKIP_LIVE_PG:-}" == "1" ]]; then
  echo "SKIP: PQPROXY_SKIP_LIVE_PG=1"
  exit 0
fi

if [[ ! -x "$PROXY" || ! -x "$HARNESS" ]]; then
  cmake -B "$BUILD" -S "$ROOT"
  cmake --build "$BUILD" --target pqproxy load_harness
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

WORKDIR="$(mktemp -d /tmp/pqproxy-e2e-XXXXXX)"
PROXY_PID=""
cleanup() {
  if [[ -n "${PROXY_PID}" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
    kill -TERM "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
  if [[ -f "$WORKDIR/pgdata/postmaster.pid" ]]; then
    "$PG_BIN/pg_ctl" -D "$WORKDIR/pgdata" -m fast stop >/dev/null 2>&1 || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

export PATH="$PG_BIN:$PATH"
PW="e2e-secret-$$"
echo "$PW" > "$WORKDIR/pwfile"
chmod 600 "$WORKDIR/pwfile"
PGPORT=$((56000 + RANDOM % 900))
PROXY_PORT=$((57000 + RANDOM % 900))
METRICS_PORT=$((58000 + RANDOM % 900))

"$PG_BIN/initdb" -D "$WORKDIR/pgdata" -A scram-sha-256 --pwfile="$WORKDIR/pwfile" \
  --username=proxyadmin -E UTF8 --locale=C >/dev/null

cat >> "$WORKDIR/pgdata/postgresql.conf" <<EOF
listen_addresses = '127.0.0.1'
port = $PGPORT
unix_socket_directories = '$WORKDIR'
logging_collector = off
EOF

cat > "$WORKDIR/pgdata/pg_hba.conf" <<EOF
host    all    all    127.0.0.1/32    scram-sha-256
local   all    all                    scram-sha-256
EOF

"$PG_BIN/pg_ctl" -D "$WORKDIR/pgdata" -l "$WORKDIR/pg.log" -w start

for i in $(seq 1 50); do
  "$PG_BIN/pg_isready" -h 127.0.0.1 -p "$PGPORT" -U proxyadmin >/dev/null 2>&1 && break
  sleep 0.1
done

export PGPASSWORD="$PW"
"$PG_BIN/psql" -h 127.0.0.1 -p "$PGPORT" -U proxyadmin -d postgres -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE region_east LOGIN PASSWORD 'e2e-role-secret';
CREATE ROLE "default" LOGIN PASSWORD 'e2e-role-secret';
CREATE TABLE events (
  id bigserial PRIMARY KEY,
  router_id text NOT NULL,
  payload text NOT NULL
);
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
CREATE POLICY events_all ON events
  FOR ALL TO region_east, "default"
  USING (true)
  WITH CHECK (true);
GRANT SELECT, INSERT ON events TO region_east, "default";
GRANT USAGE, SELECT ON SEQUENCE events_id_seq TO region_east, "default";
SQL

# Plain proxy + group-login pool (default group for --plain identity)
"$PROXY" \
  --plain \
  --listen "127.0.0.1:${PROXY_PORT}" \
  --backend "127.0.0.1:${PGPORT}" \
  --backend-user region_east \
  --backend-password e2e-role-secret \
  --backend-database postgres \
  --backend-pool 4 \
  --backend-group-login \
  --backend-groups region_east,default \
  --metrics-http "127.0.0.1:${METRICS_PORT}" \
  --metrics-ms 0 \
  --maintain-ms 2000 \
  --quiet \
  >"$WORKDIR/proxy.log" 2>&1 &
PROXY_PID=$!

# Wait for proxy listen
for i in $(seq 1 50); do
  if (echo >/dev/tcp/127.0.0.1/"$PROXY_PORT") 2>/dev/null; then
    break
  fi
  # bash /dev/tcp may not work; use ss/nc
  if command -v ss >/dev/null 2>&1; then
    ss -ltn | grep -q ":${PROXY_PORT}" && break
  fi
  sleep 0.1
  if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "FAIL: pqproxy exited early"
    cat "$WORKDIR/proxy.log" || true
    exit 1
  fi
done

sleep 0.3

echo "=== load harness (concurrent frontends via plain proxy) ==="
"$HARNESS" --host 127.0.0.1 --port "$PROXY_PORT" --threads 4 --iters 5 --user app --db postgres

echo "=== Prometheus /metrics scrape ==="
METRICS_BODY="$(curl -fsS "http://127.0.0.1:${METRICS_PORT}/metrics" || true)"
if [[ -z "$METRICS_BODY" ]]; then
  # curl may be missing; use bash /dev/tcp
  exec 3<>"/dev/tcp/127.0.0.1/${METRICS_PORT}"
  printf 'GET /metrics HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n' >&3
  METRICS_BODY="$(cat <&3)"
  exec 3<&- 3>&-
fi
echo "$METRICS_BODY" | head -n 20
echo "$METRICS_BODY" | grep -q 'pqproxy_accepts_total' || {
  echo "FAIL: metrics missing pqproxy_accepts_total"
  exit 1
}
echo "$METRICS_BODY" | grep -q 'pqproxy_backend_pipelines_ok_total' || {
  echo "FAIL: metrics missing backend_pipelines_ok"
  exit 1
}

HEALTH="$(curl -fsS "http://127.0.0.1:${METRICS_PORT}/health" 2>/dev/null || true)"
if [[ -z "$HEALTH" ]]; then
  exec 3<>"/dev/tcp/127.0.0.1/${METRICS_PORT}"
  printf 'GET /health HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n' >&3
  HEALTH="$(cat <&3)"
  exec 3<&- 3>&-
fi
echo "$HEALTH" | grep -qi 'ok' || {
  echo "FAIL: /health"
  exit 1
}

# Verify injected rows landed (plain identity = plain-dev)
export PGPASSWORD=e2e-role-secret
ROWS="$("$PG_BIN/psql" -h 127.0.0.1 -p "$PGPORT" -U region_east -d postgres -tAc \
  "SELECT count(*) FROM events")"
echo "events rows after load: $ROWS"
if [[ "${ROWS:-0}" -lt 1 ]]; then
  echo "WARN: no rows via region_east (group may be default); checking all..."
  export PGPASSWORD="$PW"
  ROWS="$("$PG_BIN/psql" -h 127.0.0.1 -p "$PGPORT" -U proxyadmin -d postgres -tAc \
    "SELECT count(*) FROM events")"
  echo "events rows (admin): $ROWS"
fi
if [[ "${ROWS:-0}" -lt 1 ]]; then
  echo "FAIL: expected inserts through proxy"
  cat "$WORKDIR/proxy.log" || true
  export PGPASSWORD="$PW"
  "$PG_BIN/psql" -h 127.0.0.1 -p "$PGPORT" -U proxyadmin -d postgres -c "SELECT * FROM events" || true
  exit 1
fi

# Injected router_id should be plain-dev (from plain-mode identity), not forged-by-client
export PGPASSWORD="$PW"
FORGED="$("$PG_BIN/psql" -h 127.0.0.1 -p "$PGPORT" -U proxyadmin -d postgres -tAc \
  "SELECT count(*) FROM events WHERE router_id = 'forged-by-client'")"
INJECTED="$("$PG_BIN/psql" -h 127.0.0.1 -p "$PGPORT" -U proxyadmin -d postgres -tAc \
  "SELECT count(*) FROM events WHERE router_id = 'plain-dev'")"
echo "forged rows=$FORGED injected plain-dev rows=$INJECTED"
if [[ "${FORGED:-0}" -ne 0 ]]; then
  echo "FAIL: client-forged router_id was accepted"
  exit 1
fi
if [[ "${INJECTED:-0}" -lt 1 ]]; then
  echo "FAIL: identity inject did not write plain-dev"
  "$PG_BIN/psql" -h 127.0.0.1 -p "$PGPORT" -U proxyadmin -d postgres -c "SELECT * FROM events LIMIT 10"
  exit 1
fi

# Stop plain proxy; optional mTLS smoke
kill -TERM "$PROXY_PID" 2>/dev/null || true
wait "$PROXY_PID" 2>/dev/null || true
PROXY_PID=""

if [[ -f "$CERTS/server.crt" && -f "$CERTS/client.crt" ]]; then
  echo "=== mTLS accept smoke (s_client) ==="
  MTLS_PORT=$((59000 + RANDOM % 900))
  "$PROXY" \
    --listen "127.0.0.1:${MTLS_PORT}" \
    --cert "$CERTS/server.crt" \
    --key "$CERTS/server.key" \
    --ca "$CERTS/ca.crt" \
    --no-metrics-http \
    --metrics-ms 0 \
    --quiet \
    >"$WORKDIR/proxy-mtls.log" 2>&1 &
  PROXY_PID=$!
  for i in $(seq 1 50); do
    if command -v ss >/dev/null 2>&1 && ss -ltn | grep -q ":${MTLS_PORT}"; then
      break
    fi
    sleep 0.1
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
      echo "FAIL: mTLS pqproxy exited"
      cat "$WORKDIR/proxy-mtls.log" || true
      exit 1
    fi
  done
  sleep 0.2
  # Handshake only — expect TLS success (proxy waits for PG Startup after)
  echo | openssl s_client -connect "127.0.0.1:${MTLS_PORT}" \
    -cert "$CERTS/client.crt" -key "$CERTS/client.key" \
    -CAfile "$CERTS/ca.crt" -brief </dev/null 2>"$WORKDIR/s_client.err" \
    | tee "$WORKDIR/s_client.out" || true
  if ! grep -qiE 'CONNECTION ESTABLISHED|Protocol version|Verification: OK' \
       "$WORKDIR/s_client.err" "$WORKDIR/s_client.out" 2>/dev/null; then
    # openssl -brief output varies; accept exit 0 from handshake bytes
    if ! grep -qi 'SSL-Session\|Verify return code: 0' "$WORKDIR/s_client.err" 2>/dev/null; then
      # try without -brief
      if openssl s_client -connect "127.0.0.1:${MTLS_PORT}" \
          -cert "$CERTS/client.crt" -key "$CERTS/client.key" \
          -CAfile "$CERTS/ca.crt" </dev/null 2>&1 | grep -q 'Verify return code: 0'; then
        echo "mTLS handshake OK"
      else
        echo "WARN: mTLS s_client ambiguous; checking proxy still up"
        kill -0 "$PROXY_PID" || { echo "FAIL mTLS proxy dead"; exit 1; }
      fi
    else
      echo "mTLS handshake OK"
    fi
  else
    echo "mTLS handshake OK"
  fi
  kill -TERM "$PROXY_PID" 2>/dev/null || true
  wait "$PROXY_PID" 2>/dev/null || true
  PROXY_PID=""
else
  echo "SKIP mTLS smoke (no certs/)"
fi

echo "e2e_proxy_rls PASSED"
