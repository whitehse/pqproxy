#!/usr/bin/env bash
# Generate a small mTLS PKI for local pqproxy development.
set -euo pipefail
DIR="${1:-$(dirname "$0")/../certs}"
mkdir -p "$DIR"
cd "$DIR"

# CA
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 3650 \
  -subj "/CN=pqproxy-dev-ca"

# Server
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 825

# Client (router identity via CN + OU group)
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
  -subj "/CN=router-dev-001/OU=region_east"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 825

rm -f server.csr client.csr ca.srl
echo "Wrote certs under $DIR"
echo "  server: --cert server.crt --key server.key --ca ca.crt"
echo "  client: client.crt / client.key (CN=router-dev-001 OU=region_east)"
