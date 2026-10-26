#!/usr/bin/env bash
# Isolated M0 guardrails; no production database or service is used.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
for tool in go psql initdb pg_ctl nats-server; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }
done
scratch=$(mktemp -d /tmp/arc-m0-02.XXXXXX)
nats_pid=
cleanup() {
  if [[ -n $nats_pid ]]; then kill "$nats_pid" 2>/dev/null || true; wait "$nats_pid" 2>/dev/null || true; fi
  pg_ctl -D "$scratch/db" -m immediate stop >/dev/null 2>&1 || true
  rm -rf "$scratch"
}
trap cleanup EXIT
initdb -D "$scratch/db" -A trust -U postgres --no-locale -E UTF8 >"$scratch/init.log"
pg_ctl -D "$scratch/db" -l "$scratch/postgres.log" -o "-k $scratch -h ''" -w start >/dev/null
export PGHOST="$scratch" PGUSER=postgres PGDATABASE=postgres
psql -X -v ON_ERROR_STOP=1 -c 'CREATE ROLE arc_migrator LOGIN;' -c 'CREATE ROLE arc_core LOGIN;' -c 'CREATE DATABASE arc OWNER arc_migrator;' >/dev/null
export PGUSER=arc_migrator PGDATABASE=arc PGPASSWORD_FILE="$scratch/password" MIGRATIONS_DIR="$PWD/migrations"
touch "$PGPASSWORD_FILE"
sh scripts/migrate.sh
sh scripts/migrate.sh
export ARC_IDENTITY_TEST_DSN="host=$scratch user=arc_core dbname=arc sslmode=disable"
export ARC_ACCESS_TEST_DSN="$ARC_IDENTITY_TEST_DSN"
# Use the existing M0-01 TLS/NKey bootstrap and smoke client unchanged.
(cd sdk && go run ./cmd/arc-dev-bootstrap -out "$scratch/secrets" -runtime-dir "$scratch/secrets" -store-dir "$scratch/jetstream")
# Bind an ephemeral port; the generated config has port 4222, replaced below.
port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(('127.0.0.1',0))
    print(sock.getsockname()[1])
PY
)
sed -i -E "s/^port: 4222/port: $port/; s/^http: .*/http: -1/" "$scratch/secrets/nats-server.conf"
start_nats() {
  nats-server -c "$scratch/secrets/nats-server.conf" >"$scratch/nats.log" 2>&1 &
  nats_pid=$!
  for attempt in $(seq 1 100); do
    if python3 - "$port" <<'PY'
import socket,sys
try:
    with socket.create_connection(('127.0.0.1',int(sys.argv[1])),0.1): pass
except OSError: sys.exit(1)
PY
    then return; fi
    if ! kill -0 "$nats_pid" 2>/dev/null; then cat "$scratch/nats.log" >&2; return 1; fi
    sleep 0.1
  done
  cat "$scratch/nats.log" >&2
  return 1
}
start_nats
(cd sdk && go run ./cmd/arc-rpc-smoke -url="tls://localhost:$port" -ca="$scratch/secrets/ca.crt" -service-seed="$scratch/secrets/nats-echo-service.seed" -client-seed="$scratch/secrets/nats-smoke-client.seed" -jetstream-seed="$scratch/secrets/nats-jetstream-admin.seed")
kill "$nats_pid"
wait "$nats_pid" || true
nats_pid=
# Only this isolated test deployment grants Identity subjects to the two test NKeys.
sed -i 's/rpc.bootstrap.v1.echo/rpc.identity.v1.>/g' "$scratch/secrets/nats-server.conf"
sed -i 's/"rpc.identity.v1.>"/"rpc.identity.v1.>", "rpc.access.v1.>"/g' "$scratch/secrets/nats-server.conf"
python3 - "$scratch/secrets/nats-server.conf" <<'PYTHON'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
config = path.read_text()
for operation in ('PING', 'INFO', 'STATS'):
    for suffix in ('', '.>'):
        subject = f'"$SRV.{operation}.arc-bootstrap{suffix}"'
        config = config.replace(subject, subject + f', "$SRV.{operation}.arc-access{suffix}"')
path.write_text(config)
PYTHON
start_nats
export ARC_IDENTITY_NATS_URL="tls://localhost:$port" ARC_IDENTITY_NATS_SECRETS="$scratch/secrets"
(cd sdk && go test -count=1 -run TestM0Identity -v ./identity)
if [[ ${ARC_TEST_ACCESS:-0} == 1 ]]; then
  (cd sdk && go test -race -count=1 -run TestM0Access -v ./access)
fi
echo 'Requested M0 integration guardrails passed; M7 not run.'
