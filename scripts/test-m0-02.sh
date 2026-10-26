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
psql -X -v ON_ERROR_STOP=1 -c 'CREATE ROLE arc_migrator LOGIN;' -c 'CREATE ROLE arc_core LOGIN;' -c 'CREATE ROLE arc_task LOGIN;' -c 'CREATE ROLE arc_notify LOGIN;' -c 'CREATE DATABASE arc OWNER arc_migrator;' >/dev/null
export PGUSER=arc_migrator PGDATABASE=arc PGPASSWORD_FILE="$scratch/password" MIGRATIONS_DIR="$PWD/services"
touch "$PGPASSWORD_FILE"
sh scripts/migrate.sh
sh scripts/migrate.sh
if [[ ${ARC_TEST_GATE:-0} == 1 ]]; then
  PGUSER=postgres PGDATABASE=postgres psql -X -v ON_ERROR_STOP=1 -c 'CREATE DATABASE arc_gate OWNER arc_migrator TEMPLATE arc;' >/dev/null
fi
if [[ ${ARC_TEST_TASK:-0} == 1 ]]; then
 PGUSER=postgres PGDATABASE=postgres psql -X -v ON_ERROR_STOP=1 -c 'CREATE DATABASE arc_task_proof OWNER arc_migrator TEMPLATE arc;' >/dev/null
fi
export ARC_IDENTITY_TEST_DSN="host=$scratch user=arc_core dbname=arc sslmode=disable"
export ARC_ACCESS_TEST_DSN="$ARC_IDENTITY_TEST_DSN"
# Use the existing M0-01 TLS/NKey bootstrap and smoke client unchanged.
(go run ./cmd/arc-dev-bootstrap -out "$scratch/secrets" -runtime-dir "$scratch/secrets" -store-dir "$scratch/jetstream")
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
(go run ./cmd/arc-rpc-smoke -url="tls://localhost:$port" -ca="$scratch/secrets/ca.crt" -service-seed="$scratch/secrets/nats-echo-service.seed" -client-seed="$scratch/secrets/nats-smoke-client.seed" -jetstream-seed="$scratch/secrets/nats-jetstream-admin.seed")
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
if [[ ${ARC_TEST_FABRIC:-0} == 1 ]]; then
  # Test-only credentials: exact RPC majors and Fabric control/probe permissions.
  python3 - "$scratch/secrets/nats-server.conf" <<'PYTHON_FABRIC'
import pathlib, sys
p=pathlib.Path(sys.argv[1])
s=p.read_text().replace('"rpc.access.v1.>"', '"rpc.access.v1.>", "rpc.books.v1.>", "rpc.books.v2.>", "ctl.arc.fabric.>"')
# The domain-owner must request Access/Fabric and receive request replies.
s=s.replace('publish: { allow: ["_INBOX.>"] }', 'publish: { allow: ["_INBOX.>", "rpc.access.v1.>", "ctl.arc.fabric.register", "ctl.arc.fabric.ready", "ctl.arc.fabric.check", "ctl.arc.fabric.probe.>", "$SRV.INFO.books.>"] }')
s=s.replace('subscribe: { allow: [\n', 'subscribe: { allow: [\n          "_INBOX.>",')
s=s.replace('"$JS.API.>", "evt.>"','"$JS.API.>", "evt.>", "dlq.>", "$JS.ACK.>"')
for operation in ('PING','INFO','STATS'):
    for suffix in ('','.>'):
        subject=f'"$SRV.{operation}.arc-access{suffix}"'
        s=s.replace(subject, subject+f', "$SRV.{operation}.books{suffix}"')
p.write_text(s)
PYTHON_FABRIC
fi
if [[ ${ARC_TEST_GATE:-0} == 1 ]]; then
  python3 - "$scratch/secrets/nats-server.conf" <<'PYTHON_GATE'
import pathlib,sys
p=pathlib.Path(sys.argv[1]);s=p.read_text()
s=s.replace('"rpc.books.v2.>"','"rpc.books.v2.>", "rpc.task.v1.>", "ctl.arc.fabric.routes"')
s=s.replace('"ctl.arc.fabric.check",','"ctl.arc.fabric.check", "ctl.arc.fabric.routes", "evt.arc.fabric.routes.changed",')
s=s.replace('subscribe: { allow: ["_INBOX.>"] }','subscribe: { allow: ["_INBOX.>", "evt.arc.fabric.routes.changed"] }')
s=s.replace('"$SRV.INFO.books.>"','"$SRV.INFO.books.>", "$SRV.INFO.tasks.>"')
for op in ('PING','INFO','STATS'):
    for suffix in ('','.>'):
        x=f'"$SRV.{op}.books{suffix}"';s=s.replace(x,x+f', "$SRV.{op}.tasks{suffix}"')
p.write_text(s)
PYTHON_GATE
fi
if [[ ${ARC_TEST_TASK:-0} == 1 ]]; then
  (go run ./cmd/arc-m0-06-credentials -dir "$scratch/secrets")
fi
start_nats
export ARC_IDENTITY_NATS_URL="tls://localhost:$port" ARC_IDENTITY_NATS_SECRETS="$scratch/secrets"
if [[ ${ARC_TEST_TASK_ONLY:-0} != 1 ]]; then
(go test -count=1 -run TestM0Identity -v ./services/core/modules/identity)
if [[ ${ARC_TEST_ACCESS:-0} == 1 ]]; then
  (go test -race -count=1 -run TestM0Access -v ./services/core/modules/access)
fi
if [[ ${ARC_TEST_FABRIC:-0} == 1 ]]; then
  (go test -race -count=1 -run TestM0Fabric -v ./services/core/modules/fabric)
fi
if [[ ${ARC_TEST_GATE:-0} == 1 ]]; then
  (ARC_ACCESS_TEST_DSN="host=$scratch user=arc_core dbname=arc_gate sslmode=disable" go test -race -count=1 -run TestM0Gate -v ./services/gate/modules/http)
fi
fi
if [[ ${ARC_TEST_TASK:-0} == 1 ]]; then
 (go build -race -o "$scratch/arc-task" ./cmd/arc-task && go build -race -o "$scratch/arc-notify" ./cmd/arc-notify)
 (ARC_TASK_TEST_DSN="host=$scratch user=arc_core dbname=arc_task_proof sslmode=disable" ARC_DOMAIN_BIN_DIR="$scratch" go test -race -count=1 -timeout=3m -run TestM006 -v ./services/task)
fi
echo 'Requested M0 integration guardrails passed; M7 not run.'
