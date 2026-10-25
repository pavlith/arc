#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
docker compose version >/dev/null
command -v go >/dev/null || { echo "go is required" >&2; exit 1; }

make bootstrap-dev

project=arc-m0-01-test
cleanup() {
  docker compose --project-name "$project" --profile tools down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

for pass in 1 2; do
  cleanup
  docker compose --project-name "$project" up --detach --wait postgres nats
  docker compose --project-name "$project" --profile tools run --rm migrate
  docker compose --project-name "$project" --profile tools run --rm migrate
  docker compose --project-name "$project" --profile tools run --rm rpc-smoke
  echo "M0-01 clean startup pass $pass succeeded"
done
