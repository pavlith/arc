#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
docker compose version >/dev/null
command -v go >/dev/null || { echo "go is required" >&2; exit 1; }

make test-bootstrap

project=arc-m0-01-test
compose=(docker compose -f compose.yaml -f test/compose.yaml --project-name "$project")
cleanup() {
  "${compose[@]}" --profile tools down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

for pass in 1 2; do
  cleanup
  "${compose[@]}" up --detach --wait nats
  for owner in core task notify; do
    "${compose[@]}" --profile tools run --rm "migrate-$owner"
  done
  for owner in core task notify; do
    "${compose[@]}" --profile tools run --rm "migrate-$owner"
  done
  "${compose[@]}" --profile tools run --rm rpc-smoke
  echo "M0-01 clean startup pass $pass succeeded"
done
