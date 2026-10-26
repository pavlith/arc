#!/usr/bin/env bash
# Explicit owner migration; no service startup runs migrations implicitly.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
if [[ $# != 2 ]]; then
  echo "Usage: $0 {core|task|notify} /absolute/path/to/owner.sqlite" >&2
  exit 2
fi
exec go run ./cmd/arc-sqlite-migrate -service "$1" -db "$2"
