#!/usr/bin/env bash
# M0-03 runs the isolated PostgreSQL/NATS harness plus Identity regression.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
ARC_TEST_ACCESS=1 bash scripts/test-m0-02.sh
