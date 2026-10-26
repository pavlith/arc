#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# Reuse the clean SQLite/TLS NATS harness and all M0-01–M0-05 regressions.
ARC_TEST_ACCESS=1 ARC_TEST_FABRIC=1 ARC_TEST_GATE=1 ARC_TEST_TASK=1 bash scripts/test-m0-02.sh
