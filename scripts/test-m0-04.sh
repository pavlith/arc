#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
ARC_TEST_ACCESS=1 ARC_TEST_FABRIC=1 bash scripts/test-m0-02.sh
