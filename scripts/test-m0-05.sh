#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
(go test -race -count=1 -run "TestSnapshot|TestReserved|TestSafe|TestRouteBundle" ./services/gate/modules/http ./services/core/modules/fabric)
ARC_TEST_ACCESS=1 ARC_TEST_FABRIC=1 ARC_TEST_GATE=1 bash scripts/test-m0-02.sh
