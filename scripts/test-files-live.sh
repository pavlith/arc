#!/usr/bin/env bash
# Isolated live Files acceptance; no production credentials or databases.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
for tool in go nats-server; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }
done
# Separate migrator processes verify empty startup and reopened-DB replay.
python3 - <<'PYTHON'
import pathlib, subprocess, tempfile
with tempfile.TemporaryDirectory(prefix="arc-files-migrate.") as scratch:
    database = str(pathlib.Path(scratch) / "files.sqlite")
    for _ in range(2):
        subprocess.run(["bash", "scripts/migrate.sh", "files", database], check=True)
PYTHON
ARC_FILES_LIVE=1 go test -count=1 -timeout 360s -run '^TestFilesLive$' -v ./services/files
