#!/usr/bin/env python3
"""Install non-secret Codex profiles without replacing personal files."""
import argparse
import os
from pathlib import Path
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex-home", type=Path,
                        default=Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex"))
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1] / ".codex/profiles"
    profiles = [(source / f"{name}.config.toml", args.codex_home / f"{name}.config.toml")
                for name in ("fast", "deep")]
    # Check both destinations before writing either profile. Never read auth files.
    for template, destination in profiles:
        if destination.is_symlink() or (destination.exists() and
                (not destination.is_file() or destination.read_bytes() != template.read_bytes())):
            print(f"Profile conflict: {destination}; review it manually, no files replaced.", file=sys.stderr)
            return 1
    args.codex_home.mkdir(parents=True, exist_ok=True)
    for template, destination in profiles:
        if not destination.exists():
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as target:
                target.write(template.read_bytes())
        print(f"Profile ready: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
