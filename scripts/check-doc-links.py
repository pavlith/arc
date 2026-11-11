#!/usr/bin/env python3
"""Check local Markdown link targets with no external dependencies."""
from pathlib import Path
from urllib.parse import unquote
import re
import sys

root = Path(__file__).resolve().parents[1]
sources = [*sorted((root / "docs").glob("*.md"))]
sources += [root / p for p in ("AGENTS.md", "README.md", "services/README.md", "client/web/README.md")]
bad = []
checked = 0
for source in sources:
    content = source.read_text(encoding="utf-8")
    for match in re.finditer(r"!?(?:\[[^\]\n]+\])\(([^)\n]+)\)", content):
        link = match.group(1).strip().strip("<>")
        target = unquote(link.split("#", 1)[0].split("?", 1)[0])
        if not target or re.match(r"^[a-z]+:", target, re.IGNORECASE):
            continue
        checked += 1
        dest = (source.parent / target).resolve()
        if not dest.is_relative_to(root) or not dest.exists():
            bad.append(f"{source.relative_to(root)}: {link}")
if bad:
    print("Broken local Markdown links:\n" + "\n".join(bad), file=sys.stderr)
    sys.exit(1)
print(f"Docs links OK: {checked} local targets in {len(sources)} files")
