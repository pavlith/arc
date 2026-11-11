#!/usr/bin/env python3
"""Validate local Markdown file and heading links without dependencies."""
from pathlib import Path
from urllib.parse import unquote
import re
import sys

root = Path(__file__).resolve().parents[1]
excluded = (".agents/skills/shadcn-svelte/",)
sources = sorted(p for p in root.rglob("*.md") if p.is_file()
                 and not any(str(p.relative_to(root)).startswith(x) for x in excluded)
                 and not any(x in p.parts for x in (".git", "node_modules", ".svelte-kit")))
errors = []
checked = 0
headings = {}

def anchors(path):
    if path not in headings:
        found = set()
        seen = {}
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"^ {0,3}#{1,6} +(.+)$", text, re.MULTILINE):
            h = re.sub(r"<[^>]*>", "", match.group(1)).replace("`", "").casefold()
            h = re.sub(r"[^\w\- ]", "", h).replace(" ", "-")
            duplicate = seen.get(h, 0)
            seen[h] = duplicate + 1
            found.add(f"{h}-{duplicate}" if duplicate else h)
        headings[path] = found
    return headings[path]

for source in sources:
    content = source.read_text(encoding="utf-8")
    content = re.sub(r"^\x60\x60\x60.*?^\x60\x60\x60", "", content, flags=re.MULTILINE | re.DOTALL)
    for match in re.finditer(r"!?\[[^\]\n]+\]\(([^)\n]+)\)", content):
        link = match.group(1).strip().strip("<>")
        path_part, _, fragment = link.partition("#")
        path_part = unquote(path_part.split("?", 1)[0])
        if not path_part and not fragment:
            continue
        if re.match(r"^[a-z][a-z0-9+.-]*:", path_part, flags=re.I) or path_part.startswith("//"):
            continue
        dest = (source.parent / path_part).resolve() if path_part else source.resolve()
        checked += 1
        if not dest.is_relative_to(root) or not dest.exists():
            errors.append(f"{source.relative_to(root)}: missing {link}")
        elif fragment and dest.suffix == ".md" and unquote(fragment) not in anchors(dest):
            errors.append(f"{source.relative_to(root)}: missing heading {link}")
if errors:
    print("Broken Markdown references:\n" + "\n".join(errors), file=sys.stderr)
    sys.exit(1)
print(f"Markdown links OK: {checked} local targets/headings in {len(sources)} files")
