#!/usr/bin/env python3
"""Validate Arc Codex files without third-party dependencies."""
from __future__ import annotations

from pathlib import Path
import json
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []

def fail(message: str) -> None:
    errors.append(message)

config_path = ROOT / ".codex/config.toml"
try:
    config = tomllib.loads(config_path.read_text(encoding="utf-8"))
except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
    fail(f"invalid config.toml: {exc}")
    config = {}

if not 0 < config.get("project_doc_max_bytes", 0) <= 8192:
    fail("project_doc_max_bytes must be between 1 and 8192")
if not 0 < config.get("tool_output_token_limit", 0) <= 6000:
    fail("tool_output_token_limit must be between 1 and 6000")
if config.get("skills", {}).get("max_context_tokens", 0) > 2000:
    fail("skill catalog budget too high")
for name in ("github", "openaiDeveloperDocs"):
    server = config.get("mcp_servers", {}).get(name)
    if not server or server.get("enabled") is not False:
        fail(f"{name} MCP must default to disabled")

for profile in (ROOT / ".codex/profiles").glob("*.toml"):
    try:
        parsed = tomllib.loads(profile.read_text(encoding="utf-8"))
        if parsed.get("model_reasoning_effort") not in ("low", "medium", "high"):
            fail(f"invalid reasoning profile: {profile.name}")
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        fail(f"invalid profile {profile.name}: {exc}")

skill_root = ROOT / ".agents/skills"
local_skills = {"arc-issue", "arc-contract", "arc-verify", "arc-go-service", "arc-svelte-ui"}
third_party_skills = {"shadcn-svelte"}
expected = local_skills | third_party_skills
actual = {p.name for p in skill_root.iterdir() if p.is_dir()} if skill_root.is_dir() else set()
if actual != expected:
    fail(f"skill directories mismatch: {sorted(actual ^ expected)}")
for name in sorted(expected):
    path = skill_root / name / "SKILL.md"
    if not path.is_file():
        fail(f"missing {path.relative_to(ROOT)}")
        continue
    content = path.read_text(encoding="utf-8")
    front = re.match(r"\A---\r?\n(.*?)\r?\n---\r?\n", content, flags=re.S)
    if not front:
        fail(f"missing skill frontmatter: {name}")
        continue
    fields = dict(re.findall(r"^(name|description):\s*(.+)$", front.group(1), flags=re.M))
    if fields.get("name") != name or len(fields.get("description", "")) < 24:
        fail(f"invalid skill metadata: {name}")

# The vendored UI skill remains managed by the skills CLI, not copied into Arc skills.
lock_path = ROOT / "skills-lock.json"
try:
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
except (OSError, ValueError) as exc:
    fail(f"invalid skills-lock.json: {exc}")
    lock = {}
installed = lock.get("skills", {}).get("shadcn-svelte")
if not isinstance(installed, dict) or installed.get("source") != "huntabyte/shadcn-svelte" or installed.get("skillPath") != "skills/shadcn-svelte/SKILL.md":
    fail("shadcn-svelte lock entry source/path mismatch")
if set(lock.get("skills", {})) != third_party_skills:
    fail("unexpected external skills in skills-lock.json")
vendor = skill_root / "shadcn-svelte"
for relative in ("cli.md", "customization.md", "rules/forms.md", "rules/composition.md", "rules/icons.md", "rules/styling.md"):
    if not (vendor / relative).is_file():
        fail(f"shadcn-svelte reference missing: {relative}")

if (ROOT / "AGENTS.md").stat().st_size > config.get("project_doc_max_bytes", 8192):
    fail("AGENTS.md exceeds project_doc_max_bytes")
for filename, headings in {
    "ARCHITECTURE.md": ["## 3.", "## 4.", "## 5.", "## 6.", "## 7.", "## 10."],
    "REQUIREMENTS.md": ["### 2.1", "### 2.2", "### 2.3", "### 2.4", "## 7."],
}.items():
    document = (ROOT / "docs" / filename).read_text(encoding="utf-8")
    for heading in headings:
        if heading not in document:
            fail(f"missing routed heading {heading} in {filename}")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    sys.exit(1)
print(f"Codex setup OK: {len(expected)} skills ({len(local_skills)} Arc + {len(third_party_skills)} upstream), lock, TOML, docs routing, MCP off by default")
