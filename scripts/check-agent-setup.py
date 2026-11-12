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

def bounded_integer(value: object, maximum: int) -> bool:
    return type(value) is int and 0 < value <= maximum


if not bounded_integer(config.get("project_doc_max_bytes"), 4096):
    fail("project_doc_max_bytes must be between 1 and 4096")
if not bounded_integer(config.get("tool_output_token_limit"), 3000):
    fail("tool_output_token_limit must be between 1 and 3000")
if not bounded_integer(config.get("skills", {}).get("max_context_tokens"), 1600):
    fail("skill catalog budget must be between 1 and 1600")
for name in ("github", "openaiDeveloperDocs"):
    server = config.get("mcp_servers", {}).get(name)
    if not server or server.get("enabled") is not False:
        fail(f"{name} MCP must default to disabled")

for name, effort, output_limit in (("fast", "low", 2000), ("deep", "high", 6000)):
    profile = ROOT / f".codex/profiles/{name}.config.toml"
    try:
        parsed = tomllib.loads(profile.read_text(encoding="utf-8"))
        if parsed.get("model_reasoning_effort") != effort:
            fail(f"invalid reasoning profile: {profile.name}")
        if parsed.get("tool_output_token_limit") != output_limit or parsed.get("model_verbosity") != "low":
            fail(f"invalid output budget: {profile.name}")
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

doc_limit = config.get("project_doc_max_bytes")
if bounded_integer(doc_limit, 4096) and (ROOT / "AGENTS.md").stat().st_size > doc_limit:
    fail("AGENTS.md exceeds project_doc_max_bytes")
for filename, headings in {
    "ARCHITECTURE.md": ["## 3.", "## 4.", "## 5.", "## 6.", "## 7.", "## 10."],
    "REQUIREMENTS.md": ["### 2.1", "### 2.2", "### 2.3", "### 2.4", "## 7."],
}.items():
    document = (ROOT / "docs" / filename).read_text(encoding="utf-8")
    for heading in headings:
        if heading not in document:
            fail(f"missing routed heading {heading} in {filename}")

# Actionable documentation must name migrations that exist in this checkout.
# Numeric migration identifiers are distinct from UUIDs and generic baseline patterns.
registered = set()
for registry in (ROOT / "services").glob("*/migrations/sqlite.go"):
    registered.update(re.findall(r'ID:\s*"([0-9]{6}_[a-z0-9_]+)"', registry.read_text()))
documents = [ROOT / "README.md", ROOT / "AGENTS.md", *ROOT.glob("docs/*.md"),
             *ROOT.glob("services/**/README.md"), *ROOT.glob("sdk/**/README.md"),
             *ROOT.glob("client/*/README.md")]
for document in documents:
    for migration in set(re.findall(r"\b[0-9]{6}_[a-z][a-z0-9_]*\b", document.read_text())):
        if migration not in registered:
            fail(f"unknown migration {migration} in {document.relative_to(ROOT)}")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    sys.exit(1)
print(f"Codex setup OK: {len(expected)} skills ({len(local_skills)} Arc + {len(third_party_skills)} upstream), lock, TOML, docs routing, MCP off by default")
