---
name: arc-verify
description: Run focused Arc verification for a change, including Go, Svelte, schemas and security guardrails. Use after implementation or when reviewing a proposed change.
---

# Arc verification workflow

1. Determine changed scope with git diff and the active Issue's minimal-verification field.
2. For docs-only work, run python3 scripts/check-agent-setup.py and separately check local links/anchors, referenced paths/commands and language. Do not invoke builds or Go tests.
3. For code changes, run bash scripts/verify-changed.sh (optionally --base REF or --all). It includes pending local/untracked changes and tests affected modules. See docs/DEVELOPMENT.md §Verification for comparison bases, focused go vet and fixture-dependent smoke.
4. For altered auth, ACL, contract digest/route snapshots, migrations and event handlers, run their relevant focused M0 guardrail tests once they exist; do not defer their invariants to M7.
5. For changes to migrations, verify empty-DB startup and replay when the migration harness exists. Never claim coverage when a harness is absent.
6. Do not run the full M7 matrix during M0–M6. Do not repeat passing unrelated checks.
7. Report exact commands run, failures/skips and known deferred work. Never claim green checks without execution.
