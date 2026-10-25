---
name: arc-verify
description: Run focused Arc verification for a change, including Go, Svelte, schemas and security guardrails. Use after implementation or when reviewing a proposed change.
---

# Arc verification workflow

1. Determine changed scope with git diff and the active Issue's minimal-verification field.
2. Run bash scripts/verify-changed.sh (optionally --base REF or --all). The script validates Codex configuration and checks only existing affected code surfaces.
3. For altered auth, ACL, contract digest/route snapshots, migrations and event handlers, run their relevant focused M0 guardrail tests once they exist; do not defer their invariants to M7.
4. For changes to migrations, verify empty-DB startup and replay when the migration harness exists. Never claim coverage when a harness is absent.
5. Do not run the full M7 matrix during M0–M6. Do not repeat passing unrelated checks.
6. Report exact commands run, failures/skips and known deferred work. Never claim green checks without execution.
