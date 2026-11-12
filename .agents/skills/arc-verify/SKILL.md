---
name: arc-verify
description: Run focused Arc verification for a change, including Go, Svelte, schemas and security guardrails. Use after implementation or when reviewing a proposed change.
---

# Proportional verification
1. Use `git diff` and the Issue's minimum checks. Run `bash scripts/verify-changed.sh --base HEAD` for code edits; docs-only require setup + links/claims checks.
2. Explicitly add the relevant M0 Identity/ACL/Fabric/Gate, migration replay, Files/Pages or realtime checks for touched trust boundaries. Inspect failures, never silently skip them.
3. Prefer targeted Go service tests; SDK/dependency changes expand to the root module. Run `go vet`/race tests where justified; M7 recovery/load/compatibility are separate.
4. Server manifests/schemas require generated client checks; relevant UI edits run unit checks. Verifier/profile edits also run `python3 scripts/test-devex.py`. Use the boundary matrix in `docs/DEVELOPMENT.md#verification`; report pass/fail/skip without redundant reruns.
