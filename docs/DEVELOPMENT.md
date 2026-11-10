# Development

## Issue-first delivery

Every change starts with a GitHub Issue, including documentation, cleanup,
refactoring and follow-up fixes. Before editing, select an existing Issue that
matches the request or create one with scope, acceptance, references and minimal
verification. Read the current implementation; historical reports alone are not
proof. A chat request authorizes work but does not replace its Issue record.

1. Confirm scope and dependencies; set `status: in-progress` and assign the executor.
2. Implement the smallest coherent change. Update normative docs when semantics change.
3. Run proportional checks and record actual results and deferred coverage.
4. Link the Issue from the PR. Use `Closes #N` only for fully satisfied scope;
   use `Refs #N` for partial/draft work. Every PR must reference an open repository Issue.
5. Move to `status: review` when a reviewable delivery exists. Close only after
   delivery/acceptance; local files or old checked boxes do not prove publication.

Work on `dev`; `main` is stable. Do not commit, push, publish or open a PR without
a request that includes it. Keep unrelated user changes. User chat is in Russian
unless the user chooses another language. Docs, Issues, PRs, templates, code
comments, UI text and commit messages use English.

## Sources of truth

- Issues: actionable work, acceptance and verification evidence.
- Labels: status, priority, milestone, area and type; no duplicate Projects/Notion/backlog.
- [Requirements](REQUIREMENTS.md): product scope and requirement IDs.
- [Architecture](ARCHITECTURE.md): protocols, ownership and durable decisions.

Issue forms seed priority/milestone labels at creation. Later label changes are
authoritative; editing a body must not reset them. `blocked` is independent of
status and records an actual unresolved dependency/decision. The triage workflow
validates PR references, sets draft/review status and maps closed/reopened Issues
to done/backlog. It must not treat a partial Issue as completed.

Definitions: `.github/labels.json`; synchronization: `Sync labels` on dev/main or
manual dispatch. Existing label names remain stable; descriptions use English.
Useful queues: [ready](https://github.com/pavlith/arc/issues?q=is%3Aissue+is%3Aopen+label%3A%22status%3A+ready%22),
[in progress](https://github.com/pavlith/arc/issues?q=is%3Aissue+is%3Aopen+label%3A%22status%3A+in-progress%22),
[review](https://github.com/pavlith/arc/issues?q=is%3Aissue+is%3Aopen+label%3A%22status%3A+review%22).

## Local environment

Require Go 1.27+, a C compiler and CGO for SQLite. Native network checks require
Python 3 and `nats-server` matching `compose.yaml`; the Compose smoke needs Docker
Compose and daemon access. Fixtures do not use production credentials.

```sh
make test-bootstrap
docker compose up -d nats
for owner in core task notify; do
  docker compose --profile tools run --rm "migrate-$owner"
done
```

Ignored `.secrets/dev/` contains generated local fixtures. NATS publishes only
loopback ports. Each SQL owner has its own volume. `compose.yaml` provides NATS
and explicit migrators; `test/compose.yaml` adds the RPC/JetStream client.
`make m0-01-smoke` uses an isolated project, runs twice from clean volumes and
removes those volumes. This infrastructure setup is not a complete product installer.

Outside Compose: `bash scripts/migrate.sh task /absolute/task.sqlite`. Create the
owner directory first; run migrations before traffic with one migrator per file.
See [database](../sdk/database/README.md) and [services](../services/README.md).
Standalone Core provisioning is tracked in #15; no production bootstrap command
should be inferred from historical Issue reports.

## Verification

| Command | Coverage |
|---|---|
| `python3 scripts/check-agent-setup.py` | Codex config, skill metadata/lock and routed headings; safe for docs-only work |
| `make verify` | Codex setup, changed Go formatting and root-module tests |
| `make m0-01-smoke` | Two clean Compose starts, migration replay and RPC/JetStream |
| `make m0-02-smoke` | Native SQLite/RPC plus Identity invocation/proof/session guards |
| `make m0-03-smoke` | Also Access and negative ACL cases |
| `make m0-04-smoke` | Also Fabric/contract boundaries |
| `make m0-05-smoke` | Also HTTPS Gate, cookies/Bearer, CSRF/CORS and signed routes |
| `make m0-06-smoke` | Above native suites plus separate Task/Notify processes and fake delivery |
| `make runtime-smoke` | Private node RPC, fake driver and standalone Linux Agent lifecycle |

`make verify` selects changes relative to `origin/dev` (fallback: `HEAD^`, then
`HEAD`) and includes local/untracked files. Use
`bash scripts/verify-changed.sh --base HEAD` to check only changes since HEAD.
It checks formatting and runs tests for affected Go modules; it does not replace
`go vet`, fixture-dependent smoke or the documentation checks below. Existing
unrelated Go edits can trigger module tests, so docs-only work should use the
setup command directly.

For transport changes, run `go test -race ./sdk/transport ./sdk/rpc ./sdk` and
`make m0-06-smoke` for broker credentials, contract approval, routes and the
Task/Notify path. Use focused package tests and `go vet` for other substantial Go
changes; CI's SDK checks also include `go test -race ./sdk/...`,
`go vet ./sdk/...` and `go build ./sdk/...`.

Scripts create and clean temporary SQLite/TLS/NKey fixtures. Migration checks
cover empty databases and replay. M0-06 uses real Identity/Access/Fabric/Gate and
domain processes; only the outbound provider is fake. `go test ./...` without
fixtures skips network/process integration. `ARC_TEST_TASK_ONLY=1 make m0-06-smoke`
is for local debugging; final acceptance/CI omits the flag.

For documentation-only changes, check local links/anchors, referenced paths and
commands, terminology/language and Codex routing; do not run builds or Go tests.
The setup checker does not validate Markdown links, language or implementation
claims. Workflow changes require relevant syntax/behavior checks. Do not repeat
successful unrelated checks. Deferred scenarios belong in the owning Issue with
ID, preconditions and expected result. Full M7 recovery/load/client/browser and
permission matrices are not implied by focused smoke success.

## Agent workflow

Read `AGENTS.md`, applicable skill and only relevant normative sections. Project
settings live in `.codex/`; local skills in `.agents/skills/`. See [Codex](CODEX.md).
Credentials remain in 1Password/local secret files, never Git, logs or Issues.
