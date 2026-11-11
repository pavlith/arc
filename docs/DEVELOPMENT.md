# Development

## Delivery policy
`main` is the active branch; `dev` remains as an older reference, not a second work queue. Do not force-push or rewrite history. Every change, including docs and cleanup, starts from a matching [GitHub Issue](https://github.com/pavlith/arc/issues); reuse it or create one with scope, acceptance and minimal checks. Issue labels own status, priority, milestone, type and area. No GitHub Projects, Notion or duplicated Markdown backlog.

Inspect actual code before implementing, keep changes scoped, update normative docs only if behavior/contract changes, run proportional checks, and attach results to the Issue. Use `Refs #N` for partial delivery and `Closes #N` only when all criteria are met. PRs require an Issue and explicit authorization. A direct commit/push requires the user's authorization; user chat is Russian, engineering material English. Never expose credentials in Git/logs/Issues.

## Local setup
Go 1.27+, C compiler/CGO (SQLite), Python 3 and the pinned `nats-server` for network smokes. Docker Compose is optional. Configuration, keys and owner-local databases are operator-provisioned; `.secrets/dev/` is ignored and contains disposable fixtures only.

```sh
make test-bootstrap
docker compose up -d nats
for owner in core task notify; do
  docker compose --profile tools run --rm "migrate-$owner"
done
```

For standalone owner migrations: `bash scripts/migrate.sh task /absolute/task.sqlite`; use `core`, `notify`, `files` or `pages` as appropriate. Run one migrator per owner database before traffic; Core startup needs signed policy and pinned trust roots. See [services](../services/README.md), [database](../sdk/database/README.md) and [Core](../services/core/README.md). These examples are not a production installer.

## Verification
Use `bash scripts/verify-changed.sh --base HEAD` (or `make verify`) after local code edits. It checks setup, Go formatting, changed Go service/package groups and relevant client workspaces. Shared SDK, test or Go dependency changes expand to `go test ./...`. The default comparison base is `origin/main`, then `HEAD^`/`HEAD`. This is **not** a complete security/CI check.

| Boundary | Additional check |
|---|---|
| Codex/config/docs only | `python3 scripts/check-agent-setup.py` plus local links, commands and claims |
| Bootstrap and migrations | `make m0-01-smoke`; fresh DB and replay |
| Identity / session / delegation | `make m0-02-smoke` |
| Access / ACL | `make m0-03-smoke` |
| Fabric / contracts | `make m0-04-smoke` |
| Gate / HTTP | `make m0-05-smoke` |
| Task / Notify end-to-end | `make m0-06-smoke` |
| Core startup | `make core-smoke` |
| Agent / Runtime | `make runtime-smoke` |
| Files / Pages owner-local acceptance | `bash scripts/test-files-live.sh` |
| Client types and UI | `npm --prefix client ci`, `npm --prefix client run check --workspace @arc/client`, `npm --prefix client run check --workspace ui` |

Run the security-relevant smoke whenever changing that boundary; never replace it with compilation alone. Use `go vet`, race checks and integration tests when relevant. The scheduled/manual `Arc full Go regression` runs `go test -race ./...`. Network/process smoke requires fixtures; ordinary `go test ./...` does not prove it. Full M7 fault/recovery, browser, load and compatibility matrices remain separate acceptance criteria. Log exact passed/failed/skipped checks, not aspirational coverage; avoid rerunning known passing unrelated checks.

## Browser, CLI and operator boundaries
The SvelteKit workspace is `ui`, TypeScript client `@arc/client`. Install at `client/` and configure Gate `ui_directory` to the built static output. Browser cookies/CSRF and CLI Bearer sessions are separate. CLI token, refresh and logout use exact `/api/v1/arc/cli/{token,refresh,logout}` endpoints without Origin or cookies; Identity's session-channel migration retains older sessions as legacy.

Provision Gate/Core service identities, explicit broker permissions, exact signed Identity/Task operations and approved Fabric artifacts before enabling routes. Task root listing does **not** imply root management or content permission; grants require fresh `access.grants.manage`, correct root/workspace and source-bound signed invocation. Workspace creation/invitations, managed Task roots and grants require separately approved operations; current manifests/handlers are authoritative over historical version-specific setup notes. Notify producer digests must be re-approved when a signed Task/Files/Pages artifact changes. Browser UI state cannot grant data access.

[Architecture](ARCHITECTURE.md) defines exact trust boundaries, [services](../services/README.md) locates APIs, and [realtime](REALTIME.md), [Files](FILES.md), [Notify](NOTIFY.md) specify their private transport/deployment contracts.

## Diagnostics
Correlate structured `arc rpc` records via `request_id` and `traceparent`; `arc event` uses event ID and trace rather than an RPC request ID. Logs include operation, duration/error category and safe delivery-lag metadata, never credentials, proofs, raw errors, payloads or idempotency keys. Trace context is diagnostic metadata, **not** caller identity or authorization evidence.
