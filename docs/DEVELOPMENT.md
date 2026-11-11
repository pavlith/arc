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

The repository uses exactly two branches: `dev` for authorized development and
`main` for tested stable releases. Do not create temporary or feature branches.
Merged work must not leave extra refs; promote release commits from `dev` to
`main` only after relevant checks pass (Refs #23).

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
[Standalone Core](../services/core/README.md) requires operator-provisioned keys,
signed bootstrap policy and explicit migrations; product provisioning remains #9.

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
| `make m0-06-smoke` | Above native suites plus separate Task/Notify processes, correlated RPC/event diagnostics and fake delivery |
| `make runtime-smoke` | Race-tested Runtime/Agent guardrails, correlated private node RPC, fake driver and standalone Linux Agent lifecycle |
| `make core-smoke` | Standalone Core, external migrations, signed login, policy denials, restart and SIGTERM/cancellation cleanup |

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

## Correlated diagnostics

Executable services use structured JSON logs. Join `arc rpc` records by
`request_id` and `traceparent` across Gate-originated and nested SDK calls,
including authorization and ACL checks. Agent reconciliation creates a root for
each online round; `arc reconcile` uses the same identifiers as its Core calls.
Diagnostics accept bounded ASCII request IDs and valid version 00 traceparent
values; malformed values are omitted. Trace context is diagnostic metadata,
not a verified actor, permission, replay key or new tracing transport.

RPC and reconciliation records include `operation`, `duration_ms` and a fixed
`error_code` (empty on success). `arc event` records include `event_id`,
`traceparent`, `kind` (`publish` or `consume`) and `delivery_lag_ms`, measured
from occurrence to broker publish result or inbox processing result. Event
correlation uses trace and event IDs; the event envelope has no RPC request ID.
A publish record reports the broker result, while consume reports the inbox
transaction result, including safe redelivery. These records do not certify an
external provider effect. No payloads, credentials, proof bytes, idempotency
keys or raw internal errors are logged by these diagnostics.

Run `make core-smoke`, `make runtime-smoke` and `make m0-06-smoke` for the
standalone Core lifecycle, fake-Agent/runtime denials and correlated vertical
path. Core startup does not enable Runtime management/node RPC; Runtime smoke
uses a trusted test policy and fake host effects. Live drivers and complete
health reporting remain #13; M7 is deferred.

## Browser and CLI setup

Install the npm workspaces with `npm --prefix client ci` and build the
SvelteKit app with `npm --prefix client run build --workspace @arc/web`.
Set Gate's `ui_directory` to the absolute path to `client/web/dist` and open the
configured HTTPS origin. Gate serves the static page at `/`, its JavaScript and
CSS under `/_app/immutable/` and the SvelteKit version at `/_app/version.json`.
Gate's CSP allows the route announcer's fixed style by hash. Check browser
startup and CSP when upgrading SvelteKit.
The web app imports `@arc/client` from `client/ts` for same-origin requests with
browser cookies. The client reads the CSRF cookie for mutations and the web app
sends an idempotency key for Identity and Task commands.

Apply Core migrations before starting the updated Core. The session-channel
migration keeps existing sessions as `legacy`. New browser sessions cannot issue
Bearer credentials. CLI clients POST email/password to `/api/v1/arc/cli/token`,
rotate with a `refresh_token` JSON field at `/api/v1/arc/cli/refresh`, and revoke
the session with its Bearer token at `/api/v1/arc/cli/logout`. These endpoints
require requests without Origin or cookies.

In the signed Core bootstrap policy, allow the provisioned Gate account the
exact `identity.v1.product.*` operations it needs with audience `identity/v1`
and actor kind `bootstrap`. The Task UI uses `profile`, `workspaces.list` and
`task_roots.list`. Workspace member/group writes also need a current owner or
administrator role and an `Idempotency-Key`. User provisioning additionally
requires the user's ID in the signed `admin_users` list. Core remains the
authority for every write and returns only readable Task roots to the UI.

Allow `workspaces.create` and `invitations.create`, `invitations.revoke` and
`invitations.accept` under the same exact Identity operation prefix to enable
workspace creation and invitations in the UI. Owners and administrators may
invite a provisioned account as a member or guest. Share the link with the
recipient, who signs in with the specified email and accepts within 48 hours.
The token travels in a URL fragment and Core persists only its hash. The
optional `workspaces.archive` operation lets an owner archive a workspace by
posting its `workspace_id` to `/api/v1/arc/identity/workspaces/archive`.

Task editing needs the signed `task.tasks.edit` operation, online `task.create`
permission on the root and matching `created_by`. `PATCH` accepts `title` and
`expected_updated_at`; the writer transaction commits the edit, audit and replay
record together. Approve the updated Task artifact and a Notify installation
pinned to the new Task digest through the existing Fabric replacement workflow.
Include the exact `rpc.task.v1.tasks.edit` subject in Task broker permissions.
New workspaces receive a corporate ACL root. Task roots still require the existing
operator setup.

Task 0.0.8 also exposes `task.roots.grants` as POST
`/api/v1/task/workspaces/{workspace_id}/roots/{acl_root_id}/grants`. Allow the
exact Gate → Task operation for actor kind `user`, action
`access.grants.manage`. The Task provider needs Access `check` for that action,
and `access.v1.grants.add`/`access.v1.grants.revoke` for `task.read`/`task.create`
with signed downstream provenance `task/v1:task.roots.grants`. Keep existing
Task operation approvals; do not replace them with wildcard authority.

Deploy updated Core before updated Task: Task now binds downstream revoke to
`resource_id`. Approve the new Task artifact and update the Notify subscription
approval/configuration to the new producer digest. Notify pins the Task artifact
even though this change adds no event. Regenerate the signed route snapshot via
the normal Fabric replacement workflow; editing the local manifest alone does
not enable the endpoint in an existing deployment. Include
`rpc.task.v1.roots.grants` in the appropriate Gate publish/Task subscribe broker
permissions, and the existing Access grant RPC permissions for Task. API request
and response examples are in [services](../services/README.md#task-permission-api).

## Agent workflow

Read `AGENTS.md`, applicable skill and only relevant normative sections. Project
settings live in `.codex/`; local skills in `.agents/skills/`. See [Codex](CODEX.md).
Credentials remain in 1Password/local secret files, never Git, logs or Issues.
