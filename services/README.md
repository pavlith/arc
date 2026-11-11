# Arc services

| Component | Current surface | Remaining product scope |
|---|---|---|
| `core/` | `cmd/arc-core`, owner SQLite, private RPC and signed approval for Identity profile, workspace lifecycle and invitations, member/group management and administrator provisioning | Runtime policy and adapter #13 |
| `gate/` | `cmd/arc-gate`, browser cookies, CLI tokens, signed domain routes, Identity routes and optional UI assets | WS/DAV adapters |
| `task/` | `cmd/arc-task`, workspace create/get/list and title edits for own tasks, roots and atomic replay/outbox | Projects and views #10 |
| `notify/` | `cmd/arc-notify`, internal inbox/notification and persisted fake outbound intents | User inbox/subscriptions, realtime and real channels #9/#12 |
| `agent/` | `cmd/arc-agent`, private node RPC, durable journal, restricted systemd and Docker drivers | Admin/Gate/UI, live Docker acceptance, LXD and Core reconcile #13 |

The first Svelte workspace and Task view is in `client/web/`. Historical reports of
unavailable implementations do not extend this table. [Core startup](core/README.md) uses strict local configuration,
explicit migrations and signed policy. Every new implementation starts with its Issue.

## Ownership and startup

Domain services use `sdk/service.Compose` and typed modules. Core uses privileged
private bootstrap transport and direct Go interfaces. Each SQL owner supplies its
own models and ordered migrations. [Database rules](../sdk/database/README.md) cover
CGO, file permissions, transactions and backups.

Task/Notify require NATS/JetStream, a provisioned Core/Gate, registered service
accounts and signed approved installations. Example configs:
[Task](../deploy/task/config.example.json), [Notify](../deploy/notify/config.example.json).
These commands are not a complete platform installer:

```sh
bash scripts/migrate.sh task /absolute/task.sqlite
bash scripts/migrate.sh notify /absolute/notify.sqlite
go run ./cmd/arc-task -config /path/to/task.json
go run ./cmd/arc-notify -config /path/to/notify.json
```

Each process receives its own config, absolute database path/data directory and
NATS credentials. Service Ed25519 seed is 32 raw bytes with mode 0600; Core public
key is a JSON base64 string. Never pass Core/operator private keys to a domain
service or mount another owner's database. `deploy/docker/Dockerfile.domain`
accepts `SERVICE=task|notify`.

Task artifact: `task/api/v1/contract/`; Notify: `notify/api/v1/contract.go`.
`fabric.Core.Approve` requires operator signature and exact identity/deployment.
Notify pins Task provider/digest/subject/durable and uses operator-managed recipient
addressing. The proof fixture provisions Task/DLQ streams; it is not an operator
installation API.

## Task proof API

```http
POST /api/v1/task/workspaces/{workspace_id}/roots/{acl_root_id}/tasks
Authorization: Bearer <access token>
Idempotency-Key: <stable client key>
Content-Type: application/json

{"title":"Proof"}
```

GET the collection with `?limit=10` lists up to 100 own permitted tasks; GET
`.../tasks/{task_id}` reads one. Signed route bindings and domain DB establish
root/workspace; online Access applies on execution and replay. Internal
`task.roots.grants` exposes root-scoped grant/revoke through the approved Gate
route below. Task mutation/audit/result/outbox and
Notify inbox/notification/intent are atomic. Fake delivery preserves provider key;
external delivery has no exactly-once guarantee.

Run `make m0-06-smoke`; dependencies and limits are in
[verification](../docs/DEVELOPMENT.md#verification).

## Task permission API

```http
POST /api/v1/task/workspaces/{workspace_id}/roots/{acl_root_id}/grants
Authorization: Bearer <access token>
Idempotency-Key: <stable client key>
Content-Type: application/json

{"action":"task.read","principal_kind":"group","principal_id":"<group UUID>"}
```

The caller needs `access.grants.manage` on the root. Supported principals are
`user`, `role` and `group`; supported actions are `task.read` and `task.create`.
For a role principal, use `owner`, `admin`, `member` or `guest` as `principal_id`.
Revoke at the same URL with `{"grant_id":"<grant UUID>"}`. Access verifies that
the grant belongs to the root from the URL. The response includes the grant ID,
state and policy revision. Browser callers use session cookies plus Origin/CSRF
instead of Bearer.

GET the same URL with `?limit=100` to list direct grants; follow `next_cursor`
using `&cursor=<grant UUID>`. The required limit is 1–100. The caller must have
`access.grants.manage` even to read this list. The response contains `resource_id`,
`grants`, `policy_revision` and optional `next_cursor`; entries expose grant ID,
principal kind/ID, action and optional expiry. Revoked/expired grants and implicit
or inherited rights are excluded. This lists stored grants rather than effective
permissions. An empty list is returned as `[]`.

This requires signed replacement approvals and updated Task/Notify deployment;
see [development](../docs/DEVELOPMENT.md#browser-and-cli-setup). Deploy the updated
Core first so it accepts the root-bound revoke request.

## Task Team and workflow APIs

Task 0.1.0 adds business Teams and workflow statuses inside existing active Task
roots. Apply Task migration `000002_teams` explicitly before starting the new
binary. Existing tasks, IDs, audit/replay and pending outbox rows are retained.
Team membership/privacy is not implied by the Team record: the root's ACL is the
access boundary. Independently private Teams need independent roots.

All paths below are relative to
`/api/v1/task/workspaces/{workspace_id}/roots/{acl_root_id}`:

| Method/path | Behavior |
|---|---|
| POST `/teams` | Create a Team and six default workflow statuses atomically |
| GET `/teams?limit=100&cursor=<uuid>` | List active Teams; `limit` is required; follow `next_cursor` |
| GET `/teams/{team_id}` | Read one active Team |
| PATCH `/teams/{team_id}` | Replace name/description/color using current `revision`; key is immutable |
| POST `/teams/{team_id}/archive` | Archive using current `revision`; retain Team and statuses |
| GET `/teams/{team_id}/statuses` | List active statuses by position/ID |
| POST `/teams/{team_id}/statuses` | Create a status, optionally make it the default |
| PATCH `/teams/{team_id}/statuses/{status_id}` | Update status fields using current `revision` |
| POST `/teams/{team_id}/statuses/{status_id}/archive` | Archive a nondefault status using current `revision` |

Team create accepts `name`, uppercase `key` (2–12 ASCII letters/digits, starting
with a letter), optional `description` and optional `color` (empty or `#RRGGBB`).
Keys are unique per workspace, including archived Teams. Team mutations require
`access.grants.manage`; reads require `task.read`. Path-bound scope/IDs must not
also occur in the body. All writes require stable `Idempotency-Key`; browser
mutations require Origin/CSRF. Responses include ID, scope, timestamps, revision
and archived flag. Archived Teams deny subsequent Team/workflow commands and
replay; there is no implicit unarchive.

Status fields are `name`, `category`, `color`, `position` and `is_default`. Categories
are `backlog`, `todo`, `in_progress`, `in_review`, `done`, `cancelled`. There are at
most 100 active statuses per Team and exactly one default. Setting another
default increments the former default's revision; refresh the list after changes.
A default cannot be archived or directly unset. Updates replace the full mutable
status representation, including `is_default`.

Every mutation commits domain state, product audit, replay result and an
`evt.task.catalog.changed.v1` identifier/revision hint together. The hint contains
no content; a subscriber must reauthorize a subsequent fetch. Approve exact
`task.teams.*`/`task.statuses.*` operation IDs and their downstream Access `check`
actions through the normal signed installation workflow. Add the new event
subject to Task's broker publish permissions and the applicable JetStream stream.
Replace the Task artifact/routes and update Notify's producer digest; Notify's
task-created event schema and subscription subject are unchanged.

The model/import/personal-task decision is in [Task product model](../docs/TASK-MODEL.md).

## Runtime

Core Control requires explicit live `RuntimeControlPolicy` and a snapshot signing
key; it defaults off. `RuntimeNodeRPC=true` binds only node inventory/pull/report,
not management. New node enrollment requires Core restart; disable/key/policy
revocation is online. Owner-local interfaces do not supply remote authentication.
The administrative policy/Gate adapter, Core reconciler/hint publisher and full
health/log APIs are missing. See [architecture §7](../docs/ARCHITECTURE.md#7-runtime-control-and-infrastructure-agent)
and [Agent operations](agent/README.md). Run `make runtime-smoke` for the private
protocol and standalone Agent lifecycle; live host effects are a separate check.
