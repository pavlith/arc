# Arc services

| Component | Current surface | Remaining product scope |
|---|---|---|
| `core/` | `cmd/arc-core`, owner SQLite, private RPC and signed approval for Identity profile, workspace lifecycle and invitations, member/group management and administrator provisioning | Runtime policy and adapter #13 |
| `gate/` | `cmd/arc-gate`, browser cookies, CLI tokens, signed domain routes, Identity routes and optional UI assets | WS/DAV adapters (shared realtime protocol in docs/REALTIME.md) |
| `task/` | `cmd/arc-task`, scoped Teams/workflow, shared work items, projects/labels, comments/history, subtasks/links, atomic bulk updates, saved-view APIs and atomic replay/outbox | Triage, UI adaptation and live template acceptance #10 |
| `files/` | `cmd/arc-files`, owner SQLite, signed folder/file/upload metadata, hidden mTLS stream receiver, live ACL and bounded chunks, post-commit cleanup and metadata outbox | Operator installation, live certificate/Core acceptance, production installation and large-transfer acceptance #29 |
| `notify/` | `cmd/arc-notify`, personal Inbox/subscriptions and persisted fake outbound intents | Realtime and real channels #9/#12 |
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
[Files](../deploy/files/config.example.json), [Task](../deploy/task/config.example.json), [Notify](../deploy/notify/config.example.json).
These commands are not a complete platform installer:

```sh
bash scripts/migrate.sh task /absolute/task.sqlite
bash scripts/migrate.sh notify /absolute/notify.sqlite
bash scripts/migrate.sh files /absolute/files.sqlite
go run ./cmd/arc-task -config /path/to/task.json
go run ./cmd/arc-notify -config /path/to/notify.json
go run ./cmd/arc-files -config /path/to/files.json
```

Each process receives its own config, absolute database path/data directory and
NATS credentials. Service Ed25519 seed is 32 raw bytes with mode 0600; Core public
key is a JSON base64 string. Never pass Core/operator private keys to a domain
service or mount another owner's database. `deploy/docker/Dockerfile.domain`
accepts `SERVICE=task|notify|files`.

Files artifact: `files/api/v1/contract/` (35 public metadata/grant/avatar + 4 hidden byte operations).
The Files owner must apply migrations `000001_files` and
`000002_upload_cleanup` and `000003_personal_roots` with `bash scripts/migrate.sh files /absolute/files.sqlite`,
set a private absolute `storage_path`, and install its signed Fabric contract
and NATS publisher permissions. The internal `AppendChunk` and `StreamDownload` primitives require a verified
identity context and live root authorization. Gate now has an **opt-in**
signed mTLS streaming adapter, configured only through the separate Gate
and Files private TLS credentials; see [Files](../docs/FILES.md). This does not
constitute a live production deployment or multi-user acceptance.

Task artifact: `task/api/v1/contract/`; Notify: `notify/api/v1/contract/`.
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

## Shared Task work-item APIs

Task 0.2.0 adds the product work-item projection without rewriting legacy tasks.
Apply Task migration `000003_work_items` after `000002_teams`, and deploy updated
Core for user reference validation before Task/Notify. All paths below are
relative to `/api/v1/task/workspaces/{workspace_id}/roots/{acl_root_id}`:

| Method/path | Authority and behavior |
|---|---|
| POST `/work` | `task.create`; create in a Team, default its status and allocate a stable Team-key identifier |
| GET `/work/{task_id}` | `task.read`; read a shared product task or legacy task projection |
| GET `/work?limit=100` | `task.read`; list shared tasks in UUID order, following `next_cursor` |
| PATCH `/work/{task_id}` | `task.create`; replace product fields with current `revision` and `expected_updated_at` |
| POST `/work/{task_id}/archive` | `task.delete`; archive a product task with both concurrency checks; return metadata only |

Create/update fields are `title`, `team_id`, optional `status_id` (defaults to the
Team's default), `description` (plain text/Markdown, at most 60,000 bytes),
`priority` (0–4), optional `due_date` (RFC3339), `sort_order` (0–1e12) and up to 20
unique `assignee_ids`. Updates replace all mutable fields; omission clears an
optional value. The Team/status must belong to the same active root/workspace.
Assigning a legacy task to a Team preserves its Task ID and title history.
The JSON-encoded mutable representation is additionally capped at 160,000 bytes
to bound responses even when JSON escaping expands user text. Team list pages
also honor a response-size budget; follow their cursor even after a short page.

List filters are optional `team_id`, `status_id`, `assignee_id`, `priority`,
`search` (literal title/description substring, ASCII case-insensitive), and UUID
`cursor`. `limit` is required, 1–100. Pages are independently snapshot-consistent
and may be shorter to respect the RPC size budget. Always follow `next_cursor`.
Descriptions are returned as data and must be safely rendered by clients.

Granting `task.create` to a root permits shared product edits under the new
operation approvals; it does not change the creator-only legacy edit behavior.
For nonempty assignees, Task needs exact Access
`access.v1.principals.validate_users` approval with actor action `task.create`
and downstream sources `task/v1:task.work.create` / `task/v1:task.work.update`.
Core checks active workspace membership and target `task.read` on the same root;
there is no cross-owner SQL access. The operation returns no profile information.

Approve exact new Work operations with their table actions and corresponding
downstream Access `check` actions (including `task.delete` for archive). Update
Task subjects/routes, signed artifact approval and Notify producer digest.
`evt.task.catalog.changed.v1` now also carries `entity_kind=work`, while new tasks
still publish the unchanged `evt.task.task.created.v1` event. Domain data,
assignees, audit, outbox and command result commit atomically. Team/status archive
responses now return identifier/revision metadata only, avoiding content exposure
to management-only callers. No UI changes are included.

## Projects, labels and business Team membership

Task 0.3.0 requires explicit migration `000004_projects_labels`. Paths below use
the same workspace/root prefix as the Work APIs:

| Method/path | Behavior |
|---|---|
| POST `/projects`, PATCH `/projects/{project_id}` | Create/replace project fields; `task.create`; updates require `revision` |
| GET `/projects/{project_id}`, GET `/projects?limit=100` | Read project metadata or page active projects; `task.read`; optional Team filter `team_id` |
| POST `/projects/{project_id}/archive` | Archive by revision; `task.delete`; metadata-only response |
| POST `/labels`, PATCH `/labels/{label_id}` | Create/replace label name/color; `access.grants.manage`; updates require `revision` |
| GET `/labels/{label_id}`, GET `/labels?limit=100` | Read label metadata or page active labels; `task.read` |
| POST `/labels/{label_id}/archive` | Archive by revision; `access.grants.manage`; metadata-only response |
| GET `/teams/{team_id}/members?limit=100` | Page business members by user UUID; `task.read` |
| POST `/teams/{team_id}/members` | Add `user_id` with current Team `revision`; `access.grants.manage` |
| POST `/teams/{team_id}/members/{user_id}/remove` | Remove using current Team `revision`; `access.grants.manage` |

Project fields are `name`, `description`, `color`, `status` (planned/active/paused/
completed/cancelled; default planned), optional immutable `team_id`, `start_date`
and `due_date`. Start cannot be after due. Updates replace mutable fields and
must preserve the Team ID. Lists require limit 1–100 and optional UUID cursor;
project pages may stop early for the RPC response budget. Direct project/label
reads include archived metadata for existing references. Archiving these records
does not hide their tasks or change ACL.

Work create/update additionally accepts optional `project_id` and up to 50 unique
`label_ids`. Omission clears those associations on update. All references must
match the root/workspace; Team projects must match the work item's Team. Existing
archived references may be retained or removed but cannot be newly assigned.
Work list filters additionally accept `project_id` and `label_id`.

Team member writes increment the Team revision and return scope/ID/revision/time
only. The add operation needs downstream
`access.v1.principals.validate_users` with actor action `access.grants.manage`,
target `task.read`, and source `task/v1:task.teams.members.add`. A business
membership never grants workspace or root access. Removal does not require the
target to remain active. Lists contain IDs/timestamps, not profile data.

All writes retain domain/audit/replay/outbox atomicity. Extend exact Gate/Task
operation approvals, downstream Access checks and broker subjects for the new
operations; replace the Task artifact/routes and update Notify's producer digest.
The catalog change hint now additionally supports project/label identifiers;
existing task-created notification semantics remain unchanged.

## Comments, history and saved views

Task 0.4.0 requires explicit migration `000005_collaboration`. Paths below use
the same workspace/root prefix:

| Method/path | Behavior |
|---|---|
| POST `/work/{task_id}/comments` | `task.create`; create plain-text/Markdown `body`, optional `parent_id` |
| GET `/work/{task_id}/comments?limit=100` | `task.read`; page active comments by UUID; follow cursor |
| PATCH `/work/{task_id}/comments/{comment_id}` | `task.create`, author only; replace body with current `revision` |
| POST `/work/{task_id}/comments/{comment_id}/resolve` | `task.create`; set `resolved` true/false with current revision; metadata-only response |
| POST `/work/{task_id}/comments/{comment_id}/archive` | `task.delete`; archive by revision; metadata-only response |
| GET `/work/{task_id}/history?limit=100` | `task.read`; product task/comment audit metadata in increasing audit-ID order |
| POST `/views`, PATCH `/views/{view_id}` | `task.create`; create or replace a personal/shared query definition; owner-only updates by revision |
| GET `/views/{view_id}`, GET `/views?limit=100` | `task.read`; own personal views and root-shared views only |
| POST `/views/{view_id}/archive` | `task.create`, owner only; archive by revision |

Comments are capped at 15,000 bytes. Reply parents must be active comments of the
same task/root/workspace; parent links are immutable and thread depth is capped
at 32. Lists are size-bounded and may return a short page with `next_cursor`.
Archived tasks and archived Team scopes deny these operations. Resolution can be
changed by another root writer; only the author can edit a comment's text.

History returns actor, operation, entity ID, revision, changed field names and
timestamp. Its cursor is an integer audit ID, unlike the UUID cursors elsewhere.
It does not reconstruct old values, content snapshots or historical changes
never captured by this model. Legacy proof audit remains retained separately.

View inputs are `name`, `description`, `is_shared` and typed `filters`. Filters
support Team/status/assignee/project/label, priority, search, `layout` (list/board),
`group_by` (status/priority/assignee/project/none) and presentation `sort`
(position/priority/updated_at/title). Defaults are list/status/position. Query
references must match the active root/workspace; assignee validation uses the
existing Access operation with additional exact view create/update downstream
sources. Layout/group/sort are presentation configuration; Work API pagination
remains UUID-ordered. Clients apply configuration to the paginated work results.

Personal view definitions are never returned to other root readers. Editing or
archiving a shared view also remains owner-only. Definitions do not grant access
to any task; reads always require current root authority. Personal-only changes
write audit/replay without a root-wide outbox hint. Shared changes and unsharing
emit identifier/revision hints without names, descriptions, filters or owner IDs.
All emitted changes use the existing catalog event subject; update its Task
artifact approval/routes and Notify producer digest through signed replacement.

## Runtime

Core Control requires explicit live `RuntimeControlPolicy` and a snapshot signing
key; it defaults off. `RuntimeNodeRPC=true` binds only node inventory/pull/report,
not management. New node enrollment requires Core restart; disable/key/policy
revocation is online. Owner-local interfaces do not supply remote authentication.
The administrative policy/Gate adapter, Core reconciler/hint publisher and full
health/log APIs are missing. See [architecture §7](../docs/ARCHITECTURE.md#7-runtime-control-and-infrastructure-agent)
and [Agent operations](agent/README.md). Run `make runtime-smoke` for the private
protocol and standalone Agent lifecycle; live host effects are a separate check.

## Personal Inbox and subscriptions

Notify 0.1.0 adds signed HTTP operations under `/api/v1/notify/`:

| Method | Path | Input / result |
|---|---|---|
| GET | `notifications?limit=100&cursor=...&tab=unread` | Own notifications and visible unread count |
| POST | `notifications/{id}/state` | `revision`, `action`, optional snooze `until` |
| POST | `notifications/mark-all-read` | Empty object; number of visible receipts updated |
| POST | `subscriptions/subscribe` | `workspace_id`, `acl_root_id` |
| POST | `subscriptions/unsubscribe` | `workspace_id`, `acl_root_id` |
| GET | `subscriptions?limit=100&cursor=...` | Own currently readable active subscriptions |

Commands require an Idempotency-Key. State actions are `read`, `unread`,
`archive`, `unarchive`, `snooze`, `unsnooze`; snooze must end within 365 days.
Tabs are `all` (default active), `unread`, `archived`, `snoozed`.
List cursors are ascending UUIDs. No request accepts a recipient identifier.

These service-owned personal operations use the existing manifest `service`
auth mode with a trusted module guard requiring an online-verified user session,
exact operation and no delegation. This mode does not imply a service actor;
health still requires the Notify service actor. SQL always binds receipt and
subscription ownership to the verified user. Mutation, personal audit and replay
are atomic in Notify's database. Individual receipt changes return state only;
a user may clear their own stale receipt/subscription after losing root access.

Lists, unread counts and mark-all-read check current `task.read` through Core
Access, fail closed on dependency failure, and never reuse decisions across
requests. Subscribing additionally binds the invocation workspace and checks
that root. Business subscription membership grants no Task rights. At most 1000
active subscriptions are allowed per user. Old notification rows without trusted
workspace/root/task provenance are retained but hidden; new task-created effects
persist provenance in the existing event inbox transaction.

Apply Notify migration `000002_user_inbox` explicitly before deployment. Replace
the signed Notify artifact approval and routes; allow the six exact user operation
subjects in its manifest. The subscription-create source operation needs approved
downstream `access.v1.check`; Inbox list, mark-all-read and subscription-list need
`access.v1.check_many`, with action `task.read` and their exact source audience and
operation. Also approve `identity.v1.invocations.exchange_service` for Notify.
Gate needs the corresponding user invocation exchange policies. Health policy
remains service-only. This delivery does not enable a real outbound provider or
realtime delivery; fake outbound intents remain unchanged.

## Task hierarchy

Task 0.5.0 adds `POST .../work/{task_id}/parent` under the existing workspace/root
prefix. Input is `parent_id` (UUID, or an empty string to detach), `revision` and
`expected_updated_at`. It requires `task.create`; output contains only scope,
child/parent IDs and the new revision/timestamp. The operation shares Task's
transactional audit, replay and catalog invalidation. Work responses include an
optional `parent_id`; collection filters `parent_id` and `top_level=true` select
immediate children or tasks without a parent. These filters are mutually exclusive.

Both endpoints must be active product work items in the same workspace/root;
legacy tasks must first be adopted into a Team using work update. Teams may differ
inside that shared ACL root. Cycles and resulting trees deeper than 32 edges are
rejected, including when moving a subtree. Composite foreign keys also reject
cross-root parents. Archiving retains hierarchy records and does not cascade or
silently reparent children; archived parents can be detached using the active
child's revision. Ordinary work edits preserve the parent. Apply migration
`000006_subtasks` and replace the signed Task artifact/routes and Notify producer
digest. Rich-text rendering and UI hierarchy interactions remain client work.

## Task links

Task 0.6.0 adds `GET` and `POST .../work/{task_id}/links`. POST requires
`target_id`, `kind` (`related`, `blocks`, `duplicate_of`), `remove` boolean,
source `revision` and `expected_updated_at`. Related links are symmetric and
stored once; directed links are source-to-target, with cycles rejected per kind.
A task has at most one outgoing duplicate target and 100 incident links total.
Both endpoints must be product work items in the same workspace/root. Creation
requires active endpoints; removal can clean up an archived target. Listing hides
archived tasks and Teams. Archive retains links without cascading changes.

A write requires `task.create` and atomically increments both endpoint revisions
and timestamps, records both history changes and emits both root-scoped catalog
hints. Output contains IDs and versions only. Reads require `task.read`. Apply
`000007_links`, replace signed Task routes/artifact approval and update Notify's
producer digest. This API does not merge duplicate tasks or propagate statuses.

## Atomic bulk work updates

Task 0.7.0 adds `POST .../work/bulk-update` with the existing workspace/root path
and a single Idempotency-Key. The body contains `items` (1–20 full work update
representations, each with `task_id`, `revision`, `expected_updated_at`); per-item
scope overrides are forbidden. Duplicate task IDs and encoded payloads above
180000 bytes are rejected. Parent and link relations are preserved.

The command requires current `task.create` and uses the same validation,
reference/assignee checks and revision guards as individual work updates. Every
update, audit, event and replay result shares one owner-local transaction: any
error or deadline aborts the whole batch. Output contains task IDs, new revisions
and timestamps only. Replace the signed Task artifact/routes approval and Notify
producer digest; no new database migration is needed for this operation. This is
a full representation API, so clients must preserve fields they are not editing.

## Task templates (0.8.0)

Apply Task migration `000008_work_templates` before deploying the new Task
binary. The following paths are relative to the Task root prefix above:

| Method/path | Action |
|---|---|
| POST `/templates` | Manage: create a scoped template from work fields and `name` |
| PATCH `/templates/{template_id}` | Manage: replace definition, using `revision` |
| POST `/templates/{template_id}/archive` | Manage: archive, using `revision` |
| GET `/templates/{template_id}` | Read: retrieve active definition |
| GET `/templates?limit=100&cursor=<uuid>` | Read: paginate active templates |
| POST `/templates/{template_id}/use` | Create: new task, optional title override |

All commands require a stable Idempotency-Key. Gate requires CSRF/Origin for
browser writes. Reapprove the exact Task 0.8.0 contract/digest, the approved
broker subjects and Notify producer pin before deployment. The event subject
remains `evt.task.catalog.changed.v1`; no new broker subjects were added.

## Task triage (0.8.1)

POST `/work/{task_id}/triage` with `status_id`, `revision` and
`expected_updated_at`. The source must currently be `backlog`;
the destination is an active status of category `todo` or `cancelled`
in the same Team. Requires live `task.create`, CSRF/Origin for browser
requests and Idempotency-Key. The ordinary `work.update` workflow remains
available for other transitions. Reapprove the new Task contract and replace
the Notify Task producer digest before deployment.

## Notify-owned realtime invalidation (Notify 0.2.0)

Apply migration `000003_notify_outbox` after `000002_user_inbox`.
Notify now stores `evt.notify.inbox.changed.v1` in its own transactional
outbox for new notifications and user Inbox changes. The event has the selected
recipient UUID and optionally a notification UUID/revision; mark-all produces
one recipient-scoped collection invalidation. It carries no notification content.
The Notify publisher is protected by the active signed Fabric lease and retries
uncertain NATS delivery using the persisted event ID. Operator provisioning must
add the exact Notify subject to a private JetStream stream and Notify NKey
publish permissions, reapprove the updated Notify artifact/digest, and update
Notify service deployment. This does not expose WebSocket to browsers; see
[realtime contract](../docs/REALTIME.md).

## Gate shared realtime (opt-in)

Gate now includes the `/api/v1/arc/realtime` WSS adapter. It remains disabled
by default and must be enabled only by an operator-configured
`"enable_realtime": true` in the Gate JSON configuration **after** exact NATS
event subscription permissions, Notify stream and signed contracts have been
deployed. Browser handshake uses the existing cookie session and an allowed
HTTPS Origin plus the offered `arc.realtime.v1` and
`csrf.<base64url(cookie CSRF value)>` subprotocols. The server replies with
only `arc.realtime.v1`. Task scopes are live-validated using the signed Task
read operation; Inbox subscriptions bind to the validated session user.
Bounded invalidations force authorized HTTP refetch. Do not enable without
the operational checks in [realtime protocol](../docs/REALTIME.md).

Files' personal/workspace live backend fixture: `bash scripts/test-files-live.sh`
(requires Go/C and pinned `nats-server` on PATH). See the scope and limits in
[Files acceptance](../docs/FILES.md#reproducible-isolated-live-acceptance).

Task Files attachments and Identity avatar asset binding:
[resource integration](../docs/RESOURCE-REFERENCES.md). Task 0.9.0 requires
migration `000009_attachments`; Core requires `000014_avatar_assets`.
