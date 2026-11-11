# Implementation sequence before GitHub

This is the agreed product implementation sequence, requested in
[#25](https://github.com/pavlith/arc/issues/25). “Before GitHub” means before the
optional GitHub connector, not before pushing code to this repository.
[Requirements](REQUIREMENTS.md) and [Architecture](ARCHITECTURE.md) remain
normative; GitHub Issues and labels own work items, acceptance and status.
This document describes dependencies and delivery boundaries, not a second tracker.

## Starting point

Baseline: `dev` at `8c476e7` (2026-11-11). Implemented backend includes invited
onboarding, account/session operations, profile/preferences, workspace/member/group
management, ACL grants, Teams/workflow, shared work items, projects/labels,
comments/history, private/shared views, subtasks, links, atomic bulk updates and
personal Inbox/subscriptions. See the [service guide](../services/README.md).
These APIs do not establish completion of the adapted Kuayle UI or live acceptance.

Svelte changes are paused until the user resumes UI work. Go tests are currently
deferred by user instruction; build/vet, artifact compilation and migration checks
are implementation evidence, not substitutes for security or product acceptance.
Continue delivering scoped commits to `dev` and pushing after each completed step.

## Service boundaries

| Owner | Responsibility |
|---|---|
| Core Identity / Access / Fabric | Identity, sessions, memberships, ACL, approved contracts and routes |
| Task | Work items, Teams/workflow, projects, comments, templates, views and domain events |
| Notify | Recipient selection, durable Inbox, subscriptions and outbound delivery |
| Gate | Public HTTP, shared realtime connections, approved routing and streaming adapters; no database |
| Files (`services/files/`, planned) | Folders, file metadata, upload lifecycle, downloads, attachments and avatar bytes |
| Pages (`services/pages/`, planned) | Wiki documents, hierarchy, Tiptap content, versions, restore and resource references |

Uploads belong to Files; Wiki is a Pages product flow. Neither needs another
service. Each new domain owns its own SQLite database, migrations and outbox.
Other domains retain file/resource references, never another owner's tables.
Realtime begins as a Gate adapter, not a new process and not a Notify-only feature.

## Delivery order

### 1. Finish the Task backend

Continue [#10](https://github.com/pavlith/arc/issues/10): add scoped templates and
template-based creation with validated workflow/project/label/assignee references.
Define explicit triage behavior and its workflow transitions. Preserve ordinary
creation, revisions, same-root relationships and transactional replay/audit/outbox.
Clarify the supported rich-text document format and validation limits before
accepting editor content; clients must not render arbitrary stored HTML.

Completion evidence: approved Gate contracts cover template CRUD/use and triage;
existing work APIs remain compatible. Personal Task roots and automatic Kuayle
database import remain separate extensions under [the Task model](TASK-MODEL.md).

### 2. Add shared realtime through Gate

Define and record the subscription contract before implementation: initial
WebSocket adapter, approved event subjects, operation/action mapping, root binding,
message limits, backpressure, reconnect and session/access revocation behavior.
Use domain outbox events over private NATS; browsers never receive broker access.
Check the live session and required resource action at subscription and before
delivery, fail closed on dependency failure, and terminate revoked subscriptions.

Start with bounded invalidation messages containing entity type, ID and revision.
The client refetches content through normal authorized APIs. Reconnect performs
fresh subscription authorization and state refetch; durable per-browser replay is
outside the initial contract. Notify separately produces personal Inbox signals.
Completion evidence: Task and Inbox updates reach only permitted subscribers;
disconnect/reconnect, overflow and revoke behavior are defined and verified.

### 3. Implement Files and uploads

Create the Files service with explicit migrations, signed artifacts and scoped
personal/workspace sections. Implement folder/file metadata, list/search, move,
delete, upload initiation/completion/abort and authorized download. Define size,
type and filename rules, ETag/conflict semantics, partial-upload cleanup and the
initial large/resumable-upload policy before exposing endpoints.

Start with local byte storage behind an adapter that permits later S3 support.
Stream bytes through approved private HTTP behind Gate, not NATS payloads; define
stream authorization/revocation and cancellation. A file becomes visible only
after successful completion; reconcile abandoned bytes and metadata failures.
Completion evidence: upload/download works with bounded memory and inaccessible
IDs, cross-root moves and revoked access do not expose bytes or metadata.

### 4. Integrate attachments, avatars and resource links

Task and Pages reference Files IDs; Identity references an authorized avatar asset.
Define attachment ownership, attach/detach permissions, deletion/reference behavior
and safe image delivery. A link or embedding must not grant access to its target.
Implement target-authorized resource lookup/search/previews without cross-owner
SQL; denied targets expose no content, title or preview. Initially cover Task and
Files, then Pages when that service is available.

Completion evidence: attached files and avatar replacement work through Gate;
revoking target access also removes previews/download access. UI integration
remains deferred until stage 7.

### 5. Implement Pages / Wiki

Continue [#11](https://github.com/pavlith/arc/issues/11): create a separate Pages
service with personal/workspace sections, selective ACL roots, page tree, CRUD,
move, search and sidebar data. Prevent hierarchy cycles and cross-scope moves.
Keep business hierarchy distinct from ACL inheritance and define moves across
permission boundaries before allowing them.

Use validated Tiptap documents, bounded content, revision conflict checks, version
history and basic restore. Support planned headings/lists/tables/code/task lists,
templates, Files images/attachments and authorized resource links. Publish
metadata-only invalidations through the shared realtime path. Completion evidence:
tree/edit/restore APIs work and forbidden embeds reveal no target data. Yjs and
Notion-style databases are outside this initial delivery.

### 6. Complete Notify integration and deployment

Continue [#9](https://github.com/pavlith/arc/issues/9) and
[#12](https://github.com/pavlith/arc/issues/12): connect Inbox realtime and add
explicitly supported Task/Page/File notification triggers with recipient policies
and target-authorized links. Define what subscriptions mean for each resource type;
do not generate a notification for every realtime update.

Before implementing a real outbound channel, select its provider and document
secret/configuration, timeout, retry, claim/lease and stable provider-key contracts.
Do not send externally without explicit authorization. Fake delivery remains a
fixture; external delivery never claims exactly-once effects.

For each new/changed service, deliver migrations, configuration examples, startup
instructions, service identities, exact signed approvals/routes/downstream rules
and event permissions. Update pinned producer digests. Publishing code is not a
deployment; no production data migration or private signing material is implicit.

### 7. Resume the Kuayle UI only when authorized

Adapt the selected Svelte 5/shadcn UI to Arc APIs, UUID/root scopes and slug lookup.
First implement workspace/account/member/group/permission management, then
Teams/projects/tasks/boards/views/templates/triage, Inbox and realtime, followed
by attachments/avatars and Wiki. Define an explicit API mapping; upstream endpoint
names, roles and Team membership are not Arc authorization rules.

Prepare Gate deep-route fallback, assets and a restrictive content policy for the
actual build. Preserve API 404s, cookie/CSRF handling and separation of browser
sessions from CLI tokens. Connect approved realtime and streaming routes on the
same public origin. Completion evidence: the UI uses the delivered backend and
shows loading, denial, conflict, reconnect and recovery states coherently.

### 8. Accept the standalone product, then start GitHub

Before declaring readiness, restore the deferred focused checks and run a current
two-user/two-workspace scenario: onboarding, roles/groups, grant/revoke, shared
tasks, templates/triage, comments/links, bulk rollback, Inbox, realtime reconnect,
file upload/download and page move/version/restore. Include known-ID isolation,
revoked sessions, safe rich-text rendering, denied previews and migration replay.
Record actual evidence in the owning Issues; leave unverified criteria open.
This does not require running the full M7 matrix prematurely.

Then define the optional connector under X-01–X-04: approved manifest/scopes,
user/workspace connection ownership, encrypted credentials and revoke/audit,
webhook verification, retry/rate limits and external-to-Arc mapping/conflicts.
Start with an explicitly scoped GitHub use case; Arc remains fully usable without
it. Provider API/authentication details must be verified against current official
documentation when that implementation begins.

## Scope boundaries

This sequence prioritizes the agreed Office/UI foundation; it does not redefine
the repository's M1–M6 milestones. Full WebDAV/public shares, additional storage
providers, file version UI/recycle bin/thumbnails, cycles/sprints, configurable
open registration, Calendars/Contacts/DAV, workflow runtimes and further Agent
drivers remain their own deliveries. They are not prerequisites for the first
GitHub connector. Files attachment storage is deliberately brought forward for
Pages/UI; the remaining M3 Files scope stays separate.

Create or reuse an active Issue before implementing each stage, especially new
Files and Gate contracts. Update normative documents when those contracts are
defined; this sequence alone does not implement or approve them.
