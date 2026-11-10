# Arc requirements

> Reviewed on 2026-11-10 under [#14](https://github.com/pavlith/arc/issues/14).
> [Architecture](ARCHITECTURE.md) defines implementation contracts.
> Requirements describe the target; their presence does not establish delivery.
> P0: foundation; P1: Office MVP; P2: automation/agents; P3: infrastructure management.

## 1. Product, goals and scope

Arc is a self-hosted team collaboration platform with shared identity, workspaces,
groups and ACL; tasks, calendars, contacts, files and hierarchical pages; then
connectors, agents and workflows. REST, CalDAV, CardDAV, WebDAV and tools use the
same permissions. Users retain control of data without a developer cloud or a
mandatory GitHub dependency. Engineering materials and new UI use English.

Actors: installation owner, workspace admin, member, guest, service and explicitly
delegated AI agent. Initial scope excludes enterprise IAM (SAML/SCIM/LDAP), CRM,
Notion databases, browser DOCX/XLSX editing, a Kubernetes/Portainer replacement,
built-in mail, initial third-party DAV sync and hostile-code isolation in ordinary Docker.

### 1.1 Kuayle adaptation

Adapt applicable [Kuayle](https://github.com/carbogninalberto/kuayle) behavior:
Go/Echo direction, Svelte 5/shadcn-svelte, workspaces, tasks/projects/views,
notifications, realtime, Tiptap and uploads. GitHub becomes an optional connector;
coding runtimes are specialized execution resources. Preserve existing data where
possible and document/test irreversible changes. Upstream or lost local code
does not count as an Arc implementation. Define the data-import and personal-task
strategy in #10 before implementing it.

## 2. Functional requirements

### 2.1 Arc Core / Identity (P0)

- **I-01:** Registration/login/logout, secure sessions, refresh rotation/revocation,
  recovery, profile and registration/invitation settings. M0 may use an admin/CLI
  one-time recovery token without a mail connector.
- **I-02:** Workspace creation, owner/admin/member/guest roles, invitations and
  membership changes; one global user may join multiple workspaces.
- **I-03:** Access groups (`Group/GroupMember`) remain separate from domain teams;
  authorized owners/admins manage membership and permissions.
- **I-04:** Scoped service accounts and agent identities; credential lifecycle
  and audited delegation issuance/revocation.
- **I-05:** Personal roots exist outside workspaces; leaving never deletes or
  transfers them to the organization.
- **I-06:** Distinct User, AgentIdentity, ServiceAccount and ServiceCredential.
  Per-service broker permissions do not replace user ACL. Credentials bind to
  approved definitions/deployments; private keys stay outside databases.
- **I-07:** Secure/HttpOnly/SameSite browser cookies and CSRF; API access JWT
  `aud=gate`, TTL ≤10 minutes and online session checks. Refresh reuse revokes
  the family. Never log tokens.
- **I-08:** Core Ed25519 invocation JWT binds
  `iss/aud/sub/caller/op/cnf.kid/iat/nbf/exp/jti`, one approved operation, TTL ≤60s.
  Service assertions have single-use jti and TTL ≤30s. Gate has no Core signing key.
- **I-09:** Per-request caller proof binds key, subject, operation, request ID,
  canonical payload hash and token jti. Verify signature, audience and live key;
  persist replay protection and command idempotency.
- **I-10:** Gate exchanges a live session for a target invocation; each downstream
  hop exchanges again. Actor/on_behalf_of/caller never come from unverified input;
  downstream rights cannot expand.
- **I-11:** Explicit delegation records grantor, grantee, resources/actions,
  mandatory expiry, consent method and audit. No self-issued user delegation;
  each Check intersects live user rights and delegation online.
- **I-12:** Session, grant, membership, service-key or delegation revoke denies
  checks after commit despite unexpired JWT. Core outage fails closed; already
  running operations may finish.
- **I-13 (later):** Advanced dangerous-action approvals, SSO/MFA, broker credential
  management and long-running delegation renewal need separate scope.

M0 guardrails: canonical proof/audience/operation/caller/replay vectors, refresh
reuse, one revoke path and denied self-delegation. M7 completes multi-workspace,
personal-root, downstream intersection and full revocation combinations.
Product Identity/Gate UI remains #9; [standalone Core startup](../services/core/README.md)
uses operator-provisioned keys, signed policy and explicit migrations.

### 2.2 Resource ACL (P0)

- **A-01:** Selective registry of ACL roots: workspace, personal, calendar,
  address book, independent files/pages section, agent/workflow. Ordinary objects
  may inherit a root without a registry row. Domain owners verify object/root
  binding and keep content in their own database.
- **A-02:** Approved contracts register namespaced types/actions. One acyclic
  `acl_parent`, matching owner/scope, explicit `inherit_acl=false` boundary.
  Joining a workspace never transfers personal resources.
- **A-03:** Allow-only user/group/role/service/agent grants with expiry and audit;
  default deny. ACL administration does not grant content access. An authorized
  admin may explicitly self-grant with audit; share cannot exceed the sharer's
  actions/expiry. free_busy and read are independent.
- **A-04:** Online Check for every protected RPC/DAV/API/tool; no positive cache.
  CheckMany handles ≤100 pairs; ListAccessibleRoots paginates. Domain owners
  filter content and reject forged object/root/parent bindings.
- **A-05:** Post-commit revoke visibility, policy revisions and immutable audit.
  Core outage denies new checks; no immediate cancellation promise.
- **A-06:** Idempotent reserve/activate/abort/begin_delete/finalize_delete.
  Pending roots are invisible; deleting roots deny new checks. Reconciliation
  must recover failures between Core and domain transactions.
- **A-07:** Agent/workflow authority intersects its tools, live delegation and
  current ACL. Broker headers do not authenticate the publisher.
- **A-08 (M2–M3):** Personal groups/cross-workspace sharing, public links,
  streaming revoke and extended policies require separate contracts.

M0 covers owner/no-grant, revoke, cross-root spoofing, fail-closed and repeated
reserve/activate. Full matrix: [architecture §4.5](ARCHITECTURE.md#45-required-security-cases).
Calendar/Files fixtures may stand in for absent endpoints.

### 2.3 Service Fabric / Arc SDK (P0)

- **F-01:** SDK is a library in the single root Go module. Arc-native NATS
  transport uses nats.go and implements Micro v1 PING/INFO/STATS plus queue
  endpoints; it does not wrap/fork the whole nats.go/micro package.
- **F-02:** Separate Definition, immutable approved Contract and ephemeral
  Instance. Manifest v1 declares API major, typed operations/subjects/schemas,
  resource actions, auth selectors, optional exposure/events and limits.
  Reject unknown fields and conflicting names.
- **F-03:** Approval binds deterministic manifest/schema digest, deployment,
  identity and subjects before business subscriptions. Readiness requires all
  handlers and proof. Unknown/revoked digest, wrong account or schema denies.
- **F-04:** RPC `rpc.<service>.v<major>.<operation>`, queue `q.<service>.v<major>`;
  JetStream `evt.<service>.<entity>.<event>.v<major>`. Restrict control subjects.
  Micro discovery/metrics alone do not prove readiness.
- **F-05:** Versioned JSON envelope, request ID, deadline, optional idempotency/
  trace, invocation and proof. Validate input/output schemas; defaults: query 5s,
  command 10s, envelope/response ≤256 KiB. Stable safe errors and HTTP mapping.
- **F-06:** Atomic command replay ≥24h by actor/operation/key. Changed hash
  conflicts; uncertain timeout retries reuse the key. No exactly-once promise.
- **F-07:** Domain mutation/outbox commit together; inbox/event_id deduplicates
  internal effects atomically before ACK. Retry/backoff/DLQ and versioned events;
  external effects may duplicate. Events grant no resource access.
- **F-08:** Breaking APIs use a new major subject/prefix. Build SemVer differs
  from API major. Test additive compatibility and version isolation;
  client generation does not block M0.
- **F-09:** Typed composition/register/call helpers enforce schemas, verified
  identity and ACL. HTTP/tool/workflow exposure independently defaults off.
  Direct RPC never bypasses ACL or trusts identity headers.

Current Fabric uses operator-signed installations, SQLite catalog, online
ContractSource, signed control replies and instance leases. One active digest per
service/API major; replacement requires revoke and conservative compatibility.
M0 covers digest/action/schema/proof, major isolation, replay and duplicate event;
full replicas/reconnect/recovery remain M7.

### 2.4 Gate (P0)

- **G-01:** Single public HTTPS REST/WS/DAV ingress. NATS and private service
  adapters are not public.
- **G-02:** Online session/auth, target invocation exchange and caller proof;
  schema/size/rate limits, CORS/CSRF and safe errors. Ignore unverified identity headers.
- **G-03:** Atomic signed RouteSnapshot(revision,digest,routes,kid,signature)
  contains approved routes only. Verify Core trust, reject rollback/conflicts/
  reserved paths; cold-start fetch and periodic reconciliation. Runtime discovery
  cannot publish an API.
- **G-04:** Missing responder →503, deadline →504, Core unavailable →503 without
  effect, policy denial →403 or safe 404. Domain service checks ACL. Unknown
  routes deny; 201/202 require contract approval.
- **G-05:** Resource-authorized WebSockets, DAV and large-file streaming without
  sending file bodies through NATS.

Current Gate is a separate process without a DB. It verifies a root-signed,
request-bound routes/JWKS bundle and preserves request/trace/deadline/idempotency.
Browser login and refresh use cookie/CSRF sessions. Explicit CLI endpoints
issue and rotate Bearer credentials for their own session channel. Gate can
serve the first workspace and Task UI on the same HTTPS origin. DAV/WS are
planned. M0 covers approved route, bad signature, reserved/colliding route and
Core outage. Full recovery is M7.

### 2.5 Task / Projects / Notify (P1; proof services in P0)

- **T-01:** Task ID, title, rich text, status, priority, due dates, multiple
  assignees, labels, files, comments and history.
- **T-02:** Subtasks, blocked/blocks/duplicate/related links, triage, templates
  and bulk actions.
- **T-03:** Workspace/team projects, Kanban/list/saved views and filters;
  cycles/sprints optional.
- **T-04:** Subscriptions, inbox/read/archive, realtime and task/page/file/event/
  contact links.
- **T-05:** Tasks work without GitHub; integration is an optional connector.

Acceptance: UI/API share a model; ACL controls assignee visibility, search and
links; task-created events drive Notify. The current M0 proof covers workspace
create/get/list, atomic replay/outbox and Notify inbox/record/fake outbound intent.
Root/workspace/ACL are checked online before mutation and replay. Recipients come
from operator subscriptions, not event input; stable provider dedup keys do not
promise external exactly-once. Product work: #9, #10, #12.

### 2.6 Calendars / CalDAV (P1)

- **C-01:** Default and additional personal/workspace calendars, owners and group grants.
- **C-02:** Timezones/all-day, recurrence/exceptions, attendee fields, attachments/
  links and independent free_busy permission.
- **C-03:** CalDAV discovery, iCalendar round-trip, ETag, sync-token and ACL.
- **C-04:** Unified permitted-calendar UI, filters and read/write/free-busy.
- **C-05 (later):** Protocol scheduling/invitations, rooms/resources and external sync.

Acceptance: two different clients round-trip CRUD/recurrence without duplicates;
read-only cannot write and free_busy discloses no private event title.

### 2.7 Contacts / CardDAV (P1)

- **K-01:** Personal/workspace address books with owners and group grants.
- **K-02:** Name, organization, role, phones, email, addresses, notes, photo,
  custom fields and resource links.
- **K-03:** vCard round-trip preserves unknown properties; ETag/incremental sync.
- **K-04 (later):** Remote sources, merge/deduplication and extended CRM.

Acceptance: externally created contacts appear without property loss; API and
CardDAV enforce identical address-book permissions.

### 2.8 Files / WebDAV / Sharing (P1)

- **L-01:** Personal/workspace folders, upload/download/search/move/delete and metadata.
- **L-02:** Local/S3-compatible bytes, DB metadata/ETag and streaming;
  resumable/large-file policy requires definition.
- **L-03:** WebDAV with ACL, file operations and conflict control.
- **L-04:** Public read links with expiry/revoke and password if approved;
  upload-to-folder later.
- **L-05:** Task/page attachments use Files rather than independent byte stores.
- **L-06 (later):** Restore/history, recycle bin, quotas, thumbnails and more
  connectors; initial schema accommodates versions.

Acceptance: UI upload and authorized WebDAV access; outsiders denied by known ID;
share revoke stops access; large uploads do not overflow NATS.

### 2.9 Pages (P1)

- **P-01:** Personal/workspace hierarchical pages, sections, inherited ACL,
  sidebar/tree and search.
- **P-02:** Tiptap headings/lists/tables/code/task lists/images/resource links/templates.
- **P-03:** Versions/basic restore and safe HTML/attachments. Links/previews
  require target ACL; public sharing follows the shared mechanism, not M1.
- **P-04 (later):** Yjs collaboration; Notion databases excluded from MVP.

Acceptance: create/move pages with correct section permissions; forbidden embeds
reveal neither content nor preview. No Pages service/UI exists; work is #11.

### 2.10 Connectors (P2)

- **X-01:** Approved manifests, versions, triggers/actions/scopes/secrets and optional sync.
- **X-02:** User/workspace OAuth/API-key connections with encryption/revoke/audit;
  personal connections are not shared implicitly.
- **X-03:** Webhooks/polling/outbound APIs with retries/rate limits and destination policy.
- **X-04:** HTTP and optional GitHub first; external DAV sync is additional.

Acceptance: registered trigger/action available only with sufficient scopes;
connection revoke denies new calls.

### 2.11 Workflows (P2)

- **W-01:** Versioned definitions/state/ownership/ACL; event/schedule/manual/approved webhook.
- **W-02:** CEL conditions, bounded Starlark transforms, typed Fabric actions;
  no arbitrary SQL, Docker or network access.
- **W-03:** Durable runs/attempts, idempotency, timeout/retry/backoff, error/history,
  manual retry/cancel and audit.
- **W-04:** Quotas, recursion/loop limits and bounded service or delegated authority.

Acceptance: duplicate events produce one internal result; external delivery
depends on provider deduplication; denied actions have no effect and worker
restart recovers the run.

### 2.12 Agents (P2)

- **AG-01:** Personal/workspace agents with model/provider settings, identity,
  approved tools/scopes/limits/audit and sensitive-action approval.
- **AG-02:** Interactive, bounded task and event/scheduled modes.
- **AG-03:** Use the same operations and ACL as human users.
- **AG-04:** Compatible local/remote model endpoints; MCP requires its own auth boundary.
- **AG-05 (later):** Isolated coding runtimes and optional browser/terminal;
  no general Docker socket access.

Acceptance: missing files.read denies file access; approved sensitive actions,
actor/on_behalf_of provenance and bounded traced runs.

### 2.13 Runtime Control and Infrastructure Agent (P3; safe baseline in P0)

- **R-01 (M0):** Node/template/deployment, immutable revision, operation and
  observation schemas plus RuntimeProvider; separate desired, observed and Fabric readiness.
- **R-02 (M0):** Independent Compose/systemd bootstrap for NATS, Core, Gate and
  owner storage. M0 requires fake-Agent contracts, not a live host executor.
  arc.runtime.manage is separate from workspace administration and defaults deny.
  Current Compose covers infrastructure/migrations only; the standalone Core
  command uses strict local bootstrap without enabling Runtime management.
- **R-03 (M0):** Versioned node-bound desired/observation protocol, invocation/
  proof, idempotency and fake negative tests; no Docker management UI requirement.
- **R-04 (M6):** Initial trusted Linux/Docker node, approved templates and immutable
  images; manage only owned resources. No arbitrary Compose/shell, privileged
  workloads, host binds/devices/sockets/network or unrestricted parameters.
- **R-05 (M6):** Create/start/stop/restart/update/delete, replica count, quotas,
  bounded health/logs; secret references only. Destructive volume purge is separate.
- **R-06 (M6):** Leased reconcile and single writer, monotonic revision/CAS,
  pending/running/succeeded/failed/cancelled operations, retry and idempotency.
  Stale requests cannot overwrite newer desired state.
- **R-07 (M6):** No cached desired execution during Core/NATS outage. Preserve
  workloads and reconcile safely after reconnect; Agent failure does not stop them.
- **R-08 (M6):** Image updates create revisions; single-node recreate may have
  downtime. No automatic rollback/zero-downtime promise.
- **R-09 (later):** Multi-node placement, hostile-code sandbox and automatic safe rollback.
- **R-10 (M6 extension):** Typed docker.container/lxd.instance/systemd.service
  drivers on explicitly selected trusted nodes/VPS. No Docker emulation for LXD/
  systemd and no exposed host API.
- **R-11 (M6):** Outbound NATS TLS/NKey; signed snapshot ≤30s binds fresh request,
  node, complete approved template digest/revision and spec revision. Independent
  invocation/proof/live policy, durable high-water journal and exclusive writer;
  corrupt state never silently resets.
- **R-12 (M6):** English Gate/Svelte UI for nodes/capabilities/resources/operations/
  desired/observed and bounded health/logs, including loading/empty/error/offline.
  UI grants no rights and never calls host/Agent APIs directly.

Current Control, private Node RPC, Linux Agent/journal and restricted systemd
driver are partial #13 delivery; see [services](../services/README.md) and
[Agent](../services/agent/README.md) for exact limits. Management stays disabled
without explicit trusted policy/signing key. Admin authorization adapter, Gate/UI,
Docker/LXD, Core reconcile/outbox publisher and complete health/logs are missing.
Host effects use test adapters; live unit start/stop is not established.
M6 is not integrated as a whole; M7 covers full crash/offline/replica/recovery.

## 3. Non-functional requirements

| ID | Requirement | Evidence |
|---|---|---|
| N-01 Security | External/internal TLS, scoped credentials, invocation/proof and audit | Security guardrails and threat review |
| N-02 Isolation | User/workspace/domain ACL on all entry points/search | Negative permission matrix |
| N-03 Reliability | Outbox, idempotent consumers, retry/deadline/shutdown | Network/crash/duplicate tests |
| N-04 Portability | Linux/Compose, documented storage and backup/restore | Clean-host install and restore |
| N-05 Observability | Safe JSON logs, request/trace IDs, health/readiness and metrics | Correlated end-to-end request |
| N-06 Compatibility | Approved CalDAV/CardDAV/WebDAV clients | Client integration matrix |
| N-07 UX | Responsive Svelte 5, search, keyboard and accessible navigation | Browser/accessibility checks |
| N-08 Language | English UI and engineering materials; other locales optional | Key flows and language scan |
| N-09 Contracts | Immutable digests, API major isolation, additive compatibility | Contract/version/collision tests |
| N-10 Operability | Explicit migrations, rollback policy and backups before critical changes | Upgrade/recovery tests |
| N-11 Runtime | Independent bootstrap, Agent-only host effects and approved resources | Focused M6 privilege guardrails; full M7 matrix |

Numeric defaults: RPC 5s/10s, 256 KiB, replay ≥24h, access ≤10min, invocation ≤60s,
assertion ≤30s, default one-time delegation 24h; no positive authorization cache.
Other SLOs, p95/RTO/RPO and capacity require measurements.

### 3.1 SQL storage

Core, Task and Notify own separate local SQLite files and GORM models/migrations;
Core modules share its file and Gate has no DB. Explicit Gormigrate before traffic,
immutable IDs, safe replay and denial of unknown history. WAL/foreign keys/busy
timeout on every connection. Owner mounts/OS permissions and RPC/events isolate
data; no cross-owner SQL/ATTACH/shared file. Mutation/audit/replay/outbox or inbox/
effect are atomic; acquire writer lock before mutable reads and retry complete
busy transactions. Independent SQLite replicas across hosts are unsupported.
[Database guide](../sdk/database/README.md) covers operation.

## 4. Milestones

| Milestone | Scope | Acceptance |
|---|---|---|
| M0 Foundation | Core, NATS/JetStream, SDK, Gate, proof Task/Notify, migrations, fake Runtime | Focused vertical smoke and mandatory guardrails; no Docker management required |
| M1 Office Core | Product Identity, Task/Projects/Views, Pages, resource links, Notify, English UI | Two-workspace/personal/product paths integrated |
| M2 Personal Data | Calendars/CalDAV, Contacts/CardDAV, free_busy and groups | One client per protocol smoke; full client matrix in M7 |
| M3 Files | Storage, WebDAV/shares and attachment migration | Streaming/sync/revoke happy path |
| M4 Automation | Event catalog, CEL/Starlark workflows and run history | Durable path, replay and denied-action guards |
| M5 Integration & Agents | Connectors, bounded agents, tools/MCP and approvals | One approved end-to-end path using shared ACL |
| M6 Managed Runtime | Trusted-node drivers, templates, Gate/UI, reconcile, safe updates | Executed lifecycle and critical privilege denials per implemented driver |
| M7 Verification & Hardening | Freeze, exhaustive correctness/security/recovery/compatibility/performance | Required scope Verified; release blockers resolved |

M0–M6 may overlap without relaxing guardrails. Tool/event contracts are designed
in M0 before full agents/workflows. M7 adds only testability changes and fixes.
No whole-milestone readiness follows from a historical issue closure or one tested library.

## 5. M7 end-to-end acceptance

1. Two workspaces, groups/roles and personal resources remain isolated.
2. Task → calendar → read-only CalDAV; Files attachment follows ACL.
3. Personal/workspace CardDAV round-trip without property loss.
4. UI/WebDAV/shares and post-revoke access agree.
5. Pages hierarchy/version/resource previews enforce target permissions.
6. Agent acts through live scoped delegation; sensitive actions require approval.
7. CEL/Starlark workflow invokes approved actions and recovers after restart.
8. Invalid service digest/major/schema/proof denies; duplicate events preserve internal effects.
9. Runtime UI changes desired replicas; Agent reconciles and denies privileged/bootstrap targets.
10. Restore databases, objects, secrets and relevant JetStream state on a clean host.

## 6. Readiness and verification policy

Implemented: builds, empty migration and principal path executed.
Integrated: connected path, diagnostics, focused smoke and mandatory guardrails.
Verified: full relevant M7 matrix executed. M0–M6 require Integrated for accepted
scope; production requires Verified. See [architecture §10](ARCHITECTURE.md#10-verification-policy)
for the single verification policy. Missing code has no current readiness claim.

## 7. M0 deliveries and remaining decisions

| Delivery / Issue | Scope | Required focused evidence |
|---|---|---|
| 1 / #2 | NATS/SQLite bootstrap, explicit migrations, minimal transport | Repeated clean start, RPC and credential isolation |
| 2 / #3 | Identity/session/refresh/delegation/invocation | Proof/audience/operation/replay, revoke and self-delegation denial |
| 3 / #4 | Root/grant lifecycle and online ACL | Owner/deny/revoke/cross-root/fail-closed and reserve replay |
| 4 / #5 | Approved Fabric contracts, readiness, typed RPC/events | Digest/schema/action/version, command replay and duplicate event |
| 5 / #6 | Signed Gate routes and auth boundary | Approved route, signature/collision and Core outage |
| 6 / #7 | Proof Task outbox and Notify inbox | Vertical path, internal atomicity and stable outbound key |
| 7 / #8 | Runtime contracts/fake Agent and diagnostics | Revision/template/bootstrap denials and correlated smoke |

#2–#7 preserve historical delivery acceptance, with current code mapped in their
bodies. #8 needs current acceptance; #13 restores/extends Runtime. #9–#10 describe
lost M1 work that must be reimplemented. #15 adds the Core command and secure
startup; product provisioning and full standalone platform acceptance remain separate.
Current paths/limits live in component guides; status remains in Issue labels.

Open decisions: M1 Kuayle import/personal Task model; M2 sharing/DAV scheduling/
client matrix; M3 WebDAV locking/versioning/stream revoke; M4–M5 Starlark limits,
approval classes/connector secrets; beyond M6 placement/rollback/zero-downtime.
Preserve operation-bound invocation, explicit ACL self-grant audit, signed routes,
atomic inbox/effect and honest external at-least-once semantics.

## 8. M7 verification

After feature freeze, execute complete business/policy unit tests; SQLite/NATS/
storage/adapters integration; Identity/ACL/Fabric/Gate/agent/Runtime contracts;
browser/accessibility and supported DAV clients; crash/network/restart/replay/
stale revision/backup/upgrade recovery; measured p50/p95 and soak/load. Rerun release
regression after fixes. Required scope must be Verified with classified remaining
defects, no release blockers and documentation matching behavior.
