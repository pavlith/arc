# Arc Architecture

> Reviewed against the checkout on 2026-11-10 under [#14](https://github.com/pavlith/arc/issues/14).
> Requirements: [REQUIREMENTS.md](REQUIREMENTS.md). Setup and checks: [DEVELOPMENT.md](DEVELOPMENT.md).
> This document defines contracts; a planned contract does not establish implementation or verification.

## 1. Purpose and boundaries

Arc is a self-hosted collaboration platform derived from applicable [Kuayle](https://github.com/carbogninalberto/kuayle) concepts. It covers tasks, calendars, contacts, files, pages, agents, connectors and workflows. HTTP, DAV, RPC and tools share the same authorization model.

One modular Go Core owns Identity, Access, Fabric and Runtime state. Modules call Go interfaces within Core; separate processes communicate over NATS. Gate is the public API ingress. NATS, databases and the infrastructure Agent remain private. Large files use private HTTP streaming behind Gate or approved object URLs rather than NATS payloads. Bootstrap infrastructure operates independently of Runtime Control.

```mermaid
flowchart TB
    Clients[Web / mobile / DAV / API clients] --> Gate[Arc Gate]
    Gate <--> NATS[NATS Core + JetStream]
    Core[Arc Core: Identity / Access / Fabric / Runtime] <--> NATS
    Apps[Domain services] <--> NATS
    Core --> CoreDB[(Core SQLite)]
    Apps --> DomainDB[(Owner SQLite / object storage)]
    Agent[Arc Infrastructure Agent] <--> NATS
    Agent --> Host[Approved host drivers]
```

The diagram includes planned components. Current executable surfaces and gaps are documented in [services](../services/README.md). [Standalone Core](../services/core/README.md) uses explicit migrations and signed local bootstrap policy. Gate can serve the first Svelte workspace and Task view. Historical reports of lost local implementations do not establish current behavior.

## 2. Process and data ownership

| Component | Owns | Boundary |
|---|---|---|
| Core Identity | Users, sessions, workspaces, memberships, groups, service accounts and delegations | No domain content |
| Core Access | Resource types, ACL roots, grants and policy revisions | Domain owner still verifies object/root binding |
| Core Fabric | Approved contracts, instances, capabilities and signed routes | Not an obligatory RPC proxy |
| Core Runtime | Desired state, operations, observations and management policy | No host runtime socket |
| Gate | Public HTTPS ingress, authentication, routing and limits | No database or independent permission authority |
| Infrastructure Agent | Approved host effects and observations | No arbitrary shell/Compose or authority to grant user access |
| SDK | Transport, typed RPC/events, contract enforcement and lifecycle | No domain models or trust in client identity fields |
| Domain service | Its objects, tables, migrations and policy enforcement | No SQL access to another owner |

Core, Task and Notify each use a separate local SQLite file through GORM. Core modules share one file and may join the same transaction. Gormigrate runs explicitly before traffic; startup AutoMigrate is forbidden. Mount only the owner's directory, including WAL/SHM. Gate has no database. Redis is not a required source of truth.

## 3. Identity, service accounts and delegation

Actor identity, authenticated process caller and delegated authority are separate. Broker authentication alone does not authorize a platform operation.

### 3.1. Principals and tenancy

| Entity | Rule |
|---|---|
| User | Global human account, active/disabled; personal resources survive workspace departure |
| Workspace / Membership | Isolated corporate scope; owner/admin/member/guest role and active state |
| Group / GroupMember | Access principal within one workspace; a Task Team is a separate business concept |
| ServiceAccount | Technical identity bound to an approved definition/deployment; no implicit user ACL |
| ServiceCredential | Account key with `kid`, public key, state and rotation overlap; private key stays outside SQL |
| AgentIdentity | Explicit owner and execution scope; tool permission does not grant resource access |
| Session / RefreshFamily | Live server state supporting logout, rotation, reuse detection and revocation |
| Delegation | Grantor consent to a grantee, bounded resources/actions, expiry and approval conditions; does not change ACL |

M0 does not support workspace groups on personal resources or cross-workspace sharing. Autonomous services need explicit grants; acting for a user additionally requires valid delegation.

### 3.2. Credential boundaries

| Surface | Credential | Verification |
|---|---|---|
| Browser | Opaque session cookie, `HttpOnly; Secure; SameSite=Lax`, plus Origin/CSRF checks | Online Identity session state |
| External API | Access JWT, `aud=gate`, `sid`, `jti`; rotating refresh family with hashed tokens | Signature, expiry and live session |
| NATS connection | Scoped NKey/JWT credentials and TLS | Broker subject permissions; NATS JWT is distinct from Arc invocation JWT |
| Internal RPC | Core-signed invocation JWT plus caller request proof | Recipient verifies proof; Identity/Access check live authority |

Passwords use Argon2id. Authentication/recovery/credential changes are audited without secrets; rate limits are required. Refresh reuse revokes the family and requires interactive authentication. Session and refresh state are excluded from workspace export. MFA/SSO/SCIM and dynamic NATS user/JWT issuance are later work.

New accounts can register only with an email-bound workspace invitation. Account,
password/recovery hashes, membership, invitation consumption, workspace revision
and success audit commit in one Core transaction. Redemption rechecks the live
workspace and issuer authority; existing accounts use invitation acceptance after
sign-in. Public self-registration without an invitation is disabled. Registration
returns a recovery code once, stores only its hash and creates no session. A lost
response cannot replay that code; the user should try signing in before retrying.

Core, Gate and Agent broker credentials and TLS roots are provisioned independently through operator-managed secret files. Bootstrap must not depend on a running Identity service to connect to NATS.

### 3.3. Invocation and request proof v1

Core uses EdDSA/Ed25519. Protected internal JWKS publishes public verification keys only; SDK rejects `alg=none` and algorithm substitution. Gate and domain services never receive the Core signing private key.

Required claims: `iss=arc-core`, `aud=<service>/v<major>`, `sub=<user|agent|service>:<uuid>`, `caller`, `op`, `iat`, `nbf`, `exp`, `jti`, `cnf.kid`. Optional claims include `sid`, `delegation_id`, `on_behalf_of` and `workspace_id`. Workspace context is not a grant; `on_behalf_of` requires delegation. Payload/headers cannot select trusted actor, caller or scopes.

Defaults: access JWT ≤10 minutes; invocation ≤60 seconds; client assertion ≤30 seconds with one-use `jti`; one-off delegation defaults to 24 hours and may be shortened by policy. These are initial limits, not measured SLOs.

Gate exchanges an active session through `identity.v1.invocations.exchange_user` for one approved target operation. Services use `identity.v1.invocations.exchange_service` with a registered-key assertion (`iss/sub=service-account-id`, `aud=identity.exchange_service`). `op` must match both envelope and approved contract. Propagation presents the incoming invocation and obtains a fresh downstream token: actor provenance is preserved, audience/caller change, and scope can only narrow. Autonomous service identity is not a human session.

NATS Micro monitoring does not attest the publisher of an individual request. Untrusted identity headers cannot replace proof. `proof_v1` is an Ed25519 signature over the UTF-8 RFC 8785 canonical JSON array:

```text
["proof_v1", subject, request_id,
 hex_lower(SHA-256(JCS(envelope without proof))), token.jti, timestamp, nonce]
```

Signature encoding is unpadded base64url. Timestamp is RFC3339Nano with a −30/+5 second window; nonce length is 16–128 characters. Verify subject, request/body, caller key and live key state. Persist nonces for all protected calls, including reads, until token expiry +30 seconds. Mutation idempotency is separate from nonce replay protection. Never accept a verification key from an untrusted request field.

### 3.4. Delegation and revocation

Only an authenticated grantor or explicitly authorized trusted consent workflow may create delegation. An agent/service cannot delegate to itself for a user. Creation verifies the grantor's current rights. Store grantor, grantee kind/ID, actions, resource scope, expiry, revocation, creator and consent method. Expanding scope requires new consent.

Each protected operation intersects current user ACL, delegation, approved service rights and allowed agent tools. `needs_approval` operations are denied without confirmed approval. Missing Identity/Access fails closed with `UNAVAILABLE`; M0 has no positive authorization cache.

Session, delegation, membership and credential revocations commit with audit/revision. Checks beginning after commit must observe revocation even while a JWT remains valid. In-flight work may finish; long jobs reacquire short-lived credentials and check each side effect. Workspace departure preserves personal resources. Full dangerous-action approval classes belong to M5.

### 3.5. Identity APIs and storage

The current internal implementation is `services/core/modules/identity`; public auth is in Gate. Session operations, service/user invocation exchange, delegation operations and public-key lookup have explicit caller policy. Local methods for users/workspaces/groups/service accounts are not automatically public APIs; product administration and approved Gate APIs remain [#9](https://github.com/pavlith/arc/issues/9).

Identity stores users, password hashes, sessions, refresh families/token hashes, workspace principals, service public keys, agents, delegations, signing-key metadata, assertion/proof nonces, command results and audit. Enforce one membership per workspace/user, same-workspace groups, unique account/key IDs and persistent anti-replay. Private keys, NKey seeds, refresh plaintext, passwords and OAuth secrets must not appear as plaintext SQL values or logs. Initial user/recovery bootstrap is local, not public RPC.

## 4. Resource registry and ACL

Core owns identity/access metadata; domain services own content and enforce decisions for every ingress protocol. Gate authorization does not replace recipient authorization.

### 4.1. ACL roots

Register only independently permissioned roots: personal/workspace roots, calendars, address books, Files/Pages sections, agents and workflows. Ordinary tasks/events/files/pages may reference a root without a registry row. `business_parent` and `acl_parent` serve different purposes.

| Storage | Rules |
|---|---|
| Resource types | Namespace, provider, approved digest, actions and inheritance policy |
| Resources | UUID, type/provider, `owner_kind=user|workspace`, owner/workspace, optional parent, inheritance flag, lifecycle, policy revision |
| Grants | Resource, principal kind/ID, action, optional expiry, creator; allow-only |
| Operations | Idempotency key, request hash, operation, resource, state and result |
| Policy audit | Verified actor/delegation, change, resource and revision; no secrets |

Personal roots may have no workspace; workspace roots require `owner_id=workspace_id`. One acyclic ACL parent must share owner/scope in M0. `inherit_acl=false` stops ancestor grants without changing ownership or system safeguards. Sharing adds a grant rather than moving ownership. Root reparenting/ownership transfer is outside M0. Workspace group/role grants stay in the same workspace; M0 personal sharing targets individual users.

Core creates the corporate `arc.workspace` root, the workspace, its owner membership and both audit records in one SQLite transaction. The root shares the workspace UUID and carries no domain permissions. The registry uses a disabled internal identity for the provider foreign key. Domain providers still own their content roots and use the existing reservation and activation protocol. An owner can archive a workspace. The transaction revokes memberships and pending invitations, removes group assignments and closes the corporate root. Subsequent Access checks deny workspace-scoped roots. Domain data and personal roots are retained.

### 4.2. Check algorithm

Actions are exact contract-defined strings. `calendar.free_busy` does not imply `calendar.read`; ACL management does not imply content read/download. Fabric validates operation/action mappings.

1. Verify invocation claims, target operation, caller proof/key and live Identity state. Unverified calls are `UNAUTHENTICATED`.
2. The domain owner resolves the actual object/root/workspace relationship from its database. A client-supplied accessible root cannot authorize an unrelated object.
3. Require an active root, valid ownership/scope and parent chain.
4. Resolve live principals in the resource workspace. Collect matching unexpired direct/ancestor grants up to the inheritance boundary.
5. A personal owner receives the type's permitted owner actions. Workspace owners/admins may manage corporate ACL, but need an explicit content grant to read/download. Authorized ACL managers can explicitly self-grant, with audit: M0 does not promise confidentiality from an administrator who can grant access. `share` grants only the initiator's existing actions and cannot grant ACL management. Owner recovery is a separate privileged audited procedure.
6. Intersect delegated user rights, consent, agent tools and approved service actions. Autonomous services use explicit grants. Broker permissions provide an additional boundary. Otherwise deny; M0 has no deny-grants or positive cache.

Signed downstream `source_aud/source_op` derive from the verified incoming invocation. Exact `DownstreamFrom/DownstreamActions` prevent `free_busy → Access.Check` from becoming read, even for a resource owner. Clients cannot select provenance at exchange.

Policy denial yields `PERMISSION_DENIED` or contract-defined concealing `NOT_FOUND`; an unavailable authority yields `UNAVAILABLE`/HTTP 503. New checks after revoke commit see the change; immediate cancellation of in-flight work is not promised. Streaming and collaborative editing require later rechecks.

### 4.3. Access v1

| Operation | Contract |
|---|---|
| `resource_types.register` | Approved contract/provider only; no public installation endpoint |
| `resources.reserve` | Verified provider/actor, owner/parent and idempotency key; returns reserved UUID |
| `resources.activate` / `abort` | Same provider; activate after committed domain binding; safe replay |
| `resources.begin_delete` / `finalize_delete` | Authorization, deletion confirmation, audit and revision |
| `check` | Verified actor, resource/action → allowed/revision |
| `check_many` | At most 100 pairs from one consistent policy snapshot |
| `list_accessible_roots` | Paginated owner/workspace/type/action filtering without hidden metadata |
| `grants.add` / `revoke` | ACL management or bounded share authority; transaction, audit/revision; revoke optionally binds `resource_id` to the grant's actual root |
| `grants.list` | Paginated direct unrevoked/unexpired grants for one root; live ACL management authority and policy snapshot; no implicit/inherited rights |
| `principals.validate_users` | Batched active user/membership and target-action checks in one root snapshot; requires the invocation-approved actor action; returns validity only |

Names use `access.v1.*`; concrete RPC subjects follow §5.3. Check payload contains resource/action, not trusted actor/caller. Listings also apply domain filters. Use batched checks rather than N+1 RPC. Denial diagnostics are limited to trusted auditors.

### 4.4. Cross-database root lifecycle

1. Provider reserves a root after actor/parent authorization; repeated identical input returns the same ID, changed input conflicts.
2. Provider commits its object/root binding and outbox locally while keeping it unpublished.
3. Access verifies the provider's committed receipt and activates the root; the provider then exposes the object and publishes the pending event.
4. Provider reconciliation retries incomplete transitions; an uncommitted expired reservation may be aborted. Timeout alone never deletes an active root.
5. `begin_delete` blocks new access; provider deletes/archives idempotently and finalizes. Retention governs physical cleanup.

There is no distributed SQL transaction. Every step must tolerate crash and replay.

### 4.5. Required security cases

| Case | Expected result |
|---|---|
| Leave workspace A while belonging to B | A corporate access ends; personal/B resources survive |
| Free/busy without read | No titles/attendees |
| ACL admin without content grant | Can manage ACL; cannot download until an explicit audited grant |
| Inheritance disabled | Ancestor grant excluded; owner/scope unchanged |
| Foreign object with an accessible root | Domain binding check rejects |
| Agent lacks delegation or current user rights | Denied |
| Forged JWT/caller/proof/body, wrong audience/op, replay | No effect; safe error/audit |
| Session/key/membership/grant/delegation revoked | New checks deny despite unexpired JWT |
| Self-issued delegation or replayed service assertion | Denied |
| Access unavailable | Fail closed without cached allow |

Minimal M0 guardrails are mandatory; exhaustive automation belongs to M7 (§10). Cross-workspace/group sharing of personal data, public links, root transfer and streaming revoke require later contracts and tests.

## 5. Service Fabric and SDK

Arc uses one root Go module, `github.com/pavlith/arc`. `sdk/transport` is an Arc-native, deliberately narrow NATS service transport using `nats.go` for connections, request/reply, JetStream and TLS/NKey. It implements the public Micro v1 PING/INFO/STATS monitoring protocol and queue endpoints; it is not a wrapper or fork of the whole upstream `nats.go/micro` package. Domain handlers use approved SDK composition, not raw transport endpoints.

### 5.1. Catalog and instance lifecycle

| Entity | Meaning |
|---|---|
| ServiceDefinition | Stable logical service/publisher and installation policy |
| ServiceContract | Immutable approved manifest, API major, schemas/resources/actions/events/exposure and digest |
| ServiceInstance | Ephemeral process identity, build version, digest, readiness and lease |
| RouteSnapshot | Monotonic atomic revision of approved routes, independent of live containers |

An operator-signed installation binds publisher, service account/deployment, deterministic artifact digest and exact subjects. Fabric commits contract, Access types, revision and audit atomically. One active digest per service/API major prevents incompatible handlers sharing a queue. Replacement requires revocation and conservative same-major compatibility: preserve existing operations/auth/responses/events; optional request fields may be added. Breaking changes require a new major. No business allowlist fallback exists when the live catalog is unavailable.

Startup: scoped broker connection → authenticated `ctl.arc.fabric.register` → approval → install all required handlers → local self-check, signed instance probe and exact Micro INFO/queue verification → `.ready`. Assertions use distinct audiences, full request proof and persistent replay checks. Core control responses are signed and bound to request ID/subject/expiry. Lease is 30 seconds, heartbeat 5 seconds; each business RPC checks live approval/lease. Reconnect repeats registration/readiness. Revocation or failed control closes processing. Discovery text alone is not proof; missing responders produce `UNAVAILABLE`, not contract deletion.

### 5.2. Manifest v1

An install artifact contains manifest and local JSON schemas. Digest covers the canonical manifest and sorted canonical schema paths/hashes, not arbitrary YAML formatting. Reject unknown manifest fields, external/file schema loaders, namespace/action/route collisions and executable selectors. Schemas define their own required fields and `additionalProperties` policy.

Operations declare stable ID, query/command kind, exact subject, request/response schema, auth action/root selector, size/timeout/idempotency and optional HTTP/tool/workflow exposure. Exposures default off independently. Root/workspace selectors are restricted paths, not code; the domain owner verifies the actual binding. Approval cannot invent unknown resource actions.

```yaml
manifest_version: 1
service: {name: calendar, build_version: 1.0.0, api_major: 1}
resources:
  - {type: calendar, actions: [read, create, update, delete, share, manage]}
operations:
  - id: calendar.events.create
    kind: command
    subject: rpc.calendar.v1.events.create
    request_schema: schemas/calendar.events.create.request.v1.json
    response_schema: schemas/calendar.events.create.response.v1.json
    auth: {action: calendar.create, resource_from: payload.calendar_id}
    idempotency: required
    timeout_ms: 10000
    http: {expose: true, method: POST, path: "/api/v1/calendars/{id}/events", success_status: 201}
    tool: {expose: false}
events:
  - {name: calendar.event.created, subject: evt.calendar.event.created.v1, schema: schemas/calendar.event.created.v1.json}
```

This is a contract illustration; Calendar is not implemented. Gate bindings must explicitly map HTTP fields to payload selectors.

### 5.3. RPC, subjects and delivery

```text
rpc.<service>.v<major>.<operation suffix>  # queue q.<service>.v<major>
evt.<service>.<entity>.<event>.v<major>    # durable fanout
ctl.arc.<operation>                      # explicit bootstrap/control policy
ctl.runtime.v1.node.<node-id>.<operation>  # closed node protocol, §7.2
```

Domain subjects use fixed approved tokens; resource/user/workspace IDs belong in payload. The node ID is an explicit, provisioned exception for private Runtime subjects. Wildcard `$SRV.>` access is restricted to monitoring/admin identities.

RPC v1 JSON carries `request_id`, `operation`, `schema_version`, `deadline_at`, optional `idempotency_key`/`traceparent`, invocation `auth`, `proof` and typed `payload`. Reply contains the same request ID and either `data` or `error{code,message,retryable}`. Input/output schema validation is required.

| Error | HTTP |
|---|---|
| `UNAUTHENTICATED` / `PERMISSION_DENIED` / `NOT_FOUND` | 401 / 403 / 404 |
| `VALIDATION_ERROR` / `CONFLICT` / `RATE_LIMITED` | 400 / 409 / 429 |
| `UNAVAILABLE` / `DEADLINE_EXCEEDED` / `INTERNAL` | 503 / 504 / 500 |

Expose safe messages, never SQL, stacks or secrets. HTTP success status comes from the approved route. Query timeout defaults to 5 seconds, command to 10 seconds; effective deadline is the smaller caller/contract budget. UTF-8 envelope and response limits are 256 KiB. Reject invalid versions before execution.

Commands atomically store actor/operation/key, request hash, result, mutation, audit and outbox. Retain replay ≥24 hours; changed payload conflicts. Validate response before commit. Clients retry an uncertain timeout with the original key; SDK/Gate never silently issue a new-key mutation retry. External side effects do not have an exactly-once guarantee.

Events include stable `event_id`, type/version, aggregate ID, occurrence time and trace, with minimal nonsecret metadata. Publish committed outbox using a stable JetStream message ID. Durable consumers atomically commit inbox deduplication and internal effects, then ACK. Retry with backoff; after five deliveries copy to `dlq.<approved-event-subject>.<durable>` before completing the original. Event/DLQ permissions and Fabric permits are explicit. An event subscription grants no resource read authority. Long work uses asynchronous jobs (`202`/job ID), not a held RPC.

Downstream `incoming_api_major` defaults to 1 and must match the incoming signed audience and approved source operation/action map. It cannot change identity or expand authority.

### 5.4. Routes and versioning

Fabric validates method, normalized path and major, including static/parameter/wildcard collisions. System prefixes such as `/api/v1/arc/*`, `/health*` and `/dav/*` cannot be captured by domain contracts. Runtime announcements do not create public routes.

Snapshot wire format is `SignedSnapshot{payload,signature}`. Payload includes revision, issued time, `kid`, digest, routes/bindings and artifacts. Digest is SHA-256 of canonical `{routes,artifacts}`; Ed25519 signature covers canonical `["arc.route_snapshot.v1", payload]`. Reject rollback or equal revision with a different digest; identical revision/content is replay-safe. Older unsigned/non-domain-separated forms are rejected.

`ctl.arc.fabric.routes` uses signed-service assertion/proof and exact `fabric/v1:fabric.v1.routes` bootstrap policy. A separately pinned RouteTrustKey signs request-bound `RouteBundle(snapshot, active JWKS, request_id, expires_at, signature)` with domain separator `arc.route_bundle.v1`. Snapshot kid must be a live Identity verification key. Gate does not trust reply publisher or unsigned change hints; hints trigger authenticated fetch and periodic reconciliation repairs missed notifications.

Gate atomically swaps immutable validated tables. Cold start serves no dynamic routes before a valid snapshot; a bad update retains the previous table while online auth remains mandatory. Signed HTTP bindings are scalar `{source:path|query,name,field,type}`; reject missing path bindings, unknown query keys, body collisions and authority fields. Body is a JSON object. Validate response before HTTP delivery. Commands cannot use GET/HEAD. Build SemVer and API major are distinct; incompatible handlers never share a queue.

### 5.5. SDK API boundaries

Actual packages: root `sdk` for App/bootstrap transport, `sdk/transport`, `sdk/service`, `sdk/module`, `sdk/client`, `sdk/rpc`, `sdk/contract`, `sdk/events`, `sdk/security`, `sdk/agent` and optional `sdk/telemetry`. Core owns Identity, Access and Fabric. See [SDK README](../sdk/README.md).

Protected handler pipeline: verify invocation/proof → validate schema → resolve domain ownership/root → online ACL → effect → response validation/observation. Manifest configuration cannot disable security checks. Private bootstrap/health operations use explicit separate policy. Typed bindings use package helpers (`sdk.Handle`, `sdk.HandleCommand`, `module.BindQuery/BindCommand`); workers start after readiness.

## 6. Gate and protocol adapters

The initial shared WebSocket invalidation protocol, ownership boundaries and
fail-closed conditions are specified in [REALTIME.md](REALTIME.md), tracked by
[#27](https://github.com/pavlith/arc/issues/27). This is a planned Gate adapter,
not an existing public API. No separate realtime database or public NATS ingress
is introduced.

Gate is a standalone HTTP process without a database. HTTPS is direct or behind explicitly trusted proxy CIDRs; forwarded headers are accepted only from trusted peers, resolving client IP from the right of the proxy chain. Configure header/read/write/idle deadlines, graceful shutdown, 200 KiB HTTP bodies within the 256 KiB RPC envelope, bounded per-IP rates and explicit HTTPS CORS origins. `/healthz` is liveness; `/readyz` reflects accepted routes and reconciliation.

Browser auth uses POST `/api/v1/arc/auth/login`, `/refresh`, `/logout` and GET `/api/v1/arc/auth/session`. Login requires allowed Origin and returns session metadata and CSRF data. Session and refresh credentials are Secure/HttpOnly/SameSite=Lax `__Host-` cookies. The CSRF cookie/header must match and Identity checks its hash for mutations. Browser sessions issue no Bearer token. CLI clients use POST `/api/v1/arc/cli/token`, `/refresh` and `/logout` without Origin or cookies. CLI token families rotate independently of browser families. Bearer uses Core `Verifier.Access` with `aud=gate` and live session. Mixing Bearer and session cookie is rejected.

POST `/api/v1/arc/auth/register-invited` accepts only `email`, `password` and
`token`, requires an allowed Origin and applies a per-client rate limit. Core also
limits registration attempts. It calls the exact operator-approved
`identity.v1.sessions.register_invited` RPC with Gate assertion/proof; Core rejects
callers whose live service definition is not `gate`. The 201 response contains
`user_id`, `workspace_id` and one-time `recovery_code`, with `Cache-Control:
no-store` and no auth cookies. Invitation links keep tokens in URL fragments; the
UI removes the fragment and keeps the token and recovery code only in memory.

The reserved `/api/v1/arc/identity/` routes map to exact operator-approved `identity.v1.product.*` RPCs. Core verifies the Gate assertion and request proof, then resolves the live browser session and checks current workspace membership or administrator authority. Workspace commands check permission inside their owner transaction before replay. Domain Task routes still require a verified Fabric snapshot and operation-bound invocation.

Task root discovery has two workspace-scoped browser queries. GET
`/api/v1/arc/identity/task_roots/list?workspace_id=<uuid>` returns roots with live
`task.read`; GET
`/api/v1/arc/identity/task_roots/managed/list?workspace_id=<uuid>` returns roots
with live `access.grants.manage`. This lets an owner/admin discover an ACL
administration scope without granting content access. An active workspace member
with an explicit ACL management grant can also discover that scope; workspace
membership alone does not reveal roots.

Both lists return at most 100 active registry roots ordered by ID, with optional
`after` cursor and per-root `can_read`, `can_write` and `can_manage` flags from one
policy/time snapshot. Flags describe domain ACL permissions, not service approval
or domain availability, and are not bearer authority. Readable-root filtering is
unchanged. The managed list exposes root IDs and flags only, and needs the exact
Gate bootstrap operation `identity.v1.product.task_roots.managed.list`. Task still
checks its own root/workspace binding and live ACL before every subsequent read
or grant operation. Archived workspaces and revoked browser sessions are denied.

GET `/api/v1/arc/identity/invitations/list?workspace_id=<uuid>&after=<uuid>`
uses `identity.v1.product.invitations.list`. Only live workspace owners/admins can
read its email-bound invitation history. Results contain at most 100 entries,
ordered by ID, with `pending`, `accepted`, `revoked`, `expired` or `invalidated`
status, issuer ID and optional consumption/revocation timestamps. `invalidated`
means the issuer is disabled or no longer an owner/admin. Accepted/revoked states
take precedence over expiry and issuer state. Tokens and token hashes are never
returned; archived workspace access is denied.

Installation user administration uses GET
`/api/v1/arc/identity/users/list?email=<email>&status=<active|disabled>&after=<uuid>`
and POST `/api/v1/arc/identity/users/status` with `user_id` and `status`.
All list filters are optional. Email lookup is exact after trimming and
lowercasing; pages contain at most 100 entries ordered by ID, exposing only ID,
email, status and creation time. Gate accepts email query values up to 254 bytes.
Both operations require a live browser session and an installation administrator
from signed `AdminUsers`; workspace owner/admin roles do not grant this authority.
Gate also needs the exact `identity.v1.product.users.list` or
`identity.v1.product.users.status` bootstrap approval. Status commands require
Origin, CSRF and `Idempotency-Key`; live administrator authority is checked inside
the transaction before command replay. The browser API rejects self-disable.

Disabling an account atomically updates its status, revokes all sessions and
refresh families, revokes its outstanding issued workspace invitations and writes
the audit. Unknown users return not found. Re-enabling changes account status
only: previous sessions, refresh families and revoked invitations stay revoked;
workspace memberships, groups and resources are preserved. A status response is
an empty object. Registration policy configuration remains separate work.

Account APIs use the same Gate-only product namespace and live browser
session/CSRF checks:

| Method and path under `/api/v1/arc/identity/` | Input | Behavior |
|---|---|---|
| GET `account/sessions/list` | Optional `after` UUID | At most 100 own live sessions ordered by ID, including channel and creation/expiry times; no secrets or hashes |
| POST `account/sessions/revoke` | `id` | Revoke one own session and its refresh families, including the current session; normal command replay applies while the calling session remains live |
| POST `account/password/change` | `current_password`, `new_password` | Verify the current password, change it and revoke all own sessions/refresh families; clear browser cookies |

Account POSTs require Origin, CSRF and `Idempotency-Key` like other product
commands. Password changes use a one-shot credential protocol: neither passwords
nor responses enter persistent command replay storage, and the revoked session
cannot repeat a successful change. Each operation requires its exact signed
`identity.v1.product.account.*` bootstrap approval for Gate.

POST `/api/v1/arc/auth/recover` accepts `email`, `code` and `password` without an
existing session, with an allowed Origin and per-client/Core rate limits. The
exact signed `identity.v1.users.recover` approval is required. Core verifies the
one-time recovery code, rotates its hash, replaces the password and revokes all
account sessions/refresh families atomically. The response returns the next code
as `code` once, with `Cache-Control: no-store`; Gate clears auth cookies and does
not log the user in. Incorrect email/code pairs have the same authentication
error. A lost success response cannot recover the next code by replaying the old
one. Email delivery and a recovery UI remain separate work.

Profile/settings migration `000013_profile_settings` adds global name,
display name and profile revision, personal preferences and workspace slugs.
GET `identity/profile` also returns the current installation-admin flag derived
from signed policy, never from request data; member/group user projections omit
that flag. POST `identity/account/profile/update` changes only the caller's name
and display name with optimistic profile revision. Email and authority fields
cannot be changed through this operation. Avatar metadata is null until a
separately authorized asset upload is installed.

GET `identity/account/preferences/get` returns caller-only presentation settings
with revision 0 for defaults. POST `identity/account/preferences/update` accepts
`revision` and a partial `changes` object, merges only known typed preference
keys and validates the complete result. Null values are rejected. Settings are
bounded to 32 KiB and carry no authority or foreign content. The write, audit and
idempotent result commit together. Workspace removal does not remove personal
preferences.

Workspace create optionally accepts a lowercase slug; omitted slugs default to
the new UUID. Workspace rename can also change its slug by current revision.
Slugs are globally unique address aliases, 3–63 characters, lowercase letters,
digits and internal hyphens. Reserved application routes and another workspace's
UUID are rejected. Existing workspaces retain their IDs and initially use them
as slugs. GET `identity/workspaces/by_slug?slug=...` resolves only an active
workspace with live membership and returns its canonical workspace/root IDs.
All subsequent authorization remains UUID/root-bound. A renamed slug has no
implicit redirect or reserved old alias.

Each protected request validates session online, exchanges a target invocation, and signs a fresh Gate proof. The recipient repeats invocation, domain binding and ACL checks. Preserve request ID, traceparent, deadline and original idempotency key. Missing responder → 503, deadline → 504, authority outage → fail closed. Snapshots do not cache authorization. Public auth exposes no installation or Runtime administration.

WS and DAV are planned adapters behind Gate, with the same resource checks. CalDAV requires iCalendar, recurrence/timezone, ETag/sync tokens and distinct free/busy rights; scheduling follows client compatibility work. CardDAV preserves vCard extension fields. WebDAV requires approved method/client coverage and private HTTP/object streaming. Public shares use scoped revocable tokens; DAV credentials and browser sessions are distinct. Remote DAV sources belong to Connectors, not server adapters.

## 7. Runtime Control and Infrastructure Agent

Runtime is an infrastructure control plane for trusted nodes, including independent VPS. Agent initiates private outbound TLS/NKey NATS; no second gRPC transport or public Docker/LXD API is introduced. Docker/LXD/systemd are separate typed drivers. A type in the SDK does not establish a working driver; explicit target nodes do not imply a scheduler. Arc service readiness still requires Fabric.

Current executable capabilities and limitations are maintained in [Agent README](../services/agent/README.md) and [services](../services/README.md). [#13](https://github.com/pavlith/arc/issues/13) tracks remaining M6 integration. M0 requires the safe contract/fake-provider baseline, not live Docker management; implementing a limited Agent early does not complete M6.

### 7.1. Data and management boundary

Core owns nodes, approved templates, typed resources/deployments, immutable revisions, operations, receipts, observations, audit and hint outbox. Operation states are pending/running/succeeded/failed/cancelled. Desired state is running/stopped/deleted. Observations and Fabric instances are distinct: host running/health does not prove approved API readiness. Secrets remain references.

`runtime.Control` implements `sdk/agent.RuntimeProvider`. Enable it with both trusted `RuntimeControlPolicy` and `RuntimeSnapshotSigningKey`; partial configuration fails and default Control is nil. Manager policy requires live `arc.runtime.manage` for a verified nondelegated Arc admin; Node policy derives service identity from trusted context. DTOs cannot choose actors. Storage additionally checks active user/node/service bindings. Administrative policy and Gate adapters are not implemented.

`RegisterNode` binds a node permanently to one active `arc-agent` service account and capabilities; disabled nodes cannot be resurrected. Template revisions are immutable and revocation irreversible. Core approval does not install the node's independent local allowlist.

`Apply` accepts revision zero/empty template digest, expected revision and idempotency key. Core assigns current template digest and next revision, committing resource/operation/revision/audit/outbox together. Resource node/kind binding is immutable; deletion leaves a tombstone. Actor-scoped replay rechecks authorization; changed payload conflicts. New revision cancels prior pending/running operations and preserves terminal history. Legacy arbitrary desired JSON is retained as storage only and never reaches a driver.

### 7.2. Node protocol and snapshot execution

| Invocation (`aud=runtime/v1`) | Subject suffix under `ctl.runtime.v1.node.<node-id>.` |
|---|---|
| `runtime.v1.node.inventory` | `inventory` |
| `runtime.v1.desired.get` | `desired.get` |
| `runtime.v1.node.report` | `report` |

`RuntimeNodeRPC=true` requires Control and installs Core's actual Identity verifier. Exact signed bootstrap rules allow only these service-actor operations without business actions/downstream. They cannot expose management or arbitrary control subjects. Require self-service identity `sub=service:<caller>`, without session/workspace/delegation/upstream claims. Verify invocation/proof, persistent nonce, live account/node/policy, subject/payload node and resource ownership. Assertions alone are insufficient. Network identity overrides any custom local Node policy.

Agent broker permissions allow only its three subjects and Identity service exchange; reply subscriptions are restricted to `_INBOX.runtime.<node-id>.>` through SDK InboxPrefix. Core binds active nodes at startup; new enrollment needs restart, while disable/key/policy revoke is live. Partial binding aborts startup. NodeClient fixes node identity and deadlines ≤5 seconds. Report retry preserves event ID with a fresh proof nonce.

Inventory returns own resource IDs, including tombstones, in pages of 100: hints, not execution authority. Pull returns only current resource/operation and approved template for the active node. Snapshot v1 binds fresh request ID (16–128 characters), operation, node, issued/expiry ≤30 seconds and typed Spec. Ed25519 signs RFC 8785 bytes with `arc.runtime.snapshot.v1\n` domain separation. Verify pinned Core key, request/node/expiry, monotonic revision, template ID/revision, driver kind and SHA-256 digest of the complete canonical template. SpecDigest also uses RFC 8785. Reject unknown fields even with a valid signature; no shell, raw env, mounts or arbitrary command fields.

Operator-installed templates use immutable Docker `@sha256:` image, local LXD fingerprint or exact preinstalled systemd unit. LXD/systemd allow one replica. Bootstrap targets are forbidden. Driver ownership, dependencies and host policy remain mandatory after template validation.

Before an effect, persist revision, spec digest and operation ID. Reject lower revision or changed content/operation at the same revision. A completed replay returns saved observation unless an Inspector rechecks host state; drift repair requires a fresh online snapshot and retains durable intent. Incomplete intent may retry only after new pull. Drivers must tolerate crash after effect/before result, honor snapshot-bounded context/cancellation, and retain data on delete. Journal errors forbid effects.

Reports bind node/service, event/operation/revision/spec digest and approved template. Success requires matching desired/observed replicas, not inferred Fabric readiness. Commit report receipt, observation, operation, node liveness and audit together. Exact duplicate changes nothing; altered duplicate or new stale report is rejected. Management reads require live policy and pagination. Hint outbox contains resource/node/revision/operation on `.changed`; publisher and Core reconciler remain unimplemented.

### 7.3. Reconciliation and failures

Agent runs serial online inventory/pull rounds with bounded backoff. Missing inventory IDs do not request deletion. No new effects occur from cached commands when Core/NATS is unavailable; existing workloads survive. Pending report retries preserve event ID in process memory; after crash a new receipt is possible while host effects remain idempotent. New successful observations refresh liveness. Failed operations are terminal and require explicit new desired revision; a complete health channel after terminal operations is still absent.

The standalone Linux Agent owns a private durable, exclusively locked journal. SIGTERM/SIGINT close connections/journal without stopping workloads. Its current systemd driver operates only root-owned, preinstalled `arc-managed-<resource-id>.service` with matching template ID. Fixed show/start/stop calls reject aliases, drop-ins, unsafe dependencies and noncanonical ownership/path. Delete stops while retaining unit/data. Installation, enable/restart and unit edits remain operator work. The Docker driver manages approved, locally available images on the node's Unix socket and persists container ownership before effects. Current restrictions and verification limits are in the [Agent README](../services/agent/README.md). LXD is not implemented.

Target Core reconciliation uses a lease/single active owner; stale operations cannot overwrite newer revisions. Failures produce bounded retry, Degraded/Failed and safe codes rather than endless restarts. Docker recovery must independently verify deployment ownership, not adopt by label alone. M6 may use single-node recreate with downtime; rollback/zero-downtime need migration compatibility evidence. Never purge volumes automatically.

### 7.4. Bootstrap and privilege boundary

SQLite, NATS/JetStream, Core, Gate, root credentials and Agent itself are independently provisioned bootstrap. Runtime may observe them but cannot reinstall, delete or reconfigure them. Only nondelegated Arc admins with `arc.runtime.manage` manage infrastructure; workspace-admin and agent/workflow permissions do not imply it.

Only Agent accesses the privileged runtime API. Compromise may compromise the host; ordinary Docker is not a hostile-code isolation guarantee. Managed containers require approved immutable images; deny privileged mode, host PID/network/IPC, runtime sockets, devices, arbitrary host binds/capabilities/entrypoint/env/ports. Templates bound CPU/RAM/PIDs/disk, user, dropped capabilities, seccomp/AppArmor and network policy. Secret/config changes create new revisions; secret values never enter events/logs. Public ingress remains Gate; host port publishing defaults off. Hostile plugins require stronger VM/microVM isolation.

### 7.5. Milestones and checks

M0: schema/interfaces, fake Agent, signed snapshots, replay/revision/template/bootstrap guardrails and independent bootstrap contract. Live Docker, UI installation and scheduling are not M0 requirements.

M6: integrated single-node Docker lifecycle, approved templates, desired/observed reconcile, protected node transport, admin Gate/UI and safe retained volumes; typed LXD/systemd and trusted VPS support use the same boundary and are accepted separately. Require an executed happy path and critical privilege denials per implemented driver. Full replicas, crash/offline/reconnect, stale/spoofed requests, recovery and secret-leak matrices belong to M7. Multi-node placement, automatic rollback and zero-downtime remain beyond the baseline.

## 8. Domain services and tools

| Service | Planned scope |
|---|---|
| Task | Tasks/projects/statuses/subtasks/boards/views; GitHub optional |
| Calendars | Personal/shared calendars, events and CalDAV |
| Contacts | Address books and CardDAV |
| Files | Files/versions/shares, local/S3 storage and WebDAV |
| Pages | Hierarchical Tiptap documents/history/resource links; no Notion databases MVP |
| Agents | Bounded runs, approved tools and consent |
| Workflows | Events/schedules, CEL, Starlark, durable typed actions |
| Connectors | Owner connections, external APIs, webhooks and optional DAV sources |

Resource links grant no access to targets. Search and previews recheck resource ACL. Existing Task/Notify are proof services, not the full Kuayle migration. Task create/get/list uses verified workspace roots; lists are limited to 100 own tasks. Reserve/domain receipt/activate establishes roots.

Files' initial local byte backend has exactly one process owning its database
and storage directory. Orphan reconciliation requires the owner database's
single connection: promoted bytes are deleted only after the completion
transaction commits or rolls back, a successful lookup finds no catalog
reference in any state, and the object is older than 26 hours. A different
connection limit disables this pass with an error. Referenced bytes are never
collected by crash recovery; retention is a separate policy. See
[Files](FILES.md#abandoned-promoted-objects).

Files catalog rename/move/archive operations require a current revision and
transactional replay/audit/outbox. Moves remain inside the bound root;
archive hides metadata and stops downloads at their next ready-state check
without deleting retained bytes. Metadata uses revision CAS; byte ETags remain
content hashes. The exact routes and actions are specified in
[Files catalog mutations](FILES.md#file-catalog-mutations-files-040).
Filename search uses the same live read policy and ready-file/root constraints;
its literal matching and bounded pagination are specified in
[Files name search](FILES.md#file-name-search-files-050).

`task.roots.grants` is exposed as POST
`/api/v1/task/workspaces/{workspace_id}/roots/{acl_root_id}/grants`. Adding requires
`action` (`task.read` or `task.create`), `principal_kind` (`user`, `role` or `group`)
and `principal_id`. Revoking uses `grant_id`; legacy descriptive fields are
optional and do not choose the grant being revoked. Path-bound workspace/root
fields cannot also appear in the HTTP body. Both paths require live
`access.grants.manage`, an active domain root bound to that workspace and exact
approved Gate/Task/downstream Access operations. Browser mutations require
Origin/CSRF; CLI uses its separate Bearer flow. An `Idempotency-Key` is required.
Task rechecks domain binding and management authority before local command replay.

Task passes the bound root as `resource_id` on Access revoke. Access rejects a
grant from another root before applying the mutation, and rechecks the actual
grant's action authority. User recipients must be active workspace members,
groups must belong to that workspace, and roles must be one of its four roles.
Grants permit only the two content actions above; this endpoint cannot delegate
ACL administration. Mutations retain Access audit/revision and cross-service
idempotency. Permissions UI remains separate work.

GET `/api/v1/task/workspaces/{workspace_id}/roots/{acl_root_id}/grants?limit=100`
uses `task.roots.grants.list` and an exact downstream `access.v1.grants.list`
invocation. Task checks the domain root/workspace binding and live
`access.grants.manage` before forwarding; Access repeats live caller/session and
management checks in the same policy/time snapshot as the query. Content read or
bounded share permission alone cannot enumerate grants. No direct HTTP Access
route is exposed.

The required `limit` is 1–100; optional `cursor` is the last grant UUID from the
previous page. The response includes `resource_id`, `grants`, `policy_revision`
and optional `next_cursor`. Each entry has ID, principal kind/ID, action and
optional expiry. Only stored direct, unrevoked, unexpired grants are listed;
this is not an effective-permission calculation and can include grants whose
principals no longer qualify. Inherited grants, implicit owner authority and
revocation history are excluded. Each page is independently authorized and
snapshot-consistent; concurrent edits may change later pages and their revisions.

Private `identity.v1.invocations.verify` checks recipient audience, JWT/proof/nonce and live state, returning a Core-signed response bound to full envelope hash, subject, claims and five-second expiry. Domain services receive no Core DB credential. `auth.workspace_from` provides an exchange context selector, not membership authority.

Notify installation pins Task provider/digest/subject/durable. `ctl.arc.fabric.event_permit` requires current approvals/readiness before pull/effect. Recipient addressing comes from operator-managed Notify subscriptions, not event fields. Inbox/notification/outbound intent commit together; ACK follows commit. The persisted SHA-256 notification/recipient/channel key is reused by the fake provider. Real outbound delivery may duplicate without provider idempotency. Runtime/Task product UI, richer Office features and external channels remain separate Issues.

## 9. Storage, observability and resilience

Use owner-local SQLite with WAL, foreign keys, 10-second busy timeout, explicit Gormigrate history and complete-transaction retry on SQLITE_BUSY. Obtain write locks before reading mutable policy/domain state. Independent SQLite file replicas or network filesystems do not provide shared state; same-owner processes may share one local file. Gate may replicate independently.

Back up using SQLite backup API or stop the owner while preserving committed WAL, plus objects, secrets and relevant JetStream state. Workspace export is not disaster recovery. Online authorization cannot fall back to a saved snapshot during Core outage. Jobs require leases or idempotent distribution.

Required diagnostics include safe structured logs, request/trace IDs, operation latency/errors, auth/ACL denial, delivery lag and desired/observed health. The M0 [diagnostic baseline](DEVELOPMENT.md#correlated-diagnostics) correlates nested RPCs, Agent reconciliation and JetStream publication/inbox processing. Correlation metadata grants no authority and does not change signed input, replay keys or transaction boundaries. Full health/log reporting and the M7 matrix remain separate. Never log payloads, credentials or secret env. Do not turn M0 into a general policy engine, scheduler or plugin platform.

## 10. Verification policy

### 10.1. Readiness levels

| Level | Evidence |
|---|---|
| Implemented | Builds; empty-DB migration and principal path run manually or through a test client |
| Integrated | Connected to Arc, observable, passes focused smoke and required boundary guardrails |
| Verified | Full relevant M7 unit/integration/contract/E2E/security/recovery matrix executed |

M0–M6 need Integrated for their accepted scope; production requires Verified. A narrow tested subsystem does not promote the entire platform. Code absent from the checkout has no current readiness claim.

### 10.2. Required M0–M6 checks

Use formatting/static analysis and focused build/tests for affected code, empty-DB/replay for migrations, schema/manifest validation for changed contracts, and one changed-path smoke. Documentation-only work does not trigger builds/tests. Add meaningful regression coverage for an actual defect.

Never defer invocation/proof vectors; ACL deny/revoke/cross-root; migrations; idempotency/outbox/inbox atomicity; digest/version/route collision; Runtime privilege/template boundaries; or one login → Gate → domain → Access → DB → event/consumer path. Prefer a short deterministic loop; do not rerun unrelated successful checks without cause.

### 10.3. Testability and deferred cases

Use replaceable time/UUID/network/storage/provider adapters, separate domain logic from handlers, version schemas/fixtures, accept stable idempotency keys and provide reproducible seed paths. Tests remain beside code; shared infrastructure belongs in `test/`. Deferred scenarios are recorded in the owning GitHub Issue with ID, preconditions and expected outcome, not a duplicate Markdown backlog.

### 10.4. M7

After M6 feature freeze, execute exhaustive business/unit, permission, browser/accessibility/localization, DAV client, replica/reconnect, crash/soak/load, backup/restore/upgrade and recovery coverage, then rerun release regression after fixes. No new product features except testability work and defect correction. See [requirements §8](REQUIREMENTS.md#8-m7-verification).

## 11. Repository layout

```text
cmd/{arc-core,arc-gate,arc-agent,arc-task,arc-notify}/
services/core/modules/{identity,access,fabric,runtime}/
services/{gate,agent,task,notify}/
services/<owner>/migrations/
services/<service>/api/
sdk/                       # library in the root Go module
test/                      # shared fixtures and test CLI tools
scripts/                   # verification and operational helpers
deploy/                    # example config, Dockerfiles, explicit migrator
docs/                      # requirements, architecture and development
```

`cmd/arc-core` uses the existing Core composition with strict owner-local bootstrap. Product Identity is available through approved Gate routes. The SvelteKit web app uses Svelte 5 and shadcn-svelte in `client/web/`. Its TypeScript Gate client lives in `client/ts/`. Do not create separate Go modules or restore legacy paths for compatibility.

## 12. Decision register

These IDs identify architecture decisions, not similarly numbered delivery Issues.

| ID | Decision |
|---|---|
| A-01–A-07 | Go/Echo direction, Svelte 5, one modular Core, NATS between processes, Gate ingress, owner data and independent privileged Agent |
| M0-01 | Selective ACL roots, separate personal/workspace ownership, allow-only grants and bounded inheritance |
| M0-02 | Online Access checks, default deny/fail-closed, post-commit revoke visibility |
| M0-03 | Session/refresh revocation; separate broker identity, Ed25519 operation-bound invocation/assertion/proof |
| M0-04 | Immutable canonical contracts; approved instance identity, exact queues and readiness |
| M0-05 | Typed schema RPC, fixed limits/errors, atomic replay and signed routes |
| M0-06 | Root lifecycle, transactional outbox and inbox/internal-effect atomicity |
| M0-07 | GORM/SQLite per owner, shared Core DB, explicit Gormigrate, Gate without DB |
| M0-08 | Expiring consent and online intersection of user/grantee/ACL rights |
| M0-09 | Core desired state, independent Agent, M0 fake baseline, M6 limited executor |
| M0-10 | Operation-bound invocation, audited ACL self-grant, signed snapshots and no external exactly-once claim |
| T-01 | Build-phase Integrated; full hardening in M7; production requires Verified |
| R-10 | Typed Docker/LXD/systemd infrastructure on trusted nodes over NATS; no arbitrary shell or second gRPC transport |
| O-01 | M1 adaptation preserves Arc IDs/data and workspace/root ACL; automatic import and personal Task roots are separate extensions; see [Task product model](TASK-MODEL.md) |
| O-02 | M2 cross-workspace sharing, scheduling and DAV client matrix |
| O-03 | M3 WebDAV locking/versioning/upload links and stream reauthorization |
| O-04 | M4–M5 Starlark limits, approval classes, connector secrets and plugin sandbox |
| O-05 | Beyond M6: scheduling, zero-downtime, automatic rollback and hostile-code isolation |

Update this document and requirements when semantics change. Record implementation work in Issues; do not add duplicate ADR/status reports.
