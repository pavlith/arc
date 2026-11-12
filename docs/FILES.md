# Files service

Files owns metadata, scoped personal/workspace roots, resumable uploads, private mTLS byte transport, cleanup, quotas and safe image routing. Exact operations live in its [signed manifest](../services/files/api/v1/contract/manifest.json). Acceptance is tracked in [#29](https://github.com/pavlith/arc/issues/29). See [resource references](RESOURCE-REFERENCES.md) for Task attachments and avatars.

## Ownership and authorization

Files is a separately deployed Go service with its own SQLite database,
GORM/gormigrate migrations, signed contract, NATS outbox and local blob store.
Gate exposes approved metadata routes through normal signed HTTP RPC.
Raw upload/download bytes travel only through an authenticated private HTTP
streaming adapter behind Gate; NATS carries bounded metadata events only.
Files never reads Core/Task/Pages tables. Personal files use a personal
Identity-bound ACL root; workspace files use explicit workspace + Files root
scope. A business folder does not create an implicit ACL grant.

Every list, search, metadata operation, upload chunk, completion and download
must revalidate the active session and the exact Files read/write/delete
action against the target root. A known UUID or a reference from Task/Pages
does not grant access. Cross-root move is **not** supported initially: copy
and explicit reauthorization is a separate future operation. A move within a
root is an atomic metadata transaction. Never expose file titles, filenames,
size, content type or existence to unauthorized callers.

## Metadata and persistence

- `folders`: id, workspace/root, parent_id, normalized display name,
  revision, timestamps, archived_at. Enforce same-root parent and prevent
  ancestry cycles on move. Unique active sibling name within a root.
- `files`: id, workspace/root, folder_id, display filename, declared MIME,
  sniffed MIME, size, SHA-256, blob key, revision, ETag, timestamps,
  archived_at, state. Only `ready` files are returned by normal reads.
- `uploads`: opaque upload ID, actor/session binding, target root/folder,
  expected byte count, expected SHA-256 (optional), temporary blob key,
  offset, expiry, state and idempotency key. Never expose filesystem paths.
- `outbox`: bounded, metadata-only events committed atomically with visible
  metadata changes; no bytes, filenames or download URLs in payloads.

Enforce SQLite foreign keys, unique scoped keys, revision-based CAS updates
and cursor pagination. Use deterministic opaque blob keys; do not derive a
filesystem path from a user-controlled name.

## Upload and download protocol

1. `initiate` validates scope, folder, sanitized filename, declared MIME,
   quota and requested size, then creates a 24-hour pending upload with
   a fixed chunk size and a bounded offset. Return upload ID, offset, expiry.
2. `PATCH /uploads/{id}/bytes` is a private Gate-streamed request. It
   requires a current actor/session/root authorization and exact offset.
   Reject overlaps and conflicting retries. Write chunks to a temporary
   file, `fsync` as needed, then advance the committed offset.
3. `complete` requires full length, verifies SHA-256 and detected MIME,
   atomically promotes the temporary blob to a durable local key and
   commits a `ready` metadata row + outbox in SQLite. If the DB commit
   fails, orphaned promoted blobs are eligible for reconciliation.
4. `abort` marks the upload aborted and removes temporary bytes
   idempotently. A sweeper expires incomplete uploads and reconciles
   orphaned temporary/promoted blobs without deleting referenced ready
   objects.
5. `GET /files/{id}/content` requires fresh authorization and streams
   only `ready` bytes with safe Content-Disposition, nosniff and ETag.
   A conditional GET must not bypass authorization. Stream cancellation,
   session expiry or revoked grants terminate the transfer.

Initial limits: 1 GiB/file, 8 MiB/chunk, 24-hour upload expiry,
256-character UTF-8 filename after normalization, no path separators,
control characters or dot-only names. Reject ambiguous MIME and executable
active content for inline delivery; default to attachment download. The
stream adapter uses bounded buffers (at most one chunk per connection).
No unlimited request buffering or public presigned URLs. Quota accounting
reserves pending upload bytes and releases on abort/expiry.

## Required signed contracts and deployment

Metadata operations: folder create/list/get/rename/move/archive; file
list/search/get/rename/move/archive; upload initiate/status/complete/abort.
Byte streaming uses separately approved private Gate routes with explicit
actor/root checks and short cancellation deadlines. File deletion is soft
metadata deletion initially; blob garbage collection requires reference
and retention policy. Add exact service identity, NATS subjects, signed
producer/consumer approvals, Gate route bindings, migrations and config
examples before enabling the service. Local disk root must be absolute,
writable only by Files and outside any static/public web root. S3 is a
future adapter, not a second backend in this release.

## Acceptance gates

Verify two users/two workspaces with known-ID access denial, cross-root
move denial, offset replay/conflict, concurrent completion, aborted upload,
expired session during streaming, grant revocation during download, hash
mismatch, cancellation, orphan cleanup, migration replay and bounded memory
for a 1 GiB transfer. Preserve errors without leaking target existence.
A successful code build or migration is not live acceptance.

## Catalog, reconciliation and search

Folder/file create, get, list, rename, same-root move and archive use current scoped permissions, revision CAS, idempotency and atomic audit/outbox. A pending upload is actor/session-bound; only complete ready files are readable. Literal, case-sensitive filename search has a 256-character query, no wildcard expansion, 1–100 result page and an exclusive ID cursor; it never searches content or other roots.

Abort persists state before removing temporary bytes. Bounded cleanup retries interrupted expiry/abort operations, checks orphan temporary files and removes promoted objects only after a successful owner SQLite reference lookup and a 26-hour safety window. DB errors stop deletion. Archived objects are not garbage-collected without a separate retention rule. All blob keys are private UUID-scoped storage keys, never user-controlled filesystem paths.

## Private Gate ↔ Files streaming

Files uses the hidden, signed RPC operations `files.uploads.chunk` (command)
and `files.files.download` (query), without exposing these as generated public
RPC endpoints or carrying any bytes over NATS. The NATS-bound placeholders
deny calls. The private `services/files/stream` HTTPS receiver decodes a
bounded, strictly validated, Core-proof-bound invocation envelope and requires
a verified **client mTLS certificate**. Files' Core RemoteAuthorizer verifies
the original Ed25519 invocation proof, actor/session, audience and live state.
The receiver then rechecks the exact Files ACL root for each upload/download.

The opt-in browser-facing paths are:

| Method | Path | Data |
|---|---|---|
| `PATCH` | `/api/v1/files/workspaces/{workspace_id}/roots/{acl_root_id}/uploads/{upload_id}/bytes` | `Content-Type: application/octet-stream`, `Content-Length` 1–8 MiB, `Upload-Offset`, `Idempotency-Key` and bytes |
| `GET` | `/api/v1/files/workspaces/{workspace_id}/roots/{acl_root_id}/files/{file_id}/content` | Attachment body, no Range requests in v1 |

Use a browser's usual Secure session cookie and CSRF token for mutation, or an
eligible Bearer token; Gate authenticates via Core before exchanging a token
scoped to the exact hidden Files operation. Gate refuses these URLs without
a currently verified signed Fabric route snapshot containing their sibling
metadata operation and an exact approved hidden Files operation. Gate does
not forward browser Authorization/Cookie headers or let clients choose the
private URL or service identity.

The example configuration files are `deploy/files/config.example.json`
(`stream_listen`, `stream_tls_cert_file`, `stream_tls_key_file`,
`stream_client_ca_file`) and `deploy/gate/config.example.json`
(`files_stream_url`, `files_stream_ca_file`,
`files_stream_server_name`, `files_stream_client_cert_file`,
`files_stream_client_key_file`). The Gate mTLS client pins the private Files
server name and CA, disables redirects and proxy lookup; Files requires TLS
1.3 and a client certificate issued by the configured CA. Disable the
private listener simply by omitting every stream key. Partial stream
configurations are rejected instead of enabling an insecure fallback.
Do not publish Files' private HTTPS port to the public internet. Provision
client/server certificates, private NATS permissions and signed Fabric/Access
installation before enabling these example settings.

Use the [isolated live fixture](#reproducible-isolated-live-acceptance) for the signed Core/Gate/mTLS/Files path. Production certificates, separate-process installation, crash/load and operator recovery require additional release acceptance; fixture authority is not a production approval.

## Workspace capacity

Operator-only `quota.workspace_bytes` and `quota.workspace_files` settings
apply to each workspace across **all roots and users**. Defaults are 10 GiB
and 10,000 files; zero selects the default, negative values are invalid.
Supported maxima are 1 PiB and 1,000,000 files. Configuration changes require
a service restart; clients cannot choose or override their limits.

Before creating an upload, Files counts all persisted file rows (including
archives) plus unexpired pending uploads. File size and expected upload size
consume byte capacity; zero-byte uploads still reserve a file slot. A command
that would exceed either limit returns the existing generic conflict error,
without exposing other users' filenames, counts or usage. The quota decision
and new reservation share the serialized replay transaction, so concurrent
users cannot reserve the same remaining capacity. Replays do not reserve twice.

Completion converts a reservation to an equal-sized file and slot. Abort or
expiry frees only the reservation; the cleanup worker removes abandoned bytes.
Archived files retain both their bytes and capacity until an explicit future
retention policy removes them. Lowering limits below existing usage preserves
data and denies additional uploads. Read/download, metadata operations and
abort remain available. These are catalog/reservation quotas, not a measurement
of filesystem free space; orphan recovery and operator disk monitoring remain
necessary. Workspace quotas do not provide per-workspace self-service quota management;
personal owner quotas are defined below. No migration or new public route is required.

## Personal and workspace roots

Personal operations have distinct `files.personal.*` IDs and subjects under
`rpc.files.v1.personal.*`, the same action names, and resource type
`files.personal`. Their public paths use `/api/v1/files/personal/roots/{acl_root_id}`
in place of `/workspaces/{workspace_id}/roots/{acl_root_id}`. They do not select
an Identity workspace: incoming and downstream invocation claims must have no
workspace. Personal requests omit `workspace_id` (only the empty string is
accepted if supplied); responses and metadata events encode it as `""`.
Workspace routes retain their required UUID and `files.workspace` type.

An operator/provider provisions a personal root through Core reserve with
`owner_kind=user`, the active user's UUID and no workspace, followed by
`PreparePersonalRoot`, signed domain receipt, Access activation and Files
activation. The Files baseline records an immutable user owner for personal
roots; workspace roots have empty owner IDs.
The Files policy checks root kind and exact scope before live Access; it does
not infer ownership or trust a browser-supplied user ID. Individual-user sharing
uses Core grants. It does not add workspace membership or implicit group rights.
Root provisioning remains an internal lifecycle, not an unapproved HTTP route.

All folder/file/upload/search operations and private byte adapters support both
scopes with separate approved operation IDs. Personal byte routes use the same
mTLS connection and Core proof/session verification as workspace byte routes;
Gate must find the exact matching hidden personal operation and public metadata
operation in the same approved artifact. Moving objects between roots/scopes is
forbidden. Uploads remain bound to the initiating user and session even when the
root has been shared. Personal sections have owner-wide quota settings
`quota.personal_bytes` and `quota.personal_files` (defaults 10 GiB / 10,000),
shared across that owner's roots; uploads by grantees charge the root owner.
Scope changes do not bypass actor reservation limits. Lowering a personal quota
preserves stored data and stops new reservations just as for workspaces.

### Root grant management

POST `.../roots/{acl_root_id}/grants` in each scope maps to
`files.roots.grants` / `files.personal.roots.grants`. It requires a current
`access.grants.manage` decision and a stable idempotency key. Add accepts only
`principal_id` (an active user UUID) and a declared action. Revoke accepts only
`grant_id`; Files always binds the downstream revoke to the URL's root.
The request cannot set resource ID, owner, workspace override or principal kind.
Personal sharing is individual-user only. Workspace group/role grant workflows
remain available through their owning Core APIs, not this initial Files form.

Core owns grants and policy audit; Files never writes Core tables. The incoming
actor is exchanged through the exact approved downstream grant operation.
A digest of actor/operation/idempotency key binds the downstream command; a
retry after a Files transaction failure cannot duplicate the Core effect.
Only user-management invocations permit these mutations: streaming and ordinary
read/create invocations cannot be used as grant-management authority.

### Installation and provisioning for both scopes

Approve both resource types at the same current Files artifact digest, all approved
operation subjects (including four hidden byte subjects), and exact Gate rules
for the declared action of each operation. Files' downstream `access.v1.check`
rule must map each `files/v1:<operation>` source to its declared action only.
Root provisioning may exchange the corresponding folder-create invocation for
`access.v1.resources.reserve` / `activate`, permitting only `files.create`.
Grant sources `files/v1:files.roots.grants` and
`files/v1:files.personal.roots.grants` may exchange only for grant add/revoke,
with the declared type actions. No bootstrap Access wildcard is needed.
Initialize an empty Files database with its owner migrator, approve the exact
artifact, then reconcile Gate; see [installation policy](DEVELOPMENT.md#pre-stable-api-rollout).
No production signing key or credential is included in the repo.

## Reproducible isolated live acceptance

Run `bash scripts/test-files-live.sh` with Go, a C compiler and the repository's
pinned `nats-server` version on PATH. The fixture creates temporary owner SQLite
databases, TLS CA/leaf certificates, distinct NKey roles and an actual loopback
NATS process with JetStream. Core, Files and Gate run their production Go
composition/handlers in the test process; RPC travels over TLS/NKey NATS, public
requests use HTTPS Gate, and bytes use a real mutual-TLS private listener.
Core verifies real Ed25519 invocation proofs and live sessions/ACL decisions.
The script runs the standalone migrator twice on a fresh/reopened database;
the test also runs owner migration replay, provisions signed installations and
roots, and requires durable outbox publication. Temporary credentials and data
are removed; no production account, database or certificate is used.

The scenario covers two active users and two workspaces plus user-owned roots;
upload initiation/chunk/completion/download in both scopes; known-ID metadata
and byte denial; personal sharing and grant/session revocation; root/workspace
substitution and grant-root binding. Transfer-revocation cases schedule the
real Core mutation after the first 256 KiB write and require an incomplete
HTTP body at the declared length. No authority or ACL decision is mocked.
This is isolated live backend evidence, not production deployment, browser UI
acceptance, a separate-process Core/Files rollout or full M7 verification.
The 1 GiB memory/load matrix and production certificate/operator rollout remain
separate acceptance work.

Full-network race instrumentation adds cryptographic overhead but does not relax metadata deadlines. Record its result separately from ordinary live acceptance and focused package race checks in the owning Issue.

## Attachments and avatar assets

Validated PNG/JPEG uploads and owner/session-bound avatar receipts are specified
in [resource integration](RESOURCE-REFERENCES.md). Image routes use the same
private signed Files download operation with an explicit signed `image` flag;
ordinary content remains an attachment. Target metadata reads used by Task or
Pages require exact signed read edges, preserving workspace scope and live ACL.

