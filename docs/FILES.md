# Files service — initial implementation contract

Tracking: [#29](https://github.com/pavlith/arc/issues/29). Stage 3 of
[shortplan](shortplan.md). **Implementation in dev:** signed Files 0.7.0 has 35 public folder/upload/file/grant/avatar operations and 4 hidden private byte operations, scoped root lifecycle, owner SQLite migrations, audit/replay/outbox, SQL/disk-synchronized chunk append, cleanup and repeated ACL checks during streaming. **Private streaming is opt-in** and routed through Gate using Core-verified Ed25519 proof and mTLS. Isolated live acceptance is described below; production deployment remains open.

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

## Delivered first slice (Files 0.1.0)

The signed artifact `services/files/api/v1/contract/` exposes six folder operations under
`/api/v1/files/workspaces/{workspace_id}/roots/{acl_root_id}/folders`:
POST create, GET list (`limit=1..100` + ID cursor), GET item, PATCH rename,
POST `/{folder_id}/move`, DELETE archive. Commands require a stable
`Idempotency-Key`; rename, move and archive require the current revision.
An empty `parent_id` means the root; archival of a nonempty folder is rejected.
Folder IDs cannot be moved across roots or used to bypass a live Access check.
Mutations write owner-local audit plus metadata-only catalog outbox atomically.

The owner must run `bash scripts/migrate.sh files /absolute/files.sqlite` before
launching `go run ./cmd/arc-files -config /path/to/files.json`. Example config:
`deploy/files/config.example.json`. No migration runs on service startup.
The only declared event is `evt.files.catalog.changed.v1`; JetStream stream,
NKey publisher ACL and signed Fabric service installation must be provisioned
explicitly. The resource type is `files.workspace`, with actions
`files.read`, `files.create`, `files.write`, `files.delete`,
`files.share`, and `access.grants.manage`. The domain root must be reserved,
prepared with a signed Files provider receipt, activated in Access, and then
activated in Files before browser requests can succeed.

**Still open:** production NATS grants, private CA/cert provisioning and operator-approved production installations. The opt-in private streaming code does not imply successful production deployment.

## Local byte adapter (internal, not an upload API)

`services/files/storage` implements an opt-in private `os.Root` local disk
backend. It rejects caller-controlled paths and non-UUID keys, requires
private storage directories, enforces 8 MiB maximum append chunks and
1 GiB maximum objects, checks exact offsets, rolls back partial writes,
and promotes verified SHA-256 bytes without replacing existing blobs.
Preparation, append, promote, read and abort are **internal primitives**.
They cannot be called by browsers or untrusted RPC clients. Root-scoped
Identity/Access checks, SQL upload sessions, authorization on chunk and
download streaming, and expiry/orphan reconciliation must be wired before
these bytes can be exposed through Gate.

## Upload metadata contract (Files 0.2.0, implementation in progress)

Files' signed contract now includes upload initiate, status, abort and complete,
plus ready-file GET/list. The upload initiator is the only actor/session that
may inspect or complete its upload. Size is at most 1 GiB, the upload expires
after 24 hours, and the initial declared MIME is restricted to
`application/octet-stream`. The complete operation promotes only when
physical and SQL offsets match the requested length, verifies SHA-256,
writes ready metadata and emits an outbox invalidation. If the SQL transaction
fails after local promotion, reconciliation must remove the unreferenced blob.
This is not a complete HTTP upload service: private chunk write and download
routes through Gate, session revalidation, cleanup and stream cancellation are
still required before public use. No production installation is implied.

### Pending upload reservation guardrail

Files caps each actor to 10 unexpired pending upload sessions and 2 GiB of
reserved bytes, independently of workspace quotas. Both caps are checked in
the upload command transaction. Completion replaces the reservation with a
catalog row; abort or expiry releases it. See workspace capacity below.

## Private chunk transaction (internal Files adapter)

`objects.Module.AppendChunk` now requires a verified invocation context and an
online `files.create` authorization for the exact active root on every call.
The upload is also bound to the verified actor and session. It accepts only
1–8 MiB chunks (up to the remaining length), serializes owner-local appends,
checks the provided offset against SQLite, reconciles uncommitted disk tails
from interrupted requests, and advances the SQL offset with a scoped CAS.
If that transaction fails, the disk is rewound to the last committed offset.
Gate now signs the exact upload scope/offset/length and relays bytes over
mutually authenticated TLS. Files verifies the Core proof and checks live
`files.create` permissions before the append and repeatedly during slow
body reads (at least every 256 KiB or one second). No browser identity
headers are trusted by the private listener.

## Durable abandoned-upload cleanup

Files uses owner-local GORM migration `000002_upload_cleanup` to record
`uploads.cleaned_at`. Abort now commits the metadata state **before** deleting
any bytes. The bounded `files-upload-cleanup` worker marks expired pending
sessions, deletes their temporary bytes (and those of aborted sessions), and
records completion. It retries interrupted cleanup safely, rather than
removing the file inside a potentially rolled-back SQL command. This handles
known SQL upload rows. Orphan files lacking an upload row and abandoned
promoted objects are handled by the reconciliation pass below.

### Abandoned temporary inodes

The cleanup worker now scans its private pending directory in bounded batches
and removes UUID-named temp files older than **26 hours** only when SQLite
has no active/pending-cleanup upload referencing them. This covers a process
crash between creating an inode and committing an upload row. A disk failure
while deleting is surfaced, not treated as successful cleanup. Committed blobs
are protected by the promoted-object reconciliation pass below.

## Bounded private read primitive

`objects.Module.StreamDownload` requires a verified scoped identity and an
online `files.read` check before touching disk. It reads only `ready`
metadata in the same ACL root, validates the committed object size, copies
at most 256 KiB per write, and repeats online authorization before each
block and on completion. A cancellation or rejected Access check stops
further delivery. This remains an **internal** primitive called by the opt-in Files private
mTLS listener. Gate only exposes an approved public byte URL when the same
signed Fabric snapshot includes the matching public metadata operation and
the exact hidden private operation. Live multiuser acceptance remains open.

## Opt-in private Gate ↔ Files streaming (0.3.0)

Files adds the hidden, signed RPC operations `files.uploads.chunk` (command)
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

**Acceptance remaining:** test the full live Core → Gate → private mTLS → Files
pipeline with two users and two workspaces, validate actual certificate trust,
network loss/retry under load, process failures, Access revocation during a
long download and upload, operator install/uninstall, and cleanup of promoted
blobs that fail metadata commit. The domain unit tests use a local fixture
identity authority and do **not** replace live Core cryptographic acceptance.

## Abandoned promoted objects

The cleanup worker also scans UUID-named `.blob` objects in bounded directory
batches. It removes objects older than 26 hours only after a successful Files
SQLite lookup confirms that **no file row in any state** references the blob key.
Recent objects and all referenced objects are retained; this is crash recovery,
not deletion of archived files or a file retention policy. Database failures
stop the pass without deleting the candidate, and disk failures are surfaced.

This relies on the initial deployment model: exactly one Files process owns
its SQLite database and local byte directory. The single database connection
serializes reference lookups behind completion transactions, including SQL
rollback after promotion. Sharing the byte directory between independent
processes or changing the database connection limit requires a new coordination
contract before enabling this worker. No public endpoint or signed operation
changes; existing cleanup also reclaims leftover pending links.

## File catalog mutations (Files 0.4.0)

The approved metadata contract adds PATCH `.../files/{file_id}` (rename),
POST `.../files/{file_id}/move` and DELETE `.../files/{file_id}` (archive).
Commands require an idempotency key and current positive `revision`.
Rename/move require `files.write`; archive requires `files.delete`.
Every operation binds the current workspace/root and requires live Access.
Rename reuses upload filename validation; duplicate file display names remain
allowed. Move accepts an active folder in the same root; omitted `folder_id`
means the root. Cross-root moves and archived target folders are rejected.

Successful mutations increment the metadata revision and atomically commit
owner-local audit and a metadata-only catalog invalidation. A stale revision
is a conflict. Content hashes and byte ETags stay unchanged across metadata
updates; callers use `revision` for metadata CAS. Archive returns `archived:
true`, hides the file from GET/list/download, and retains its blob and catalog
row for a future retention policy. Subsequent mutations cannot revive it.
Downloads recheck ready state before each 256 KiB block and at completion;
archiving terminates the transfer at its next state check. An in-flight block
may already have been written. Rename/move do not interrupt a download or
change headers already sent. No schema migration is needed: the initial file
table already includes archive state and timestamp.

New operations require operator-approved installation of the new complete
artifact and refreshed Gate routes. This source change does not authorize
production signing or deployment.

## File name search (Files 0.5.0)

GET `.../workspaces/{workspace_id}/roots/{acl_root_id}/search` maps to
`files.files.search` and requires live `files.read` on the bound root.
Required `query` is a trimmed, nonempty UTF-8 string of at most 256 characters.
Matching is a case-sensitive literal substring of the filename; `%`, `_` and
backslashes have no wildcard meaning. This initial search does not read file
contents, perform Unicode case folding, or expose other roots.

Without `folder_id`, search covers all ready files within the current root.
An explicit folder selects only its direct files and must be active in that
same root. Archived files are excluded. `limit` is 1–100; the exclusive UUID
`cursor` and `next_cursor` use ascending file IDs as in list. Results are live,
not a snapshot: callers retain the same query/folder while paging and refetch
after invalidations. The response is the existing bounded `FilesResult` shape.
No full-text index, schema migration or browser UI is introduced. Deploying
0.5.0 requires approving its new complete artifact and refreshing Gate routes.

## Workspace capacity (Files 0.5.1)

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

## Personal sections (Files 0.6.0)

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
activation. Migration `000003_personal_roots` records the immutable user owner
alongside each personal root. Existing workspace roots retain empty owner IDs.
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

Approve both resource types at the same Files 0.6.0 artifact digest, all 38
operation subjects (including four hidden byte subjects), and exact Gate rules
for the declared action of each operation. Files' downstream `access.v1.check`
rule must map each `files/v1:<operation>` source to its declared action only.
Root provisioning may exchange the corresponding folder-create invocation for
`access.v1.resources.reserve` / `activate`, permitting only `files.create`.
Grant sources `files/v1:files.roots.grants` and
`files/v1:files.personal.roots.grants` may exchange only for grant add/revoke,
with the declared type actions. No bootstrap Access wildcard is needed.
Apply `000003_personal_roots` explicitly before restart, approve the new signed
artifact, then reconcile Gate. Old installations do not implicitly approve the
new operations. No production signing key or credential is included in the repo.

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

Full-network `-race` instrumentation can exceed the unchanged 5-second metadata
budgets because each request verifies/exchanges multiple Ed25519 invocations.
The current full-network instrumented run hit a metadata deadline; it is not
reported as a passing live guardrail. Focused Files/Gate package race checks
and the ordinary live network scenario are recorded independently.

## Attachments and avatar assets (Files 0.7.0)

Validated PNG/JPEG uploads and owner/session-bound avatar receipts are specified
in [resource integration](RESOURCE-REFERENCES.md). Image routes use the same
private signed Files download operation with an explicit signed `image` flag;
ordinary content remains an attachment. Target metadata reads used by Task or
Pages require exact signed read edges, preserving workspace scope and live ACL.
