# Files service — initial implementation contract

Tracking: [#29](https://github.com/pavlith/arc/issues/29). Stage 3 of
[shortplan](shortplan.md). **Implementation in dev:** signed Files 0.1.0 folder metadata CRUD, scoped move/archive, root lifecycle methods, owner SQLite migration, audit, replay and outbox are committed. No file-upload or download streaming has been implemented or deployed.

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

**Still open:** personal sections, file metadata operations, byte storage,
initiate/complete/abort, private streaming Gate routes, quotas, orphan cleanup,
production NATS grants and two-user acceptance. The existing Files SQL tables
for ready bytes/uploads are reserved for this next implementation step; they
do not imply that those endpoints are exposed.

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

Until tenant-level quotas are implemented, the Files metadata owner caps each
actor to 10 unexpired pending upload sessions and 2 GiB reserved bytes. This
is a strict temporary protection, not a complete tenant quota or cleanup
subsystem. The service must not be exposed for arbitrary byte transfer until
expiry, cross-owner quotas, and the private Gate stream authorization are live.
