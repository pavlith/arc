# Files service — initial implementation contract

Tracking: [#29](https://github.com/pavlith/arc/issues/29). Stage 3 of
[shortplan](shortplan.md). **Design only**: no public Files API or byte
stream is deployed by this document.

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
