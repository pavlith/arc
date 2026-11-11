# Files service — initial implementation contract

Tracking: [#29](https://github.com/pavlith/arc/issues/29). Stage 3 of
[shortplan](shortplan.md). **Implementation in dev:** signed Files 0.3.0 has 12 public folder/upload/file metadata operations and 2 hidden private byte operations, scoped root lifecycle, owner SQLite migrations, audit/replay/outbox, SQL/disk-synchronized chunk append, cleanup and repeated ACL checks during streaming. **Private streaming is opt-in** and routed through Gate using Core-verified Ed25519 proof and mTLS. Deployment and two-user acceptance remain open.

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

**Still open:** personal file sections, file rename/move/archive/search, full tenant-level quotas, orphaned promoted-object garbage collection, production NATS grants, private CA/cert provisioning, operator-approved service installations and two-user/two-workspace live upload/download acceptance. The opt-in private streaming code does not imply successful production deployment.

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
promoted objects still require their own retention-based reconciliation.

### Abandoned temporary inodes

The cleanup worker now scans its private pending directory in bounded batches
and removes UUID-named temp files older than **26 hours** only when SQLite
has no active/pending-cleanup upload referencing them. This covers a process
crash between creating an inode and committing an upload row. A disk failure
while deleting is surfaced, not treated as successful cleanup. Committed blobs
must be retained: automatic garbage collection of promoted objects without
SQL metadata still needs its own safe reference/retention protocol.

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
