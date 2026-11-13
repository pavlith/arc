# Mail service design

Mail 0.4.0 implements personal IMAP connection settings, sealed password
submission, pause/resume/disconnect, live folder discovery, message summaries, MIME structure and a bounded
user-requested TLS IMAP check.
Folder/message synchronization and persistence, content caching/streaming, OAuth provider flows,
workspace accounts and sending remain planned. Requirements:
[MAIL-01–MAIL-10](REQUIREMENTS.md#214-mail--imap-p1). This connection foundation does
not satisfy full MAIL-10 or establish Gmail/Microsoft compatibility.

## Implemented connection API (0.4.0)

The [signed contract](../services/mail/api/v1/contract/manifest.json) exposes nine
operations under `/api/v1/mail/personal/accounts/{acl_root_id}`. Each account is
one `mail.personal` root, owner-bound with an empty workspace. Account provisioning
is an explicit operator reserve → `Accounts.PrepareRoot` → Access activation →
`Accounts.ActivateRoot` workflow. Public root creation, account discovery and
sharing APIs are deferred. Separate roots support multiple accounts per user.

| Method / suffix | Operation / required action |
|---|---|
| GET base | `mail.personal.accounts.get`; `mail.read` |
| PUT base | Full settings replacement with expected `revision`; `mail.connection.manage` |
| GET `/credentials/key` | Current scoped sealing public key/binding; `mail.connection.manage` |
| PUT `/credentials` | Write-only sealed password replacement with expected `revision`; `mail.connection.manage` |
| POST `/state` | Set enabled/paused/disconnected with expected `revision`; `mail.connection.manage` |
| POST `/check` | Current-user TLS authentication/capability check; `mail.connection.manage` |
| GET `/folders` | Live folder discovery; `mail.read` |
| POST `/messages/list` | Live message summaries in bounded UID windows; `mail.read` |
| POST `/messages/structure` | Live MIME structure and attachment metadata for one UID; `mail.read` |

Settings are `name` (1–256 Unicode characters), ASCII DNS/IP `host` (≤253), `port`
(1–65535), `login` (1–320) and bare display `email` (≤254). Text is UTF-8,
trimmed and control-free; hostnames normalize to lowercase. Only implicit TLS and
password/application-password authentication are implemented. Checks negotiate
AUTHENTICATE PLAIN (with/without SASL-IR), or TLS LOGIN when permitted by the server.
The adapter sends CAPABILITY, authentication, LIST, read-only EXAMINE, UID FETCH
metadata and LOGOUT. Bodies, remote mutations and mailbox changes remain unavailable. Query deadlines remain 5 s; network policy defaults to 2 s and permits
100–3000 ms, bounded by the caller deadline. Server input is capped at 64 KiB,
4096 bytes per line, 128 total lines and 32 response lines per command. Only eight
recognized capability names can appear in the safe result.

GET `/folders` authenticates under the current user request, sends LIST and returns
scope, account revision/generation, safe status and `folders`. Each entry contains
`name`, exact wire bytes encoded as unpadded base64url `wire_name`, nullable
`delimiter`, server `attributes` and `selectable` (false for \Noselect). These are
live transport bindings, not durable folder UUIDs or permissions; future message
operations must bind their selectors to the account/generation. No folder cache,
background session or migration is introduced.

Accept atom/quoted/literal mailbox names, quoted/NIL delimiters and bounded
attributes. IMAP4rev1 names decode modified UTF-7; IMAP4rev2 names decode UTF-8.
UTF8=ACCEPT negotiation for rev1-only servers and extended LIST return data are
not implemented. Reject malformed encodings, control characters and duplicate
wire identities. Maximums are 64 folders, 1024 wire bytes/name, 32 attributes of
64 characters, 256 total response lines for folder sessions and 128 KiB serialized
folder data, within the existing 64 KiB aggregate server-input and 4096-byte line
budgets. Error/limit results contain an empty list, never a success-shaped partial
listing. Large accounts need a subsequent bounded discovery/cache design; this
query has no pagination or silent truncation. Reauthorize `mail.read` and verify
the account revision after network I/O, including for read-only grantees.

Folder discovery requires operator approval of its artifact digest and exact
`mail.personal.folders.list` / `rpc.mail.v1.personal.folders.list` read/check edge.
The same operator destination and TLS policy applies; no production permission
is widened automatically.

POST `/messages/list` is a read-only query with a 5 s deadline, under the same TLS,
destination and `mail.read` checks. Supply the `generation` and exact `wire_name`
from account/folder discovery, plus `uid_window` (1–20). For example, using values
from the actual discovery response:

```json
{"generation":1,"wire_name":"SU5CT1g","uid_window":20}
```

EXAMINE selects the folder read-only and captures UIDVALIDITY, UIDNEXT and the
selection-time EXISTS count. Initial scanning starts below UIDNEXT. A page
examines at most `uid_window` numeric UID positions and sorts returned messages by
UID descending; this is a scan bound, not a promise of that many existing messages.
Gaps/expunges can produce empty pages. Continue with `before_uid` equal to
`next_before_uid`, the returned `uid_validity`, and the same root/generation/folder.
Each continuation advances its UID boundary even for an empty page. An absent
`next_before_uid` ends the scan. `exists` is informational and not a stable count
across requests. There is no frozen mailbox snapshot or unbounded UID SEARCH.

Stale account generation conflicts before network I/O. A changed UIDVALIDITY
returns `uidvalidity_changed`, the current namespace and no messages/continuation;
restart discovery rather than interpreting old UIDs in the new namespace. A
rejected EXAMINE returns `folder_unavailable`. Other credential/state/transport
statuses match existing reads. Malformed/ambiguous/oversized results fail without
a partial page. Cursor fields and wire names are selectors, never permissions;
individual-message reads bind UID to the same complete namespace.

Only `UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE` are fetched. Each summary has
UID, flags, internal date, byte size, decoded subject, header date, From/To address
summaries and Message-ID/In-Reply-To strings. Envelope MIME encoded words support
UTF-8 and registered legacy charsets through the existing text encoding library.
Address summaries retain display name/mailbox/host; group-boundary markers,
source routes and the other envelope address lists are not projected. This is a
summary view, not a lossless mail export or threading model. Message-ID is not a
storage identity. Fetching ENVELOPE in a read-only selection does not mark a
message Seen; other clients may still change flags/expunge while a page is read.

The parser bounds literals to 8192 bytes, nesting to eight, tokens to 8192 per
fetch and individual lists to 512 elements, within the existing aggregate 64 KiB
input/4096-byte line/256-line read budgets. Message flags are limited to 64 × 64
characters, address lists to 32, decoded text to 8192 bytes (subject ≤2048 Unicode
characters; address display names ≤256; mailbox/host ≤320; identifiers ≤1024).
Message-page JSON fits 128 KiB; remote sizes fit a safely represented JSON integer.
Unrequested full-message UIDs, duplicate metadata and unsupported extra FETCH
fields fail closed. Extended compatibility/recovery matrices remain M7 work.

POST `/messages/structure` uses the same live `mail.read` authorization, TLS policy
and 5 s deadline. Supply the current account `generation`, exact `wire_name`,
`uid_validity` and positive `uid`, for example:

```json
{"generation":1,"wire_name":"SU5CT1g","uid_validity":77,"uid":102}
```

It selects with EXAMINE and fetches only `UID BODYSTRUCTURE`, following
[RFC 9051 §7.5.2](https://www.rfc-editor.org/rfc/rfc9051.html#section-7.5.2).
The response echoes the requested wire name, UID and UIDVALIDITY and includes
account revision/generation, safe status, a preorder `parts` list and `attachments`
section identifiers. No message content is fetched or marked Seen. Multipart root
section is empty; other parts use numeric sections (`1`, `2`, `2.1`). A single-part
root is section `1`. Each part contains `media_type`, raw lowercased parameter keys,
Content-ID, decoded description, transfer encoding, nullable encoded octet size
and line count, disposition/parameters, decoded filename and `embedded` flag.
Multipart sizes/line counts are null. MESSAGE/RFC822 and MESSAGE/GLOBAL are opaque
embedded leaves: their envelope and inner sections are not projected.

Filenames prefer disposition `filename`, then content-type `name`. UTF-8/Latin-1
RFC 2231 extended/continued parameters and MIME encoded words are decoded using
standard MIME parsing. Unsupported extended parameter charsets can leave the
filename empty; raw parameters remain available. Names are untrusted display
metadata, never paths. `attachments` includes parts with attachment disposition
or a nonempty filename, including inline candidates; this is not a download URL.

Maximums are 64 projected parts, five descendant levels (also subject to the
shared eight-level data parser), 32 parameter pairs per list, 1024 characters per
parameter value and 256 per filename. Numeric sizes/line counts fit a safe JSON
integer. The entire response structure fits 128 KiB and existing transport/parser
budgets still apply. Unknown extension fields are skipped within those bounds.
Absent or concurrently expunged UIDs return `message_unavailable`; namespace resets
return `uidvalidity_changed`. All error statuses contain empty `parts` and
`attachments`, never partial metadata. Stale account generation conflicts before
IMAP I/O; the live ACL/account revision check runs again after remote I/O.

Version 0.4.0 requires explicit approval of the new artifact digest,
`mail.personal.messages.structure` / `rpc.mail.v1.personal.messages.structure` and
its exact Access read-check edge, retaining approval for message listing. No SQL
cache/migration, body/attachment transfer, retained session or autonomous
synchronization is introduced. Body/attachment bytes still require the planned
private Mail-to-Gate streaming transport.

Commands require `Idempotency-Key`. Current authorization precedes replay; retry
the exact sealed request, since resealing changes its ciphertext/fingerprint.
Replay is a historical result, not a fresh account snapshot. State changes commit
account data, audit, command result and `evt.mail.accounts.changed.v1` outbox in one
transaction. Events contain scope/revision/generation/action, without settings or
credentials. The ordinary outbox worker performs no autonomous IMAP work.

Account revision advances on every command. Remote host/port/login/display-email
changes also advance the binding generation and remove the stored password;
name-only edits retain it. Pause blocks checks but retains credentials. Disconnect
advances generation, deletes the current encrypted credential and blocks key
submission/checks until explicitly enabled; enabling does not restore a password.
Older ciphertext/results may remain in WAL/backups/replay retention, but replay
cannot recreate a disconnected credential. No remote side effect is made by
settings/state commands. Checks hold no SQL write transaction and recheck current
Access and account revision after network I/O. Concurrent changes/revocation deny
or invalidate the result. In-flight sockets close on cancellation/network deadline.

A check returns only a safe status and recognized capabilities: ok,
authentication_failed, tls_failed, destination_denied, unavailable, protocol_error,
credentials_missing, paused or disconnected. It does not persist a last-check
snapshot or continue after the current user request. Core outage denies access.

Credential ingress uses randomized anonymous NaCl boxes. `credentials/key` binds
its public information to account ID, owner, generation and current revision.
The sealed plaintext contains that binding and password bytes; server-side
comparison rejects cross-account/owner/generation/revision reuse. Only sealed
ciphertext enters signed RPC payloads and generic replay hashes. Passwords are
UTF-8, 1–4096 bytes and control-free; line terminators are rejected, not trimmed.

At rest, AES-256-GCM uses random nonces and associated data binding the personal
account/owner/generation/credential version. A private 32-byte nonzero master key
is provisioned separately from service signing keys; HMAC-SHA256 domain separation
derives independent sealing/storage keys. The public-key fingerprint is the key
ID. Wrong keys/tampering fail closed. GET never returns ciphertext/passwords.
Hot key rotation and credential export are deferred: preserve the exact master
key securely with backups; changing/losing it makes old credentials unavailable
and requires restoration or explicit credential replacement. Deletion is not a
promise of physical erasure from historical WAL/backups.

Backend clients can use the Go sealing helper or the standalone CLI. Obtain
`key-info.json` through authenticated, certificate-verified Gate HTTPS and protect
its integrity; it selects the recipient of the submitted secret. For example:

```sh
go run ./cmd/arc-mail-credential -key-info /private/key-info.json < /private/password > /private/sealed-request.json
```

HTTP path bindings supply `acl_root_id`; omit it from JSON request bodies.
The password file/pipe must contain the exact bytes without a trailing newline.
Submit the output to PUT `/credentials` with a fresh idempotency key. Preserve the
same output/key for retries. The CLI emits ciphertext only; no TS/Svelte client is
added in this delivery.

Startup uses the [configuration example](../deploy/mail/config.example.json):

```sh
bash scripts/migrate.sh mail /absolute/mail.sqlite
go run ./cmd/arc-mail -config /absolute/mail.json
```

Provision private service/NATS keys, Core's public trust root and a distinct
absolute `master_key_file` containing exactly 32 bytes with owner-only permissions.
Startup never migrates. `imap.endpoints` defaults empty (deny all). Each operator
entry requires an exact host/port and nonempty CIDR allowlist; every resolved
address must match, and the dial pins the validated IP while TLS verifies the
original host. Internal/private addresses work only through explicit policy.
Optional `imap_ca_file` adds a private CA without disabling system trust or
hostname checks. Approve the exact artifact, personal root/action bindings, Access
check/provisioning edges and broker subjects; provision the Mail JetStream event
stream separately. No production permissions or external credentials are installed
by the example.

Focused verification is `scripts/test-mail-live.sh`: isolated Core/Gate/Access,
TLS+NKey NATS/JetStream and a real local TLS IMAP fixture. Record actual results
in the owning Issue. Extended tests/provider matrices remain deferred. The design
below describes the wider service and pending synchronization/integration scope.

## Ownership and boundaries

The owner is `services/mail`, with a standalone `arc-mail` process and its own
SQLite migrations/models. A private content cache is planned.
Core retains Identity/Access/Fabric authority; Gate owns public
HTTPS and authentication. Mail owns connection configuration, encrypted external
credentials, remote bindings, synchronization state and cached message content.
Notify may later consume approved minimal Mail events for notifications.

External IMAP servers are authoritative for message content, folder membership
and flags. Arc owns connection settings, local IDs, cache policy, synchronization
consent and progress. Fetching and reconciliation must preserve this distinction.
SMTP submission, inbound SMTP/MX hosting, mail delivery and spam filtering are
outside the first delivery; operating an Arc mail server is outside this design.

User requests pass through signed Gate/Fabric operations with online Core checks.
NATS carries bounded commands, job references and metadata invalidations. Raw MIME,
large bodies and attachment bytes use an approved private Mail-to-Gate stream,
following the Files transport boundary. They never become NATS file payloads,
public cache paths or browser IMAP connections.

## Accounts and access

One Arc user can connect several unrelated accounts. A connection stores its
display name, IMAP host/port/TLS policy, remote login, display email identity,
authentication method, secret reference/version, selected folders, cache policy
and synchronization state. Remote login and display email need not be equal.
Changing host, login or account identity creates a new remote binding generation;
old cursors and message mappings cannot be reused against another account.

Each connection is an independently permissioned ACL root. Proposed types are
`mail.personal` and, for a later shared-account delivery, `mail.workspace`.
Personal roots have one user owner and empty workspace; workspace roots bind one
workspace and may grant access to its users/groups. Personal connections are not
shared implicitly with a workspace. Provisioning must follow the existing
reserve/prepare/activate lifecycle under the approved Mail provider.

Current resource actions are `mail.read`, `mail.connection.manage`, `mail.share`
and `access.grants.manage`; no public sharing operation is installed. `mail.sync`
belongs to the future synchronization contract. Managing a root alone does not confer message read;
reading messages does not expose credentials or permit connection changes.
`mail.modify` and `mail.send` belong to later explicitly approved contracts.
Final operation IDs, schemas, limits and action bindings require an implementation
Issue and exact Fabric approval before any route is exposed.

Folder/message lookup, search, job inspection and byte streaming bind their local
IDs to the verified account root/workspace. A unified Inbox aggregates only
currently readable accounts and preserves source-account identity. Known UUIDs,
email addresses and cached data do not grant access. Grant revocation or root
archive denies subsequent content access; unavailable Core fails closed.

## Authentication and credential storage

Support a generic TLS IMAP adapter using a password/application password when the
server permits it, plus provider-specific OAuth2 adapters. Negotiate IMAP4rev1/
IMAP4rev2 capabilities rather than assuming every extension is present. TLS
certificate/hostname validation is mandatory; an explicitly provisioned private
CA can support internal mail servers. Cleartext authentication and automatic
certificate-verification bypass are outside the design.

Exchange Online has removed Basic authentication for IMAP, so its adapter needs
OAuth. Microsoft documents `IMAP.AccessAsUser.All` and `offline_access` for delegated
access/refresh. Its shared-mailbox flow also distinguishes the authorizing user
from the selected mailbox. See [Basic authentication removal](https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/deprecation-of-basic-authentication-exchange-online)
and [IMAP OAuth authentication](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth).

Gmail supports SASL XOAUTH2. Its ordinary IMAP OAuth scope is
`https://mail.google.com/`, which is broader than this first delivery's read-only
behavior. Arc enforces read-only operation selection; it must not describe the
provider token as read-only. OAuth client registration, consent and applicable
provider verification remain installation concerns. See [Gmail IMAP OAuth](https://developers.google.com/workspace/gmail/imap/xoauth2-protocol).

Credentials use a Mail-owned secret-store interface with encrypted records and
an independently provisioned encryption key outside SQLite/Git. Bind encryption
to the account/scope and secret version, support key identification/rotation and
include protected key recovery in backup design. An initial implementation may
use owner-local encrypted storage; it does not establish a general connector
vault or allow other services to read Mail secrets.

Secret submission/replacement is write-only. Read APIs return safe metadata;
passwords, access/refresh tokens and OAuth authorization material are excluded
from logs, audit, events, exports and stored command results. Credential handlers
must explicitly review request hashing, retry records and OAuth callbacks so
generic command replay cannot persist a secret or an offline password verifier.
Secret references are scope-bound opaque IDs, never caller-selected filesystem
paths or references to another account's credentials.

OAuth state/PKCE and account binding, refresh-token rotation, credential write
semantics and the concrete encryption/key lifecycle require focused contracts
and security guardrails in their owning implementation Issues before credential
endpoints are enabled. The generic connector requirements
[X-01–X-03](REQUIREMENTS.md#210-connectors-p2) retain their broader scope.

## Background synchronization authority

Mail needs revocable, durable consent to synchronize one external connection
while its user has no open browser session. A worker runs as its approved service
identity with a separately bound read-only synchronization authorization; it does
not retain or impersonate a browser session. Consent binds account/root, owner,
scope, allowed remote operations and connection/credential generation.

Before each bounded batch and before publishing its local effects, validate
current account/consent state, Core authority and Fabric readiness. Jobs have
exclusive leases/fencing and cancellation; a stale worker cannot commit using a
superseded connection generation. Workspace authorization must also account for
archive and membership rules when shared accounts are introduced. Core outage
pauses background work; a saved positive decision is not an authorization fallback.

Pause stops synchronization while retaining permitted cache reads. Disconnect
revokes synchronization consent and credentials, closes active remote sessions
and fences pending jobs. Retained cache remains subject to current root ACL;
root archive/delete denies content independently of retention. Cache purge is a
separate explicit operation. Credential failures require reauthentication rather
than an unbounded login retry loop; transient failures use bounded backoff.

This noninteractive authorization contract is a prerequisite, not a capability
already supplied by the current user-invocation helpers. Specify its exact
Core/service edges and verify revoke behavior before enabling an autonomous
worker; deployment still requires exact operator-approved Fabric policy.

## Data model and synchronization

| Entity | Role |
|---|---|
| Account | ACL root, remote configuration, binding generation, consent and credential reference |
| Folder | Local UUID, account binding, remote mailbox name, delimiter/attributes and selection policy |
| Message occurrence | Local UUID bound to account, folder, UIDVALIDITY and UID; envelope, flags, size and MIME metadata |
| Content cache | Private raw MIME/body/part objects, account binding, size/digest and retention state |
| Folder cursor | Binding generation, UIDVALIDITY, progress and optional server modification sequence |
| Job | Account/generation, operation, state, lease/fence, bounded progress, safe error and retry time |

The remote identity is account + folder + UIDVALIDITY + UID. Sequence numbers and
Message-ID are not storage identities. Repeated Message-ID values do not collapse
messages across folders or accounts; Gmail-style labels may expose multiple
occurrences of related content. Provider-specific stable IDs or account-local
blob deduplication may optimize storage later without changing ACL boundaries.

On connection, discover capabilities/folders and synchronize selected folders in
bounded batches. Initial ingestion prioritizes metadata and recent messages;
history backfill is resumable and visible in job progress. Lists read local
metadata with pagination. Opening uncached content schedules a bounded fetch and
returns a job reference when it cannot finish within the normal RPC deadline.
No public request waits for a whole mailbox synchronization.

New-UID tracking is only part of reconciliation: existing flags and expunged UIDs
also need periodic comparison. A UIDVALIDITY change invalidates that folder's old
binding/cursor and triggers a controlled rescan; renamed/recreated folders must
not inherit guessed mappings. Preserve local generation history so stale IDs
cannot resolve to newly assigned remote UIDs. See [IMAP identifier semantics](https://www.rfc-editor.org/rfc/rfc9051.html#section-2.3.1.1).

Polling is the baseline. IDLE is an optional change hint for selected folders,
with periodic reconciliation/reconnect. CONDSTORE/QRESYNC may optimize flag and
deletion synchronization when supported; they are not connection prerequisites.
Bound connections per account/provider instead of opening one permanent session
for every folder. See [IMAP IDLE](https://www.rfc-editor.org/rfc/rfc9051.html#section-6.3.13)
and [CONDSTORE/QRESYNC](https://www.rfc-editor.org/rfc/rfc7162.html).

The first adapter uses EXAMINE and BODY.PEEK so fetching content does not
implicitly set `\Seen`. It issues no STORE, MOVE, COPY, APPEND, EXPUNGE or send
operation. Flags still reflect changes made by external clients. See
[EXAMINE](https://www.rfc-editor.org/rfc/rfc9051.html#section-6.3.3) and
[FETCH](https://www.rfc-editor.org/rfc/rfc9051.html#section-6.4.5).

Commit validated message changes, cursor progress, audit and minimal outbox hints
atomically in Mail SQLite. Retries use stable remote bindings and job generations
to avoid duplicate occurrences/events. Cache writes need private staging/promotion
and safe orphan cleanup before their metadata is committed. Events contain IDs,
scope and revision, never subjects, participants, bodies or credentials; consumers
must reauthorize and refetch. Restart resumes durable progress without assuming
that an interrupted IMAP batch completed.

## Content, network and resource bounds

Define explicit limits for pages, batch size/runtime, folders/connections, header
and literal sizes, message/attachment size, MIME nesting/part counts, decoded text,
history window and per-account/installation cache quotas before implementation.
Inspect advertised sizes and bound reads/decoding; an oversized message may retain
safe metadata with an explicit content-unavailable reason. Large content is
streamed rather than materialized in RPC envelopes or unbounded memory buffers.

The first representation exposes plain text and attachment metadata/downloads.
Raw MIME remains private. Later HTML rendering needs sanitization and isolated
display; external images/resources default off and require explicit policy.
CID references and filenames are untrusted input, not local paths or authority.
Destination policy applies to IMAP and OAuth endpoints, including resolved
addresses/reconnects; internal servers require explicit operator configuration.

Saving an attachment into Files is a later explicit action with fresh Mail source
read and Files target create authority, approved transport and separate ownership.
A Mail grant never grants Files access. Notification and future Contacts/Task links
likewise require exact contracts and current target authorization.

## Delivery boundaries and verification

| Delivery boundary | Intended result / dependency |
|---|---|
| Personal connections | Multiple accounts, encrypted credentials, bounded connection checks, safe statuses, pause/disconnect; credential and worker-authorization contracts first |
| Read-only synchronization | Folders, metadata, content/attachments, local pagination, jobs/cursors, restart/revoke behavior; provider OAuth adapters before claiming that provider supported |
| Remote changes and integrations | Explicit flag/move/delete policies, workspace/shared accounts, Notify and Files actions; SMTP/drafts/sending have a separate approved delivery contract |

These are durable capability boundaries, not a task/status backlog. GitHub Issues
own implementation scope, labels, provider acceptance and execution evidence.
Backend work precedes TS/Svelte integration; full M7 coverage remains separate.

The first integrated acceptance connects two distinct IMAP accounts, lists their
folders/messages, opens content without changing remote flags, resumes after a
restart and stops synchronization after disconnect. Focused guardrails cover
account/root isolation, current read/stream revoke, UIDVALIDITY reset, changed
flags/expunges, stale-worker fencing, TLS/destination denial, secret-free
logs/replay, MIME/content bounds and empty/reopened migration replay. Exercise a
real local IMAP fixture and the signed Gate/Core/NATS path; a parser or mock alone
does not establish integration or provider compatibility.

Provider matrices, long outage/rate-limit behavior, full MIME/HTML compatibility,
large-history load, crash/restore, key rotation/recovery and all-client regression
belong to M7 verification. Encrypted credentials and their protected recovery key
must be considered alongside SQLite, cached content and relevant JetStream state.
