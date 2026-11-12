# Contacts backend

Contacts 0.2.0 is an independent SQLite owner with the signed `contacts/v1`
contract. This foundation implements personal/workspace address books and native
structured contact CRUD/search and vCard objects for [K-01 and initial K-02](REQUIREMENTS.md#27-contacts--carddav-p1).
Bounded vCard 3.0/4.0 import/export preserves unknown properties and parameters.
CardDAV transport/credentials, incremental sync, photos/Files references, resource
links, remote sources and CRM remain deferred. K-03 is not fully accepted by these
owner APIs.

## Roots and authority

Each address book is an independent ACL root: `contacts.workspace` or
`contacts.personal`. Multiple roots provide multiple books. Workspace books bind
one workspace; personal books bind one user with an empty workspace. Workspace
users/groups may receive grants; personal grants target users only. Core checks
principal validity, workspace membership and ownership. Root management alone does
not grant content access.

Provisioning is an explicit operator workflow: reserve the exact provider/type/
owner binding in Access, call `Contacts.PrepareRoot` with that scope, personal user
owner (empty for a workspace) and `BookInput{Name: ...}`, activate the signed
receipt in Access, then call `Contacts.ActivateRoot`. These trusted in-process
hooks are not public RPCs. Prepared roots are unavailable; retries cannot rebind
an existing book. Automatic default books, root deletion, ownership transfer and
provisioning reconciliation are deferred.

Every request verifies the signed caller/audience/operation, live user session and
workspace. The owner checks its active root and calls Access online before reads,
writes and idempotent replay. Every contact lookup/mutation binds ID, root and
workspace. Unavailable authority fails closed. No cross-owner SQL or positive
permission cache is used.

Independent actions are `contacts.read`, `contacts.create`, `contacts.write`,
`contacts.delete`, `contacts.share` and `access.grants.manage`. The grant API
requires `access.grants.manage` and delegates add/revoke to Core using the current
invocation and a stable downstream idempotency key. No content grant is implicit.

## API

Workspace base: `/api/v1/contacts/workspaces/{workspace_id}/roots/{acl_root_id}`.
Personal base: `/api/v1/contacts/personal/roots/{acl_root_id}`. Personal requests
omit `workspace_id` or use `""`; responses include `""`. The 24 exact operation IDs,
NATS subjects and schemas live in [the manifest](../services/contacts/api/v1/contract/manifest.json).

| Method / suffix | Behavior / action |
|---|---|
| GET base | Book name and revision; `contacts.read` |
| PATCH base | Replace book name with expected `revision`; `contacts.write` |
| POST `/contacts` | Create contact; `contacts.create` |
| GET `/contacts/{contact_id}` | Full contact; `contacts.read` |
| PUT `/contacts/{contact_id}` | Replace all fields with expected `revision`; `contacts.write` |
| DELETE `/contacts/{contact_id}` | Soft-delete with expected `revision`; `contacts.delete` |
| GET `/contacts?limit=...&query=...&cursor=...` | Search summaries in one book; `contacts.read` |
| GET `/objects/{contact_id}` | vCard data, UID, ETag and revision; `contacts.read` |
| POST `/objects/{contact_id}` | Conditional create-only vCard import; `contacts.create` |
| PUT `/objects/{contact_id}` | Conditional full vCard replacement; `contacts.write` |
| DELETE `/objects/{contact_id}` | Conditional soft deletion; `contacts.delete` |
| POST `/grants` | Add user/group action grant or revoke by `grant_id`; `access.grants.manage` |

Commands require `Idempotency-Key`. An identical retry returns the committed
result only after current authorization; changed payloads conflict. Revisions
start at 1; stale writes return a conflict. PUT is full replacement: omitted
optional fields are cleared. Native create generates a UUID and UID `<id>@arc`. Object create accepts a
caller-chosen UUID and the card's UID. The UID is immutable through either API;
uniqueness includes soft-deleted records within a book, while the same UID may
exist in independently permissioned books. UID is not a permission.

Create example (same fields for PUT, plus expected `revision`):

```json
{
  "display_name": "Ivan Petrov",
  "given_name": "Ivan",
  "family_name": "Petrov",
  "organization": "Arc",
  "role": "Engineer",
  "emails": [{"label": "work", "value": "ivan@example.test"}],
  "phones": [{"label": "mobile", "value": "+7 123"}],
  "addresses": [{"street": "Main street", "locality": "Moscow", "country": "RU"}],
  "notes": "Plain text",
  "custom_fields": {"external_id": "local-42"}
}
```

## Bounds and search semantics

All text must be UTF-8. Normalization trims surrounding Unicode whitespace.
Single-line fields reject control characters; notes and streets also allow LF
and TAB. Limits are Unicode characters, measured before trimming:

| Field | Limit |
|---|---|
| `display_name`, book `name` | Required, 1–256 after trimming |
| `given_name`, `family_name`, `additional_name`, `prefix`, `suffix`, `role` | 128 |
| `organization` | 256 |
| `phones` | Up to 32; nonempty value ≤128, label ≤32 |
| `emails` | Up to 32; bare mailbox value ≤254, label ≤32 |
| `addresses` | Up to 16; street ≤512, locality/region/postal_code/country ≤128, label ≤32 |
| `notes` | 8192 |
| `custom_fields` | Up to 32 entries; nonempty key ≤64, value ≤512 |

An address needs at least one non-label field. Email validation is syntactic,
requires a bare mailbox and preserves case; no DNS lookup or delivery occurs.
Telephone/country values are free text. Labels and duplicate phone/email values
are preserved. Custom keys are trimmed; colliding normalized keys are rejected.
Normalized JSON-encoded contact input must fit 48 KiB, even when individual field
limits pass. A book retains at most 10,000 contacts including tombstones.

Search is a literal Unicode-lowercased substring over normalized field values
(including labels, addresses, notes and custom values). JSON/custom field keys
are excluded; `%` and `_` are ordinary characters. There is no locale folding,
accent removal, phone normalization, token ranking or cross-book aggregation.
An empty query lists active contacts. Query length is at most 256 characters.

`limit` is required, 1–100. Results are ascending UUID summaries with ID, UID,
display name, organization, role, revision, update time and scope. Full notes,
mailboxes, addresses and custom data require individual GET. Pages stop at 100
items or a 200 KiB serialized JSON budget, with `next_cursor` equal to the last
returned ID when more rows remain. Continue with the same book/query and that
cursor. This is current-state pagination, not a frozen sync snapshot: concurrent
changes can affect subsequent pages.

## vCard objects and native coherence

These are JSON owner operations for a later CardDAV adapter; there is no new DAV
HTTP/XML endpoint, media negotiation, discovery or DAV credential. Rules follow
[vCard 4.0](https://www.rfc-editor.org/rfc/rfc6350.html) and the bounded
[vCard 3.0](https://www.rfc-editor.org/rfc/rfc2426.html) subset below. Unknown
parameter text, including [caret-encoded values](https://www.rfc-editor.org/rfc/rfc6868.html),
is retained without interpretation.

POST `/objects/{contact_id}` takes `{"if_none_match":true,"data":"BEGIN:VCARD\r\n..."}`;
PUT takes `{"if_match":"\"<64 lowercase hex characters>\"","data":"..."}`;
DELETE takes `{"if_match":"\"<64 lowercase hex characters>\""}`. The match value
is the exact quoted `etag` returned by object GET or a successful object command.
These are JSON fields, not HTTP conditional headers. No wildcard, weak validator,
validator list, unconditional overwrite or UID rebinding is accepted. Syntax
errors return validation errors; stale validators, duplicate IDs or same-book
UIDs (including tombstones) conflict. Missing/deleted objects are unavailable.

An object response contains scope, `contact_id`, `uid`, `etag`, `revision` and
`data`. ETag hashes the stored revision and serialized data, so even a committed
same-content replacement changes it. Idempotent replay returns the original
result after current authorization, regardless of later edits; that old result
must not be treated as the current representation. Native JSON writes and object
writes share the same row, revision, online ACL, replay/audit/outbox and soft delete.
A native update invalidates the object's previous ETag and vice versa. Imported
`REV` is retained as opaque text; it does not control owner revisions or clocks.

Each import is one UTF-8 VCARD, version 3.0 or 4.0, with VERSION first, one nonempty
UID and one FN. Version 3.0 also requires N. UID is at most 255 bytes without
whitespace/control characters; a URI-valued UID requires a scheme. Version 4.0
native export uses `UID;VALUE=text:<id>@arc`. Duplicate singleton projections
(UID/FN/N/ORG/ROLE/NOTE), nested/multiple cards, malformed property headers,
unsupported versions, unsupported managed VALUE/ENCODING/CHARSET representations
or native projection bound failures are rejected. Multi-language alternate FN
instances and legacy vCard 2.1/quoted-printable/charset conversion are deferred.

Native projection:

| vCard property | Native field / preserved remainder |
|---|---|
| FN | `display_name` |
| N (five components) | family/given/additional name, prefix, suffix |
| ORG | First organization component; remaining units stay in the object |
| ROLE | `role`; TITLE is independent opaque data |
| TEL / EMAIL | Repeated `phones` / `emails` in property order |
| ADR (seven components) | street/locality/region/postal code/country; PO box and extended-address components stay in the object |
| NOTE | `notes` |
| X-ARC-CUSTOM;X-ARC-KEY=... | Native custom field; key is unpadded base64url of its UTF-8 bytes |

TEXT values decode backslash/comma/semicolon/newline escapes. Structured component
lists project as comma-containing strings, while their original separators remain
in the template until that component is explicitly edited. Managed text must use
UTF-8 without transfer encoding; TEL additionally supports version 4 URI values
and version 3 phone-number values. URI phone values remain literal strings in the
native projection; a native value edit exports TEXT. ADR needs at least one
projected non-label field, so a PO-box-only card is outside this subset.

TYPE token lists become comma-joined native labels. Native labels that fit token
lists use TYPE; other labels use Arc's `X-ARC-LABEL-B64` parameter (unpadded
base64url UTF-8). This Arc parameter takes precedence when present. Changing a
label changes only these modeled parameters; unrelated parameters remain intact.
Unmodeled properties are not added to native search.
Unknown properties, grouped names, photo data/URIs, TITLE, vendor extensions and
unmodeled parameter text are retained as inert card data. Nothing is fetched,
executed, displayed as an image or resolved through Files automatically.

Native full replacement clears omitted modeled fields, but patches their old
property lines rather than rebuilding imported data. Changed names/organization/
address components retain unprojected neighbors and unknown parameters. Repeated
items first match unchanged values (including labels), then matching values
without labels, then unused old positions for explicit edits; survivors retain
their original group/metadata during removal or reordering. Ambiguous simultaneous
value edits use position. Removing a modeled item removes its own property line;
independent opaque properties remain. Use full object replacement when exact
vendor-specific group restructuring is intended.

Input accepts CRLF or LF. Output uses CRLF and folds at 75 octets without splitting
UTF-8; physical folding and line grouping may normalize, so preservation is not a
byte-identical copy of the upload. Each card fits 96 KiB and its JSON-encoded data
string fits 160 KiB; headers fit 4 KiB, unfolded lines 64 KiB, parameter occurrences
32 per property, physical lines 2048 and interior properties 512. Existing native
field/collection bounds still apply. A native merge that would exceed an object
budget fails atomically and retains the previous card, rather than discarding
opaque extensions. No external parser, network lookup or charset conversion runs.

## Persistence and events

Create/replace/delete and book rename commit domain data, audit, command replay
and `evt.contacts.catalog.changed.v1` outbox records in one local transaction.
Events carry scope, entity ID, revision and action (`created`, `updated`, `deleted`,
`book.updated`), without private field values. Events are invalidation hints;
consumers must reauthorize and refetch. The worker requires current Fabric
approval/readiness and publishes with stable event IDs; transient failures retry.
Core grants retain Core's own atomic mutation/replay/audit semantics.

Contact fields are inert text. An email, URL or custom value neither triggers
external activity nor grants authority over another owner/resource. There are no
photo uploads, Files lookups, web fetches or message deliveries in this service.

## Startup and verification

```sh
bash scripts/migrate.sh contacts /absolute/contacts.sqlite
go run ./cmd/arc-contacts -config /absolute/contacts.json
```

Use [the config example](../deploy/contacts/config.example.json), private owner DB,
service account/signing seed/NATS credentials and Core's public trust root. Startup
never runs migrations. Migration `000002_contacts_vcard` adds opaque storage without
rewriting existing contacts, UIDs, revisions or tombstones. Existing rows export
deterministic native vCard 4.0 until the next write materializes their card. Install and approve the exact artifact digest, all required
operation subjects, resource types/actions and downstream bindings. Version 0.2.0
requires operator reapproval of the new digest and four `contacts.objects.*` plus
four `contacts.personal.objects.*` operations (get/create/update/delete), each
with its exact existing read/create/write/delete action and Access check binding.
Gate needs
explicit Contacts RPC publication. The Contacts broker role needs only its own
RPC subscriptions, identity/access/Fabric control subjects and
`evt.contacts.catalog.changed.v1` publication; provision the JetStream stream
separately. The isolated live fixture is an example, not production installation
or authorization to widen deployed credentials.

Focused tests cover CRUD/CAS/replay/rollback, bounded normalized input, Unicode
search, serialized list budgets, vCard unknown-property/native round-trip, ETag
conditions, UID/tombstones, root/claim/personal denial and migration replay
on reopened SQLite. `scripts/test-files-live.sh` additionally exercises the real
signed Gate/Core/Access/NATS/JetStream path with separate service credentials,
two workspaces and personal books. Record actual runs in the delivery Issue.
Frontend work, full M7 recovery/load/compatibility and CardDAV client acceptance
are deferred.
