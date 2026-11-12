# Contacts backend

Contacts 0.1.0 is an independent SQLite owner with the signed `contacts/v1`
contract. This foundation implements personal/workspace address books and native
structured contact CRUD/search for [K-01 and initial K-02](REQUIREMENTS.md#27-contacts--carddav-p1).
vCard import/export, unknown-property preservation, CardDAV, incremental sync,
photos/Files references, resource links, remote sources and CRM remain deferred.
Native custom fields do not imply vCard property round-trip support.

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
omit `workspace_id` or use `""`; responses include `""`. The 16 exact operation IDs,
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
| POST `/grants` | Add user/group action grant or revoke by `grant_id`; `access.grants.manage` |

Commands require `Idempotency-Key`. An identical retry returns the committed
result only after current authorization; changed payloads conflict. Revisions
start at 1; stale writes return a conflict. PUT is full replacement: omitted
optional fields are cleared. IDs are generated UUIDs. The immutable generated UID
is `<id>@arc`; UID uniqueness includes soft-deleted records within a book. UID is
not a permission or caller-supplied create key.

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
never runs migrations. Install and approve the exact artifact digest, all required
operation subjects, resource types/actions and downstream bindings. Gate needs
explicit Contacts RPC publication. The Contacts broker role needs only its own
RPC subscriptions, identity/access/Fabric control subjects and
`evt.contacts.catalog.changed.v1` publication; provision the JetStream stream
separately. The isolated live fixture is an example, not production installation
or authorization to widen deployed credentials.

Focused tests cover CRUD/CAS/replay/rollback, bounded normalized input, Unicode
search, serialized list budgets, root/claim/personal denial and migration replay
on reopened SQLite. `scripts/test-files-live.sh` additionally exercises the real
signed Gate/Core/Access/NATS/JetStream path with separate service credentials,
two workspaces and personal books. Record actual runs in the delivery Issue.
Frontend work, full M7 recovery/load/compatibility and CardDAV client acceptance
are deferred.
