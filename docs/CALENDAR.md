# Calendar backend

Calendar is an independent SQLite owner (`services/calendar`) with the signed
`calendar/v1` contract. Calendar 0.5.0 implements bounded object multiget, collection sync, metadata, iCalendar
objects, single events
and bounded recurring series
with cancellation/move exceptions and materialized occurrence queries. It does not
implement CalDAV, scheduling or default calendar auto-provisioning. Requirements: [C-01–C-04](REQUIREMENTS.md#26-calendars--caldav-p1).

## Roots and authority

Each calendar is an independently permissioned ACL root, of type
`calendar.workspace` or `calendar.personal`. Multiple roots provide additional
calendars. Workspace roots bind their workspace; personal roots bind one user and
have an empty workspace. Workspace groups and individual users may receive grants;
personal grants target individual users only. Core enforces membership, ownership
and grant scope; root management does not imply content read.

The operator reserves a root through Access under the Calendar provider's approved
identity, calls `Calendar.PrepareRoot` with the reserved scope, personal owner
(or empty owner for workspace), name and timezone, then activates the receipt in
Access before calling `Calendar.ActivateRoot`. Prepared roots are unavailable.
These are trusted in-process provisioning hooks, not public RPC endpoints. A retry
cannot rebind an existing root to a different owner/workspace. Root deletion,
automatic provisioning/reconciliation and ownership transfer require later work.

Every request verifies its signed caller, audience and operation, then checks the
local active root/scope and current Access decision, including before command
replay. Actual event reads and mutations bind event ID, workspace and root in the
owner database. Core failures fail closed. No positive authorization cache or
cross-owner SQL is used.

Actions are independent: `calendar.read`, `calendar.create`, `calendar.write`,
`calendar.delete`, `calendar.free_busy`, `calendar.share`, and
`access.grants.manage`. In particular, free/busy does not confer read authority.
The grants endpoint requires `access.grants.manage`; group membership and principal
validity are checked by Core. Empty or mixed add/revoke payloads are rejected.

## API

Workspace base: `/api/v1/calendar/workspaces/{workspace_id}/roots/{acl_root_id}`.
Personal base: `/api/v1/calendar/personal/roots/{acl_root_id}`. Personal payloads
omit `workspace_id` or use an empty string. Request and response schemas live in
[the contract](../services/calendar/api/v1/contract/manifest.json).

| Method / suffix | Behavior / required action |
|---|---|
| GET base | Calendar name, timezone, revision; `calendar.read` |
| PATCH base | Replace name/timezone with expected `revision`; `calendar.write` |
| POST `/events` | Create event/series; `calendar.create` |
| GET `/events/{event_id}` | Read stored event/series; `calendar.read` |
| PATCH `/events/{event_id}` | Replace all event/series fields with expected `revision`; `calendar.write` |
| DELETE `/events/{event_id}` | Soft-delete entire event/series with expected `revision`; `calendar.delete` |
| GET `/events?from=...&until=...&limit=...&cursor=...` | Series with effective overlapping occurrences, UUID-ordered pagination; `calendar.read` |
| GET `/occurrences?from=...&until=...&limit=...&cursor=...` | Effective occurrence summaries, decimal cursor pagination; `calendar.read` |
| GET `/free_busy?from=...&until=...` | Merged, clipped busy intervals only; `calendar.free_busy` |
| POST `/multiget` | Ordered bounded object batch; `calendar.read` |
| GET `/sync?limit=...&token=...&cursor=...` | Initial/delta metadata sync; `calendar.read` |
| GET `/objects/{event_id}` | iCalendar data, UID, ETag and revision; `calendar.read` |
| POST `/objects/{event_id}` | Create-only import (`if_none_match: true`); `calendar.create` |
| PUT `/objects/{event_id}` | Full object replacement with `if_match`; `calendar.write` |
| DELETE `/objects/{event_id}` | Conditional delete with `if_match`; `calendar.delete` |
| POST `/grants` | Add individual/group action grant or revoke by `grant_id`; `access.grants.manage` |

Commands require an `Idempotency-Key`. Reusing it with a changed payload conflicts.
An event write, audit entry, replay result and metadata-only outbox event commit
atomically. Delete preserves a tombstone; no restore/history API is exposed. List
pagination is current-state pagination and does not promise a stable snapshot
across concurrent writes. Name/timezone changes do not reinterpret existing events. A series update replaces
its rule and exceptions together; omitting `rrule` and `exceptions` converts it to
a single event. All occurrence rows change within the same CAS/replay transaction.
Occurrence cursors are positive decimal IDs; they are pagination state, not
permission or stable event identities. Pagination is by storage ID, not start time.
A concurrent series rebuild can change occurrence cursor IDs.

Event input (the fields below are required; `rrule` and `exceptions` are optional):

```json
{
  "title": "Review",
  "description": "Agenda",
  "timezone": "Europe/Moscow",
  "all_day": false,
  "start": "2026-11-12T12:00:00+03:00",
  "end": "2026-11-12T13:00:00+03:00",
  "busy": true
}
```

Timed events accept RFC3339 instants and return UTC values with the supplied IANA
display timezone. Floating local times are not accepted. All-day events use
`YYYY-MM-DD` start and exclusive end dates in their stored timezone. Their busy
intervals follow local midnight and DST. Timezone data is embedded; `Local` is
rejected. Transparent (`busy: false`) events do not appear in free/busy.

Free/busy selects and returns only UTC intervals, merged across overlapping or
adjacent events and clipped to the request range. It discloses no event IDs,
titles, descriptions or per-event pagination tokens. Neither `calendar.read` nor
`calendar.free_busy` implicitly grants the other action.

## Recurrence and exceptions

`rrule` is the property value, for example `FREQ=DAILY;COUNT=10`, without an
`RRULE:` prefix or embedded DTSTART. Supported frequencies are `DAILY`, `WEEKLY`,
`MONTHLY` and `YEARLY`; `INTERVAL` is 1–366 (default 1). Exactly one of `COUNT`
(1–1000) or inclusive `UNTIL` is required. Timed UNTIL is UTC
`YYYYMMDDTHHMMSSZ`; all-day UNTIL is `YYYYMMDD` in the event timezone.

Weekly rules may specify distinct, non-ordinal `BYDAY` values such as `MO,WE`;
weeks start on Monday. Monthly rules may specify one `BYMONTHDAY` value from
1–31 or -31–-1. Other filters/frequencies, duplicate rule keys, COUNT with UNTIL,
infinite rules, RDATE and THISANDFUTURE are rejected. DTSTART must be the first
matching occurrence. The complete series must fit the supported 1900–2100
horizon and at most 1000 original occurrences, including subsequently cancelled
ones. Over-limit series fail atomically rather than returning partial expansion.

The pinned [rrule-go](https://github.com/teambition/rrule-go/tree/v1.8.2) iterator
operates on floating civil coordinates behind the supported-rule validator. The
owner resolves those coordinates in the stored timezone: nonexistent local times
are skipped without consuming COUNT, ambiguous times use the first instant, and
invalid month dates are skipped. Recurring timed events require whole seconds;
the elapsed duration is copied to each occurrence. All-day ranges retain their
civil day count across DST. Non-recurring events retain nanosecond support.

`exceptions` replaces the complete exception set (at most 128 entries). Each entry
selects an original start in `recurrence_id`: UTC RFC3339 for timed events (offset
input is normalized), or `YYYY-MM-DD` for all-day events. It must belong to the
original series and cannot repeat another normalized key.

```json
{
  "rrule": "FREQ=DAILY;COUNT=3",
  "exceptions": [
    {"recurrence_id": "2026-11-13T09:00:00Z", "cancelled": true},
    {
      "recurrence_id": "2026-11-14T09:00:00Z",
      "cancelled": false,
      "start": "2026-11-20T09:00:00Z",
      "end": "2026-11-20T10:00:00Z"
    }
  ]
}
```

A cancellation has no replacement dates; a move requires both start and end and
keeps the series timezone, all-day flag, title and busy flag. The original
`recurrence_id` survives a move; `(event_id, recurrence_id)` identifies a slot.
Detached title/attendee overrides are outside this contract. Exception changes
use the ordinary whole-series PATCH with its expected revision and idempotency
key; no separate mutation bypasses series CAS.

The owner materializes effective intervals on create/update and removes them on
series delete. Both series lists and free/busy query these intervals, including
moved occurrences outside the original series window. The new occurrence API
returns summaries with `event_id`, original `recurrence_id` and effective dates;
it omits descriptions. Free/busy still selects only interval columns and returns
no series/occurrence IDs, exceptions or private fields.

## iCalendar objects

An object is one `VCALENDAR` containing one master `VEVENT` and at most 128
same-UID detached exceptions. These endpoints use **JSON**, not DAV HTTP methods,
content negotiation or headers. The owner interface is intended for a later Gate
CalDAV adapter; discovery, DAV XML/REPORT/PROPFIND and DAV credentials
are not implemented here. Collection sync tokens use the owner JSON API below.

POST takes `{"if_none_match":true,"data":"BEGIN:VCALENDAR\r\n..."}`. The path
`event_id` is a caller-chosen UUID; it is independent of the calendar UID. PUT
takes `{"if_match":"\"<64 lowercase hex characters>\"","data":"..."}`. DELETE
requires the same `if_match` string. All commands also require the ordinary
`Idempotency-Key`. This is explicit create-only versus strong-validator matching;
missing, weak and wildcard validators are not accepted. Duplicate event IDs/UIDs,
UID changes and stale matches conflict. Identical replay returns the original
result only after the current online permission check.

Responses contain scope, `event_id`, `uid`, `etag`, `revision` and canonical
`data`. Export is deterministic for the current stored revision and tzdb. The
strong ETag covers exported bytes and owner revision; even identical same-second
writes invalidate the old ETag. UID is immutable and unique within a root,
including tombstones: a stale client cannot recreate deleted content at a new URL
using the old UID. Another root may independently store the same external UID.
JSON-created events receive `<event UUID>@arc`; ordinary event reads now include
that UID. JSON updates retain UID and opaque imported fields and invalidate ETag.
Server `DTSTAMP`, `LAST-MODIFIED` and `SEQUENCE` follow the owner revision/time,
not client assertions. A UID or SEQUENCE never grants access or overrides CAS.

Supported input includes UTC DATE-TIME, IANA `TZID` local DATE-TIME, explicit DATE
values, supported finite RRULE, EXDATE lists and detached cancellation/move
components. Floating times, scheduling METHOD, RDATE/EXRULE/DURATION, multiple
master events/UIDs, unsupported recurrence and detached content overrides are
rejected. DTSTART and DTEND are required. Detached cancellation components omit
DTSTART/DTEND; moves retain the master's title, description, busy flag and DATE
versus DATE-TIME type. Unsupported data fails atomically rather than being
silently discarded or changing free/busy interpretation.

IANA times are resolved from embedded tzdb. Export includes explicit transition
`VTIMEZONE` components over 1899–2102 so recurrence retains civil time across DST.
When a VTIMEZONE is supplied on import, only the owner's canonical IANA form is
accepted; arbitrary client timezone definitions are rejected. Known IANA TZID
input without a VTIMEZONE is accepted and normalized on export. The
`X-ARC-TIMEZONE` extension preserves the owner's all-day timezone, because DATE
values themselves have no TZID. Complete external-client timezone compatibility
remains part of the subsequent CalDAV work.

Text escaping, CRLF and UTF-8-safe 75-octet folding are handled on export. Opaque
properties (including X-properties, attendee metadata and VALARM) are retained as
data; importing/exporting them sends no invitations, runs no alarms, fetches no
URLs/attachments and renders no HTML. JSON projection does not interpret opaque
properties. Known temporal/text fields are regenerated from the owner model;
this is not byte-for-byte archival of the original document or a generic
lossless converter for every iCalendar property/parameter combination.

Raw object size is at most 96 KiB; parsing bounds component depth/count and lines
before invoking the component decoder. Export's JSON-encoded text is capped at
180 KiB to preserve RPC/HTTP headroom. A native event with subsecond timestamps,
a second-fold local timestamp, unsupported control text or excessive serialized
size cannot be exported losslessly and returns validation failure; the native
JSON data remains intact. Imported writes that cannot be exported within these
bounds roll back event data, effective occurrences, replay, audit and outbox.

## Object multiget

POST `/multiget` is an owner JSON query for a later CalDAV `calendar-multiget`
adapter. It requires the same live `calendar.read` permission as object GET and
has no mutation, audit or outbox effect. An ETag/cache hint is not authority.

```json
{
  "objects": [
    {"event_id": "40000000-0000-4000-8000-000000000003"},
    {
      "event_id": "40000000-0000-4000-8000-000000000004",
      "known_etag": "\"<64 lowercase hex characters>\""
    }
  ],
  "offset": 0
}
```

A request contains 1–100 distinct canonical event UUIDs, with optional strong
`known_etag` hints. Results preserve request order and contain scope, `items`,
`complete`, and a `next_index` only when continuation is needed. Item statuses:

| Status | Fields / behavior |
|---|---|
| `ok` | UID, revision, current ETag and canonical iCalendar `data` |
| `not_modified` | UID, revision and matching ETag, without data |
| `not_found` | Event ID only: unknown, deleted and foreign-root IDs are indistinguishable |
| `unsupported` | UID/revision of a native object that cannot be exported, without ETag/data |

One SQLite read snapshot binds each batch page's metadata and content. All rows
are filtered by the actual root/workspace before lookup; there is no cross-owner
query or per-item permission widening. The whole request fails on current read
denial or authority outage. Free/busy-only actors cannot use this query.

The actual JSON response, including escaping, is capped at 200 KiB below the
ordinary RPC envelope limit. When more content would exceed that budget,
`complete` is false and `next_index` identifies the first unreturned target.
Resend the same ordered `objects` array with `offset=next_index`; completed
results have no next index. Continuation performs a new current read and ACL
check, so ETags may change between pages. Use sync tokens for consistent
collection metadata windows; this endpoint does not freeze historical content.

## Collection sync

`GET /sync?limit=1..100` starts a full metadata enumeration. Continue incomplete
pages by passing **only** `cursor` and `limit`. A complete response contains a
`token`; later `GET /sync?token=<previous token>&limit=...` returns incremental
changes. Token and cursor are mutually exclusive. The response includes scope,
`items`, `complete`, and either a continuation `cursor` or a final `token`.
Never checkpoint an incomplete page as a completed sync.

Each item has `event_id`, stable `uid`, owner `revision` and a state:

| State | Meaning |
|---|---|
| `active` | Exportable object with its strong `etag` |
| `deleted` | Tombstone with no ETag; remove the client copy |
| `unsupported` | Native object exists but cannot be exported under iCalendar limits; no ETag |

Initial enumeration omits resources already deleted at its watermark and includes
unsupported objects explicitly. Incremental sync returns changes and deletions,
coalescing multiple changes to each event at the latest revision in the selected
window. It does not filter by occurrence time: a whole series is one sync member.
Calendar display-name/timezone changes retain their separate calendar revision;
they do not mutate object sync metadata.

Every page series fixes an upper change watermark. Later writes do not move that
watermark or alter returned metadata. The journal retains before-images, so an
initial scan still returns a resource deleted or changed after the first page;
a resource created later is excluded. Delta pagination coalesces within its fixed
window. Changes after that window appear in the next sync. Object GET still
returns the latest authorized content, so an object fetched after a metadata page
may already have a newer ETag. A sync page is not historical iCalendar storage.

The owner keeps 10,000 recent changes per root, plus current metadata for its
bounded event/tombstone catalog. Create/update/delete, previous/current metadata,
root sequence, replay result, audit and outbox commit together. Retrying a command
does not advance sync; failed commands leave no journal entry or sequence gap.
iCalendar replacement snapshots its final opaque properties before advancing sync.

Tokens and cursors are opaque state references bound to root, workspace and a
random collection generation. They are not credentials, user identities or signed
invocations. Every request still verifies the invocation, active root and current
`calendar.read`. `calendar.free_busy` cannot enumerate UIDs, ETags or tombstones.
Revocation and Core outage fail closed even with a previously valid cursor.

Expired history, wrong scope/generation, future or malformed state references
return `CONFLICT` with `Calendar sync token invalid; restart full sync`. The client
must discard its collection baseline and restart without token/cursor. There is
no time-based expiry while the required history remains available. A cursor can
expire during a sufficiently long scan; no partial success token is returned.

### Owner bootstrap and reset

Migration `000004_calendar_sync` adds storage without doing expensive iCalendar
rendering in SQL, service startup or a user request. Existing roots need an
explicit owner bootstrap before sync can issue tokens. Other Calendar APIs keep
working before bootstrap; sync returns unavailable. New roots provisioned through
`PrepareRoot` start with an initialized empty collection.

With Calendar stopped, apply migrations and prepare its existing database:

```sh
bash scripts/migrate.sh calendar /absolute/calendar.sqlite
go run ./cmd/arc-calendar-sync -db /absolute/calendar.sqlite
```

The command requires an existing migrated Calendar database, reads events in
bounded batches, includes UID tombstones, and records `calendar.sync.reset` under
`operator:offline` in the owner audit. It uses no Identity credentials and exposes
no public administrative RPC. A normal repeat skips initialized roots. Each root
is atomic; interrupted preparation can be rerun for remaining roots.

After restoring a database, changing the iCalendar serializer or upgrading tzdb,
rebuild metadata and rotate all generations **before** reopening sync traffic:

```sh
go run ./cmd/arc-calendar-sync -db /absolute/calendar.sqlite -reset
```

This invalidates old tokens/cursors and rebuilds ETags from current authorized
object representations. It retains events, UIDs, domain revisions and outbox;
clients must perform a full sync. Ordinary bootstrap does not rotate an already
initialized generation. This explicit offline procedure is part of installation;
backup/restore automation and M7 recovery acceptance remain separate.

## Limits

- Names/titles: 1–256 Unicode characters after trimming; description: at most 8192.
- Timezones: at most 128 bytes; instants/dates within 1900–2100; positive duration
  of at most 367 days. Unknown fields and unsupported recurrence syntax are rejected.
- Overlap/free-busy range: positive, at most 31 elapsed days; exclusive upper bound.
- Lists: 1–100 series/occurrence summaries (without descriptions), with a UUID series cursor or decimal occurrence cursor; no global cross-root search.
- Root capacity: 10,000 stored series/events including tombstones and 100,000
  effective occurrence rows. Deleted/cancelled occurrences do not consume the
  occurrence capacity. Free/busy is bounded by that capacity. More than 1000 disjoint merged intervals rejects the query rather than
  returning partial coverage; use a narrower range.

## Startup and installation

Run explicit migrations before traffic; startup does not migrate:

```sh
bash scripts/migrate.sh calendar /absolute/calendar.sqlite
go run ./cmd/arc-calendar -config /absolute/calendar.json
```

Apply migrations through `000004_calendar_sync` and run the owner sync bootstrap
for existing #36–#38 Calendar databases before enabling sync. Version 0.5.0 adds no further schema migration. Migration 000002 adds recurrence columns and backfills
one effective occurrence per active single event; deleted events remain absent.
Reopen/replay does not duplicate occurrences. Migration 000003 gives every
existing event (including tombstones) a stable UID
and adds opaque object storage plus root-scoped UID uniqueness. Both earlier
schemas remain unchanged; replay does not regenerate existing UIDs.

Use [the configuration example](../deploy/calendar/config.example.json), a private
owner database, a separate ServiceAccount/key/NATS connection, and the Core public
trust root. Install the compiled artifact through the existing signed Fabric
workflow. The new version/digest, `calendar.events.occurrences` and
`calendar.personal.events.occurrences` require explicit operator reapproval and
broker permissions. Approve each object operation (`get`, `create`, `update`,
`delete`) in both the `calendar.objects` and `calendar.personal.objects`
namespaces. Sync additionally requires exact `calendar.objects.sync` and
`calendar.personal.objects.sync` approvals and broker subjects. Version 0.5.0
also needs exact `calendar.objects.multiget` and
`calendar.personal.objects.multiget` read approvals and broker subjects. Reapprove any
installed consumers pinned to the old digest.
Gate must be approved for the exact Calendar operations it exposes.
Calendar needs exact Identity verify/exchange and Access check operations, with
signed downstream provenance from each incoming Calendar operation to its matching
action. A free-busy source must be approved **only** for `calendar.free_busy`.
Grants additionally require approved Access add/revoke operations; trusted root
provisioning needs reserve/activate under an approved Calendar source.

Allow the installed RPC subjects and
`evt.calendar.catalog.changed.v1` on the private broker; provision a JetStream
stream for the event. The publisher rechecks the active Fabric permit before
publishing committed events. It emits only scope, entity ID, revision and change
kind. Notify/realtime consumers are not automatically added or authorized by this
slice. No production policy, credentials, permissions or deployment are changed.

## Verification boundary

Focused owner tests cover migration/reopen/replay, event CRUD, CAS/idempotency,
rollback, scope checks, free-busy non-disclosure, recurrence/exception/pagination
behavior, iCalendar UID/ETag/escaping/opaque fields/conditional writes, DST
gaps/folds, frozen sync pagination, history expiry/reset, journal rollback, multiget ordering/ETag/scope/budget continuation and
additive migration/bootstrap replay. The
isolated Office fixture (`PATH=/path/to/nats-bin:$PATH bash scripts/test-files-live.sh`)
also exercises Calendar through real Gate/Core/NATS/Access and JetStream. These
checks do not establish CalDAV compatibility, full M2 completion or M7 resilience.
