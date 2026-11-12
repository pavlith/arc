# Arc service map

| Owner | Binary | Core responsibility | Contract / guide |
|---|---|---|---|
| Core Identity / Access / Fabric | `arc-core` | Sessions, principals, workspaces, grants, signed policy/routing | [Core](core/README.md), [Architecture](../docs/ARCHITECTURE.md) |
| Gate | `arc-gate` | Public HTTPS, signed routes, optional shared realtime and private Files proxy; no DB | [Realtime](../docs/REALTIME.md) |
| Task | `arc-task` | Teams, work items, projects, views, templates, triage, links, attachments and outbox | [Task model](../docs/TASK-MODEL.md), [contract](task/api/v1/contract/manifest.json) |
| Notify | `arc-notify` | Recipient-scoped Inbox/subscriptions, hints and opt-in HTTPS webhook | [Notify](../docs/NOTIFY.md), [contract](notify/api/v1/contract/manifest.json) |
| Files | `arc-files` | Personal/workspace metadata, bounded uploads/bytes and safe image delivery | [Files](../docs/FILES.md), [contract](files/api/v1/contract/manifest.json) |
| Pages | `arc-pages` | Scoped Tiptap tree, versions, templates, ACL-checked references | [Pages](../docs/PAGES.md), [contract](pages/api/v1/contract/manifest.json) |
| Calendar | `arc-calendar` | Personal/workspace calendars, bounded multiget/sync, iCalendar/UID/ETag, recurrence and free/busy | [Calendar](../docs/CALENDAR.md), [contract](calendar/api/v1/contract/manifest.json) |
| Contacts | `arc-contacts` | Personal/workspace address books, structured CRUD/search, vCard/UID/ETag, conditional writes and grants | [Contacts](../docs/CONTACTS.md), [contract](contacts/api/v1/contract/manifest.json) |
| Agent | `arc-agent` | Trusted node runtime, journal and restricted host drivers | [Agent](agent/README.md) |

These are code surfaces, **not production acceptance**. Progress, unfinished UI and verification live in [GitHub Issues](https://github.com/pavlith/arc/issues), not this catalog. `main` is authoritative; historical delivery notes are in Git.

## Shared rules
Each SQL owner has its own explicit migrations, models, idempotency/replay and transactional outbox; no cross-owner database joins. Domain services compose typed modules with `sdk/service`, private NATS and signed installation contracts. Core alone owns Identity/Access/Fabric authority; Gate does not store or infer ACL. Never trust a browser, a known UUID, a source resource reference or a previous grant to authorize a target read. Revocation and unavailable Core fail closed; NATS carries metadata, not file bytes.

All operations/paths/schemas are authoritative in each owner's `api/v1/contract/` and code. Public routes and service-to-service downstream calls require **exact operator-approved Fabric manifests, signed routes, scopes, NATS subjects and pinned digests**. Updating an artifact on disk does not update an installed policy. Reapprove consumers when producer digests change. Do not replace specific approvals with wildcard permissions.

## Startup
Run each owner's migrator before startup and use separate SQLite paths, private keys and NATS credentials. Service seeds are private 32-byte Ed25519 material (0600); give domain services only Core's public trust root, never operator/Core signing secrets. Disk stores are private and outside public static roots. See [database](../sdk/database/README.md), [Core config](core/README.md) and examples in `deploy/{task,notify,files,pages,calendar,contacts,gate,core}/`.

```sh
bash scripts/migrate.sh files /absolute/files.sqlite
bash scripts/migrate.sh pages /absolute/pages.sqlite
go run ./cmd/arc-files -config /path/to/files.json
go run ./cmd/arc-pages -config /path/to/pages.json
```

These are examples, not an automatic installer. Task/Notify/Core have the same separate-process and migration rule. File streaming requires opted-in Gate ↔ Files mTLS, signed private operation and repeated ACL checks; outbound Notify webhook defaults off.

## Product integration
- Identity: separate browser cookie/CSRF and CLI Bearer flows, explicit user bootstrap and workspace/membership/group approvals. Root read grants do not imply root management.
- Task: personal/workspace root and actor scoping, CAS/idempotency, same-root hierarchy and source/target permissions, atomic audit/outbox/replay; [Task](../docs/TASK-MODEL.md).
- Files: private 8 MiB chunks, 1 GiB max file, SHA-256 promotion and safe read cancellation. The browser never gets NATS or unscoped blob paths; [Files](../docs/FILES.md).
- Pages: bounded validated Tiptap, revision restore without cross-root moves, live target authorization; [Pages](../docs/PAGES.md).
- Notify: Task/Pages/Files event sources pin their contracts. Per-recipient inbox is rechecked against target read authority. HTTPS webhook is operator-configured and at-least-once; [Notify](../docs/NOTIFY.md).
- Gate realtime: `/api/v1/arc/realtime` is disabled by default. Requires approved event subjects, cookie/origin/CSRF handshake, fresh ACL and authorized HTTP refetch; [protocol](../docs/REALTIME.md).
- Files-backed Task attachments and Identity avatars: [references](../docs/RESOURCE-REFERENCES.md).

## Verification
Run [targeted checks](../docs/DEVELOPMENT.md#verification) and record *actual* evidence in the Issue. `make m0-06-smoke` tests the signed Core/Gate/Task/Notify path with fixture outbound delivery; `bash scripts/test-files-live.sh` runs isolated real TLS/NATS/ACL Files/Pages acceptance. These do not prove production installation or M7 resilience.
