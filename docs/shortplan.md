# Product integration sequence

GitHub Issues are the only task/status tracker. This file records *dependencies*, not completion claims; current code lives on `main`. The optional GitHub product connector comes **after** the standalone product acceptance, not before Git pushes.

| Order | Area | Tracking | Exit criterion |
|---|---|---|---|
| 1 | Task model, templates, triage | [#10](https://github.com/pavlith/arc/issues/10) | Approved Task operations, replay/CAS, scoped links and focused checks |
| 2 | Gate shared realtime | [#27](https://github.com/pavlith/arc/issues/27) | Live ACL/session checks, bounded invalidations, reconnect/revoke safety |
| 3 | Files and byte streaming | [#29](https://github.com/pavlith/arc/issues/29) | Isolated two-user, two-workspace upload/download and revoke |
| 4 | Attachments, avatars and references | [#31](https://github.com/pavlith/arc/issues/31) | Source/target permissions, no denied preview/bytes |
| 5 | Pages / Wiki | [#11](https://github.com/pavlith/arc/issues/11) | Scoped hierarchy, safe Tiptap, version/restore, resource checks |
| 6 | Notify and provider integration | [#12](https://github.com/pavlith/arc/issues/12), [#32](https://github.com/pavlith/arc/issues/32) | Recipient-isolated inbox, delivery and four-owner signed route reconciliation |
| 7 | English Gate/Svelte product UI | [#9](https://github.com/pavlith/arc/issues/9), [#10](https://github.com/pavlith/arc/issues/10) | Account/workspace → Task → Inbox → Files/Pages flows |
| 8 | Standalone product acceptance, then optional GitHub connector | [#9](https://github.com/pavlith/arc/issues/9), [Requirements](REQUIREMENTS.md) | Two users/workspaces; deny/revoke, restart, migration replay and end-to-end flows |

Backend implementations of Task, Files, Pages, references and Notify already exist, but Issue acceptance remains authoritative. UI work remains paused pending explicit authorization. Do not infer production readiness from code or migration compilation; document verified results in the owning Issue.

## Invariants
- Core owns Identity/Access/Fabric; Gate owns the public HTTP/WebSocket edge without a DB; Task/Notify/Files/Pages own separate SQLite/outbox data. Domain-to-domain references are opaque, never cross-owner SQL.
- NATS transports approved metadata and events, **not file bytes**. Private byte streaming is mTLS and signed through Gate; browser sessions and CLI Bearer identities stay distinct.
- Every step uses exact approved routes/downstream permissions, current ACL/session, revocation, idempotency and replay-safe transactions. Unverified target links convey no authority or content.
- New migrations/producer digests require explicit operator deployment. No automatic signing, production rollout or outbound delivery.
- UI uses the existing Svelte 5 package, Gate API and validated Tiptap documents; do not restore upstream Kuayle trust assumptions.
- M7, broad WebDAV/public sharing, Calendars/Contacts, new agent drivers and full provider connectors are separate deliverables.

Component details: [Task](TASK-MODEL.md), [Realtime](REALTIME.md), [Files](FILES.md), [References](RESOURCE-REFERENCES.md), [Pages](PAGES.md), [Notify](NOTIFY.md).
