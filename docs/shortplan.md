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

Issue scope and labels determine remaining work and any temporary pause. No dependency row establishes completion or authorizes production rollout.

## Contracts

[Architecture](ARCHITECTURE.md) defines ownership, approved transport and authorization. [Development](DEVELOPMENT.md) defines installation and verification. Task stores plain text/Markdown; Pages uses validated Tiptap. M7 and later product domains retain their own requirement scope.

Component details: [Task](TASK-MODEL.md), [Realtime](REALTIME.md), [Files](FILES.md), [References](RESOURCE-REFERENCES.md), [Pages](PAGES.md), [Notify](NOTIFY.md).
