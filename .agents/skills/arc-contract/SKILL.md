---
name: arc-contract
description: Implement or review Arc Identity, ACL, SDK, NATS Fabric, Gate and Runtime contracts. Use for security boundaries, APIs, schemas, manifests and architecture changes.
---

# Arc contract workflow

1. Identify the Issue, affected contract IDs and subsystem using the AGENTS.md context map.
2. Read ONLY relevant headings in docs/ARCHITECTURE.md and docs/REQUIREMENTS.md; do not reread both complete documents.
3. Keep agreed decisions; do not broaden the change into unrequested architecture redesign.
4. Protect trust boundaries: reject unverified identity headers, bind invocation to caller/audience/op/proof, enforce online ACL and fail closed.
5. For storage/events preserve transaction boundaries, ownership, idempotency and outbox/inbox semantics. For Fabric/Gate preserve manifest approval, signed snapshots and deny unknown routes.
6. Change implementation, schemas, tests and normative documentation together when contract semantics change.
7. Apply arc-verify only to the touched boundary, including non-negotiable M0 guardrails. Report remaining M7 verification explicitly.
