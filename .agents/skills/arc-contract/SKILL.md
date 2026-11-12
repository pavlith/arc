---
name: arc-contract
description: Implement or review Arc Identity, ACL, SDK, NATS Fabric, Gate and Runtime contracts. Use for security boundaries, APIs, schemas, manifests and architecture changes.
---

# Security and protocol boundary
1. Read the active Issue and relevant Architecture/Requirements headings. Start at `sdk/{security,rpc,contract}`, `services/core/modules/<module>` or the owner's `api/v1/contract/`; avoid whole-document ingestion.
2. Preserve exact signed caller/audience/operation/proof, session/delegation verification, online ACL and fail-closed errors.
3. Preserve owner-local SQL boundaries, transaction + replay + outbox atomicity and explicitly approved Fabric manifests, NATS permissions and Gate routes. Do not widen authority or redesign unrelated contracts.
4. Change implementation, schema, focused negative tests and normative contract documentation together; run the corresponding M0 security guardrail. Never infer acceptance from a build.
