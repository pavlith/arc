---
name: arc-go-service
description: Build Arc Go/Echo domain services, Core modules or SDK integrations. Use when Go code, NATS endpoints, migrations or service registration is requested.
---

# Go owner implementation
1. One root Go module. Locate the existing owner; prefer small in-process Go interfaces and typed `sdk/service` modules; NATS only between processes.
2. Domain data stays in its owner SQLite with explicit migrations. Preserve bounded deadlines/errors, live authorization, idempotency and atomic outbox.
3. Do not create new transport abstractions or dependencies without a concrete need. Use current approved contract/SDK patterns, not legacy packages.
4. Run focused package tests/format/vet and boundary guardrails via `arc-verify`.
