---
name: arc-go-service
description: Build Arc Go/Echo domain services, Core modules or SDK integrations. Use when Go code, NATS endpoints, migrations or service registration is requested.
---

# Go owner implementation
1. One root Go module. Start at `services/<owner>/service.go`, `modules/` and `api/v1/contract/`; prefer small in-process Go interfaces and typed `sdk/service` modules; NATS only between processes.
2. Domain data stays in its owner SQLite with explicit migrations. Preserve bounded deadlines/errors, live authorization, idempotency and atomic outbox.
3. Follow `services/task`, `sdk/service/runtime.go`, `sdk/module` and `sdk/events` patterns. Owner migration registries are `services/<owner>/migrations/sqlite.go`. Add abstractions/dependencies only for a concrete need.
4. Run focused package tests/format/vet and boundary guardrails via `arc-verify`.
