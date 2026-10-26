# Arc services — independent Core and Gate packages

This directory introduces the first service-owned packages without changing any
legacy `sdk/` source, NATS subjects, signed artifacts or the existing M0 startup.

- `core/`: four in-process modules (`identity`, `access`, `fabric`, `runtime`),
  owner-local SQL migrations, typed API aliases and a single trusted NATS Micro bootstrap.
- `gate/`: independently composed `http`, `discovery` and `listener` modules.
  Gate reads signed route snapshots, verifies on-line auth, and never reads the Core database.
- `internal/testcontract/`: test-only artifact fixture shared by service packages.

The implementations of Identity, Access, Fabric and Gate HTTP are based on the
already-tested M0 code, moved to service ownership and retargeted to
`github.com/pavlith/arc/pkgs`. All domain RPC operation IDs, NATS subjects,
approval signatures and message semantics are unchanged.

**Security boundary:** `pkgs/service.Compose` is reserved for operator-approved
domain services. Core's root/bootstrap endpoints cannot be registered as an
unapproved domain contract merely to reuse that API; Core uses the separate
low-level `pkgs.Service` Micro transport with strict private subjects. The
modules still use direct Go interfaces internally. Gate remains an HTTPS edge
process, not an NATS business-service publisher.

No production binary or deployment has been switched from the existing `sdk/`
implementation. The new packages need real PostgreSQL/NATS integration
validation before cutover. `services/core/migrations` are embedded and should
be applied by the migrator under its scoped role; do not run them a second time
against a database where the legacy migrations have already been applied.

To verify:

```bash
go test -race ./services/...
go vet ./services/...
go build ./services/...
```

## Domain packages: task and notify

`services/task` (Fabric identity `tasks`) and `services/notify` (Fabric
identity `notifications`) are independently composed from `pkgs/service`
and strongly typed `pkgs/module` registrations. The singular directory names
are Go layout choices **only**; no existing API ID, subject, durable name,
schema name or JWT audience is renamed.

Each owns `api/v1`, embedded `migrations/`, `service.go` and `modules/`:

- `task/modules/tasks`: create/get/list/root grants with owner-local
  transactions, live resource checks and typed operation bindings.
- `task/modules/outbox`: committed publisher with stable JetStream message ID
  and per-batch online Fabric `Check`.
- `notify/modules/inbox`: durable consumer, exact approved
  producer/digest/subject/durable `EventPermit`, atomic inbox/effect.
- `notify/modules/delivery`: independently polling persisted outbound intents,
  stable idempotency keys, and live event permit before external effects.
- `notify/modules/health`: typed authenticated health operation.

Service constructors refuse missing signing credentials, Core trust key,
owner DB or consumer event permission. They pin the reviewed v1 artifact and
signed Core invocation verification. Unlike the legacy combined
`migrations/000005_tasks_notifications.up.sql`, each service now carries its
own domain schema migration; **do not apply both migration strategies to the
same database**.

Standalone `cmd/arc-task` and `cmd/arc-notify` each load their own
service-specific bootstrap config, credentials, DB, NATS connections, workers,
and SDK runtime. The common `sdk/bootstrap` owns only reusable infrastructure
initialization; it never selects domain services or composes multiple services
into one process. Each image/container is deployed independently.

