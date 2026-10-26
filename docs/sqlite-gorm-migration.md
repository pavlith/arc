# SQLite / GORM migration contract

Status: implementation plan; PostgreSQL remains active until the service cutovers are tested.

## Decisions

- Each independently deployed SQL-owning service (core, task, notify) owns its own SQLite database file. Gate does not own a database.
- Shared connection and migration utilities belong in `sdk/database`. Service-specific models, queries, and ordered migrations stay in each service.
- Use `gorm.io/gorm`, `gorm.io/driver/sqlite`, and `github.com/go-gormigrate/gormigrate/v2`. Do not call GORM AutoMigrate in production startup.
- Every migration has an immutable ID and is run by an explicit owner migrator, before service traffic starts. A running service must not silently migrate its database.
- Configure foreign keys, busy timeout, and WAL; verify pragmas on actual connections. Do not use an in-memory database in concurrency proofs.
- SQLite has no PostgreSQL schemas: replace schema-qualified identifiers with owner-local tables. Remove PostgreSQL-only advisory locks, `$n` placeholders, JSONB/array syntax and `FOR UPDATE` where applicable.
- Preserve command replay semantics: identical actor/operation/idempotency key + identical canonical payload returns the original result; changed payload conflicts; failed handlers leave no result.
- Preserve inbox semantics: same consumer/event ID + identical canonical payload is a no-op; changed payload conflicts; inbox insert and domain effects commit atomically.
- Preserve outbox semantics: domain mutations and outbox inserts share a single transaction. External publication occurs after commit; retries use stable event IDs.
- Use database constraints and write transactions to serialize conflicting writes; do not rely on a process-local mutex for correctness across service instances.
- Existing PostgreSQL data is not automatically migrated by switching the driver. Any production data transfer requires a separately tested export/import procedure.

## Cutover sequence

1. Add GORM/Gormigrate dependencies and reproducible `go.sum`; introduce `sdk/database` with SQLite open/close, pragmas and explicit migration runner, plus connection and migration tests.
2. Port `sdk/events` to GORM transactions and SQLite-compatible SQL. Prove concurrent command replay, conflict, handler rollback, inbox deduplication and outbox atomicity.
3. Port Core models, repositories and migrations. Replace `core.*` identifiers and validate identity, ACL and Fabric behavior.
4. Port Task models, repositories and migrations. Prove task mutation + outbox atomicity and concurrent replay.
5. Port Notify models, repositories and migrations. Prove inbox + notification effects and stable outbound retry keys.
6. Switch each service's bootstrap/config to its own SQLite path; remove PostgreSQL wiring and dependencies only after every service and CLI is migrated.
7. Update Compose, CI, test fixtures and documentation. Run `go test ./...`, `go vet ./...`, race/concurrency tests and the running-consumer end-to-end chain.

## Release gates

- No service references PostgreSQL driver, schema names or PostgreSQL-specific SQL.
- No service can read or write another service's database.
- Each migration is deterministic, repeatable and failure-safe.
- Concurrent replay and consumer tests pass against file-backed SQLite.
- Existing tests and the M0-06 end-to-end proof pass before declaring migration complete.

## Implementation checkpoints (2026-10-26)

- Implemented: `sdk/database` with SQLite WAL, foreign-key enforcement, busy retry and Gormigrate.
- Implemented: owner-local SQLite schemas and migration CLI for Core, Task and Notify.
- Implemented: GORM-based SDK command replay and inbox/outbox helpers, plus Task and Notify persistence paths.
- Implemented: Core Runtime GORM desired-state compare-and-swap with multi-connection concurrency tests.
- Implemented: Core Identity GORM signing-key metadata, JWKS, service-credential revocation, nonce replay protection, session and delegation live-state checks.
- Implemented: Core Fabric GORM signed approval, rollback-safe revocation, ACL catalog loading, signed route snapshots, and instance lease/ready persistence.
- Verified: SQLite unit test suite in GitHub Actions at commit `bd2d582`; source formatting fixes are included.
- **Not yet implemented:** Core Identity account/session mutation and token exchange repositories; Core Access resource/grant/check mutation paths; full Core service composition using GORM; PostgreSQL removal; live multi-service M0-06 SQLite proof.
- **Deployment caution:** `arc-sqlite-migrate` builds the new database schemas, but does NOT switch the Core binary to SQLite. Core still requires PostgreSQL until the remaining modules and bootstrap have been ported.

```bash
CGO_ENABLED=1 go run ./cmd/arc-sqlite-migrate -service core -db /var/lib/arc/core/core.sqlite
CGO_ENABLED=1 go run ./cmd/arc-sqlite-migrate -service task -db /var/lib/arc/task/task.sqlite
CGO_ENABLED=1 go run ./cmd/arc-sqlite-migrate -service notify -db /var/lib/arc/notify/notify.sqlite
```

Keep PostgreSQL services running until the complete cutover has been verified.
