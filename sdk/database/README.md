# SDK database

The Arc SDK owns only the SQLite connection settings and Gormigrate runner.
Each service owns its own absolute SQLite file, tables, GORM models, and migration
history. The service **does not** migrate on startup; deployment runs its
migrator exactly once before starting consumers or accepting requests.

```go
db, err := database.Open(ctx, "/var/lib/arc/task/task.sqlite")
if err != nil { return err }
defer database.Close(db)
err = database.Migrate(ctx, db, task.Migrations())
```

Use `gorm.DB.Transaction` for domain writes + inbox/outbox. Uniqueness
constraints, not process mutexes, enforce replay/inbox deduplication. Handle
SQLite's one-writer limitation and transient busy responses. Explicit migration
versions cannot be removed from a released service.

This SQLite driver uses CGO. Build with `CGO_ENABLED=1` and a C compiler.

## Explicit migration command

Task and Notify have registered owner-local SQLite migrations:

```sh
go run ./cmd/arc-db-migrate -service task -db /var/lib/arc/task/task.sqlite
go run ./cmd/arc-db-migrate -service notify -db /var/lib/arc/notify/notify.sqlite
```

Create the parent directories with appropriate owner permissions first. Run the
migrator as a separate deployment step with no other migrator active. The
command deliberately rejects `core` until its SQLite schema has been ported.

**Migration status:** SQLite repositories are being introduced incrementally.
Core and other remaining PostgreSQL paths have not been cut over. Do not
interpret a successful migration command as proof that the corresponding
service is fully SQLite-only; verify its runtime wiring and end-to-end tests
before deployment.
