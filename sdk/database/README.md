# SDK database

The Arc SDK owns only the SQLite connection settings and Gormigrate runner.
Each service owns its own absolute SQLite file, tables, GORM models, and migration
history. The service **does not** migrate on startup; deployment runs its
migrator exactly once before starting consumers or accepting requests.

```go
db, err := database.Open(ctx, "/var/lib/arc/task/task.sqlite")
if err != nil { return err }
defer database.Close(db)
err = database.Migrate(ctx, db, taskmigrations.SQLite())
```

Use `gorm.DB.Transaction` for domain writes + inbox/outbox. Uniqueness
constraints, not process mutexes, enforce replay/inbox deduplication. Handle
SQLite's one-writer limitation and transient busy responses. Explicit migration
versions cannot be removed from a released service.

This SQLite driver uses CGO. Build with `CGO_ENABLED=1` and a C compiler.

## Explicit migration command

Core, Task and Notify have registered owner-local SQLite migrations:

```sh
go run ./cmd/arc-sqlite-migrate -service core -db /var/lib/arc/core/core.sqlite
go run ./cmd/arc-sqlite-migrate -service task -db /var/lib/arc/task/task.sqlite
go run ./cmd/arc-sqlite-migrate -service notify -db /var/lib/arc/notify/notify.sqlite
```

Create the parent directories with appropriate owner permissions first. Run the
migrator as a separate deployment step with no other migrator active. The
command rejects unknown owners before opening or creating a database.

Core, Task and Notify runtime wiring uses these GORM handles exclusively. Gate has no database. Compose uses separate owner volumes and explicit migration containers; never mount another owner's data directory into a domain service. SQLite requires local storage and a single shared file for processes of the same owner; independent file replicas across hosts are unsupported. Back up a consistent snapshot including committed WAL state.
