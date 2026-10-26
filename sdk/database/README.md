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

**Migration status:** this SDK package is available but existing service
bootstrap and SQL repositories still use PostgreSQL until each owner is ported.
Do not point the current service binaries at these SQLite files.
