# SQLite / GORM storage contract

Core, Task and Notify each own a local SQLite file, GORM repositories and an ordered Gormigrate history. Gate has no database. The SDK supplies connection/transaction/retry helpers, without service models or automatic migrations.

- Configure an absolute `sqlite_path`; parent directories must already exist and belong to the service user. Files start with mode 0600. Mount only that owner's directory, including WAL/SHM sidecars.
- Use WAL, foreign keys and a 10-second busy timeout on every connection. SQLite has one writer; acquire its write lock before reading mutable authorization/domain state and retry complete short transactions on busy errors.
- Run immutable explicit migrations before traffic. AutoMigrate during service startup is forbidden. Only one owner migrator may run at a time; unknown migration IDs fail closed.
- Domain mutation, audit, command result and outbox share one GORM transaction. Same actor/operation/key and canonical payload replays the result; changed payload conflicts; failed handlers leave no effects.
- Inbox deduplication and internal effects commit together. Stable event IDs and provider keys survive retry/restart; external sends require provider idempotency.
- Core modules share one database and can join the current in-process transaction for live policy checks. Different service owners communicate only through RPC/events.
- Local processes of one owner may share one file; independent databases on different hosts and network filesystems are unsupported. Gate replicas remain independent.
- Back up through SQLite backup API or with the owner stopped and its committed WAL state preserved. Existing data from the former database backend requires a separately verified export/import; switching storage does not transfer it.

```sh
bash scripts/migrate.sh core /var/lib/arc/core/core.sqlite
bash scripts/migrate.sh task /var/lib/arc/task/task.sqlite
bash scripts/migrate.sh notify /var/lib/arc/notify/notify.sqlite
```

Build with `CGO_ENABLED=1` and a C compiler. Compose migration containers and domain containers use separate owner volumes. `go test ./...` covers file-backed repositories and migration replay; `scripts/test-m0-06.sh` supplies TLS/NKey NATS and real Task/Notify process restart guardrails. Full M7 recovery/load testing remains deferred.
