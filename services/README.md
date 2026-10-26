# Arc services

- `core/`: Identity, Access, Fabric and Runtime in one trusted process and one SQLite file. Modules call direct Go interfaces; owner tables use module prefixes.
- `task/`: approved `task` service, task/root mutations, transactional replay/outbox and online ACL checks.
- `notify/`: approved `notify` service, atomic inbox/notification effects and durable delivery intents with stable provider keys.
- `gate/`: HTTPS ingress using signed routes and online Core checks, without a database.

Each SQL owner provides GORM models/repositories and explicit ordered Gormigrate migrations in its own `migrations/` package. SDK bootstrap opens only that service's absolute `sqlite_path`; it never runs migrations or chooses a service. Core uses the private SDK Micro bootstrap; domain services use `sdk/service.Compose` and typed `sdk/module` registrations.

`cmd/arc-task` and `cmd/arc-notify` own separate config, credentials, NATS connections and data volumes. Deploy migrations with `cmd/arc-sqlite-migrate -service OWNER -db /absolute/owner.sqlite` before traffic. CGO and a C compiler are required. Different services must never share or mount each other's database files.

Run `bash scripts/verify-changed.sh` for changed code and `bash scripts/test-m0-06.sh` for TLS/NKey and actual domain-process guardrails. Full M7 recovery/load coverage is separate.
