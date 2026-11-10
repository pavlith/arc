# Arc services

- `core/`: Identity, Access, Fabric and Runtime in one trusted process and one SQLite file. Modules call direct Go interfaces; owner tables use module prefixes.
- `task/`: approved `task` service, task/root mutations, transactional replay/outbox and online ACL checks.
- `notify/`: approved `notify` service, atomic inbox/notification effects and durable delivery intents with stable provider keys.
- `gate/`: HTTPS ingress using signed routes and online Core checks, without a database.

Each SQL owner provides GORM models/repositories and explicit ordered Gormigrate migrations in its own `migrations/` package. SDK bootstrap opens only that service's absolute `sqlite_path`; it never runs migrations or chooses a service. Core uses the private SDK Micro bootstrap; domain services use `sdk/service.Compose` and typed `sdk/module` registrations.

`cmd/arc-task` and `cmd/arc-notify` own separate config, credentials, NATS connections and data volumes. Deploy migrations with `cmd/arc-sqlite-migrate -service OWNER -db /absolute/owner.sqlite` before traffic. CGO and a C compiler are required. Different services must never share or mount each other's database files.

Run `bash scripts/verify-changed.sh` for changed code and `bash scripts/test-m0-06.sh` for TLS/NKey and actual domain-process guardrails. Full M7 recovery/load coverage is separate.

Runtime recovery is tracked in [#13](https://github.com/pavlith/arc/issues/13). `sdk/agent` defines the typed node boundary and `agent/journal` supplies a Linux persistent single-writer journal. No host driver or Agent RPC is currently bound; Core's existing untyped `runtime.Desired.Spec` is storage only and must never be forwarded directly to a privileged driver. Future control API must validate typed specs against approved node templates and enforce live `arc.runtime.manage`. Docker, LXD and systemd resources are distinct; Svelte UI must use Gate. Earlier unpushed implementation reports do not describe this checkout.
