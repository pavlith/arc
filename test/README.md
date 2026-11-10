# Shared test infrastructure

Component unit/integration tests remain beside code in `sdk/` and `services/`.
This directory contains reusable fixtures and isolated test commands.

| Path | Purpose |
|---|---|
| `bootstrap/` | TLS/NKey and temporary NATS configuration generator |
| `task-notify-credentials/` | Scoped broker identities for the vertical proof |
| `rpc-smoke/` | RPC/JetStream and negative broker-permission checks |
| `testdb/` | Migrated, owner-local SQLite fixtures |
| `compose.yaml`, `docker/` | Test client overlay for root Compose infrastructure |

Run scenarios through `scripts/test-*.sh` and `scripts/test-runtime.py`; commands
and dependencies are in [development](../docs/DEVELOPMENT.md#verification).
Credential generators are for dev/test. The deployment migrator is separate in
`deploy/migrate/`.
