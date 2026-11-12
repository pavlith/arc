# Arc

Self-hosted collaboration platform: Core Identity/Access/Fabric, HTTPS Gate, Task, Notify, Files, Pages, Calendar, Contacts, Mail connections and infrastructure Agent, with a SvelteKit browser client. Go code is one root module; SQLite databases and migrations are owned independently by each service.

- [Docs](docs/README.md) · [Architecture](docs/ARCHITECTURE.md) · [Development](docs/DEVELOPMENT.md) · [Issues](https://github.com/pavlith/arc/issues)
- `main` is the active source of truth; GitHub Issues track incomplete product acceptance.
- Backend delivery is not product acceptance or production deployment; track unfinished UI and verification in Issues.
- [Mail](docs/MAIL.md) currently provides personal connection settings, sealed credentials and TLS checks; synchronization and provider OAuth acceptance remain pending.

Requirements: Go 1.27+, C compiler/CGO for SQLite; network tests use Python 3 and the pinned `nats-server`. Clients use Node.js 26 and the npm version in `client/package.json`; `client/web` (`ui`) and `client/ts` (`@arc/client`) share `client/package-lock.json`.

```sh
bash scripts/verify-changed.sh --base HEAD
npm --prefix client ci
npm --prefix client run check --workspace ui
```

Per-push CI runs relevant Go/UI/docs and security checks. Weekly CI runs full Go race tests; `v*` release tags and manual runs add Core/Runtime, signed vertical, Files/Pages and bootstrap acceptance. See [verification](docs/DEVELOPMENT.md#verification). No automatic deployment or production secrets.
