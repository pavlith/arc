# Arc

Self-hosted collaboration platform: Core Identity/Access/Fabric, HTTPS Gate, Task, Notify, Files, Pages and infrastructure Agent, with a SvelteKit browser client. Go code is one root module; SQLite databases and migrations are owned independently by each service.

- [Docs](docs/README.md) · [Architecture](docs/ARCHITECTURE.md) · [Development](docs/DEVELOPMENT.md) · [Issues](https://github.com/pavlith/arc/issues)
- `main`: active development and source of truth. `dev`: retained historical reference.
- Backend delivery is not product acceptance or production deployment; track unfinished UI and verification in Issues.

Requirements: Go 1.27+, C compiler/CGO for SQLite; network tests use Python 3 and the pinned `nats-server`. UI workspaces are `client/web` (`ui`) and `client/ts` (`@arc/client`).

```sh
bash scripts/verify-changed.sh --base HEAD
npm --prefix client ci
npm --prefix client run check --workspace ui
```

Security-sensitive work requires the [focused guardrails](docs/DEVELOPMENT.md#verification); scheduled/manual CI runs the full Go regression. No automated production setup or secrets are provided.
