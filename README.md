# Arc

Arc is a self-hosted team collaboration platform, currently building its M0 foundation.
Work and status live in [GitHub Issues](https://github.com/pavlith/arc/issues).
Engineering materials use English; every change starts with an Issue.

- [Documentation](docs/README.md): requirements, architecture and component guides.
- [Development](docs/DEVELOPMENT.md): local setup, verification and issue-first delivery.

One root Go module contains `sdk/`, Core modules and domain services. Existing
executables are Gate, Task, Notify and the Linux infrastructure Agent in `cmd/`.
Core currently runs inside integration hosts; its missing standalone executable
is tracked in [#15](https://github.com/pavlith/arc/issues/15). Shared test tools live
in `test/`, deployment configuration and the explicit migrator in `deploy/`.

The HTTPS Gate → Task/Core → JetStream → Notify proof path and private Runtime node
protocol have focused guardrails. Full product/admin APIs, Office features and
Svelte UI are not implemented. See [service capabilities](services/README.md).
Historical Issue reports do not establish code absent from this checkout.

Development requires Go 1.27+ and a C compiler for SQLite/CGO. Network checks also
need Python 3 and the `nats-server` version pinned in `compose.yaml`.

```sh
make verify
make m0-06-smoke
```

[Local infrastructure](docs/DEVELOPMENT.md#local-environment) additionally supports
Docker Compose. M7 recovery, compatibility and load verification remains deferred.
