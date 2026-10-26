# Arc services — independent Core and Gate packages

This directory introduces the first service-owned packages without changing any
legacy `sdk/` source, NATS subjects, signed artifacts or the existing M0 startup.

- `core/`: four in-process modules (`identity`, `access`, `fabric`, `runtime`),
  owner-local SQL migrations, typed API aliases and a single trusted NATS Micro bootstrap.
- `gate/`: independently composed `http`, `discovery` and `listener` modules.
  Gate reads signed route snapshots, verifies on-line auth, and never reads the Core database.
- `internal/testcontract/`: test-only artifact fixture shared by service packages.

The implementations of Identity, Access, Fabric and Gate HTTP are based on the
already-tested M0 code, moved to service ownership and retargeted to
`github.com/pavlith/arc/pkgs`. All domain RPC operation IDs, NATS subjects,
approval signatures and message semantics are unchanged.

**Security boundary:** `pkgs/service.Compose` is reserved for operator-approved
domain services. Core's root/bootstrap endpoints cannot be registered as an
unapproved domain contract merely to reuse that API; Core uses the separate
low-level `pkgs.Service` Micro transport with strict private subjects. The
modules still use direct Go interfaces internally. Gate remains an HTTPS edge
process, not an NATS business-service publisher.

No production binary or deployment has been switched from the existing `sdk/`
implementation. The new packages need real PostgreSQL/NATS integration
validation before cutover. `services/core/migrations` are embedded and should
be applied by the migrator under its scoped role; do not run them a second time
against a database where the legacy migrations have already been applied.

To verify:

```bash
go test -race ./services/...
go vet ./services/...
go build ./services/...
```
