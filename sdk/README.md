# Arc SDK

Single Go module: `github.com/pavlith/arc`. The `sdk/` directory is a
library **within** this module; it has no `go.mod` or `go.sum`.

| Package | Role |
| --- | --- |
| `sdk/agent` | Typed infrastructure specs/templates and content digests, signed short-lived snapshots, RuntimeProvider inventory/pull/report, per-node NATS NodeClient with operation-bound invocation/proof, serialized executor and driver/journal interfaces; no host driver |
| `sdk/bootstrap` | Common infrastructure config, independent process resources |
| `sdk/transport` | Native NATS queue endpoints and Micro-compatible PING/INFO/STATS |
| `sdk` | Approved service registration, readiness, lease checks, transport ownership |
| `sdk/service` | Typed service and module composition, worker lifecycle |
| `sdk/module` | Typed queries, commands, events, per-operation authorization |
| `sdk/rpc` | Signed RPC envelope, deadlines, schemas, error mapping |
| `sdk/client` | Typed contract-checked RPC calls |
| `sdk/contract` | Immutable manifest and JSON Schema validation |
| `sdk/events` | Transactional outbox, inbox, retry, JetStream delivery |
| [`sdk/database`](database/README.md) | SQLite connection settings and explicit owner-local migration runner |
| `sdk/security` | Signed JWT, PoP, JWKS, invocation verification |
| `sdk/telemetry` | Optional safe operation observation |
| `sdk/testcontract` | Shared test fixture, not business service code |

## Architectural boundaries

Domain services have executables under `cmd/arc-<service>` and own API,
migrations, modules and composition under `services/<service>/`. Core currently
has no executable entry point; see [#15](https://github.com/pavlith/arc/issues/15). `sdk/bootstrap` does not know concrete services.

Domain RPC subscriptions require a **Fabric-approved contract** and runtime
lease; private Core bootstrap and node protocols have explicit separate policy. `sdk/service.Compose` installs typed operations and enforces online ACL
and verified identity before domain effects; it does not grant privileges.
Core's privileged private/bootstrap transport uses `sdk.NewService`.

The SDK contains a **small Arc-native NATS transport**, not a fork of the
entire `nats.go/micro` package. Service monitoring retains the public
`$SRV.PING/INFO/STATS` protocol and `micro_id` identity used by Fabric.
Actual NATS network, JetStream and NKey/TLS remain in `nats.go`.
Do not directly register domain endpoints with `sdk/transport`: its job is
routing and introspection, **not** proof, policy or schema checks.

`sdk/agent.NewNodeClient` fixes one node ID on an existing RPC connection and takes
an operation-bound `InvocationCredentials` factory. It must obtain an Identity
invocation and respect the supplied context; assertions alone are rejected.
The executor independently verifies signed pull responses against its Core key
and local template allowlist. See [Agent startup](../services/agent/README.md#startup)
for node-scoped credentials, inbox permissions and configuration, and
[Runtime contracts](../docs/ARCHITECTURE.md#7-runtime-control-and-infrastructure-agent)
for protocol boundaries.

Go syntax:

```go
service.Compose(service.Config{
    Definition: service.Definition{
        Name: "task", APIMajor: 1, Kind: service.Domain,
        Modules: []module.Module{taskModule, outboxModule},
    },
    Runtime: approvedSDKAppConfig,
})
```

Handlers use `module.BindQuery` / `module.BindCommand`, consumers must use
an exact Fabric event permit, and mutation replay + outbox must share a domain
transaction. Workers run only after service readiness.

Use the [verification guide](../docs/DEVELOPMENT.md#verification) for focused SDK
checks and required transport smoke. Task and Notify deploy independently.
