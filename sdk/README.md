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
| `sdk/security` | Signed JWT, PoP, JWKS, invocation verification |
| `sdk/telemetry` | Optional safe operation observation |
| `sdk/testcontract` | Shared test fixture, not business service code |

## Architectural boundaries

Each service is a separately deployed executable under `cmd/arc-<service>`;
its own `services/<service>/` directory owns API, migrations, modules, and
bootstrap composition. `sdk/bootstrap` does not know concrete services.

Every RPC subscription requires a **Fabric-approved contract** and runtime
lease. `sdk/service.Compose` installs typed operations and enforces online ACL
and verified identity before domain effects; it does not grant privileges.
Core's privileged private/bootstrap transport uses `sdk.NewService`.

The SDK contains a **small Arc-native NATS transport**, not a fork of the
entire `nats.go/micro` package. Service monitoring retains the public
`$SRV.PING/INFO/STATS` protocol and `micro_id` identity used by Fabric.
Actual NATS network, JetStream and NKey/TLS remain in `nats.go`.
Do not directly register domain endpoints with `sdk/transport`: its job is
routing and introspection, **not** proof, policy or schema checks.

`sdk/agent.NewNodeClient` fixes one node ID on an existing RPC connection and takes an operation-bound `InvocationCredentials` factory. Use `sdk.Connect` with that node's TLS/NKey paths and `InboxPrefix: "_INBOX.runtime.<node-id>"`; the broker should allow reply subscriptions only under that prefix. The factory must obtain a service invocation from Identity and respect the supplied context; assertions alone are rejected by Runtime. Concrete `ctl.runtime.v1.node.<node-id>.*` subjects are limited to inventory, desired.get and report. The executor must independently verify signed pull responses against its Core key and local template allowlist. `make runtime-smoke` exercises the private Core protocol with real TLS/NKey, Identity, Access and a fake host driver.

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

Verification:

```bash
go test -race ./sdk/... ./services/...
go vet ./...
go build ./cmd/...
make m0-06-smoke
```

The M0 suite is the end-to-end security and interoperability acceptance
gate for changes to the SDK transport. Deployment of the task and notify
services remains independent.
