# Arc pkgs — independent typed service SDK

`sdk` is part of the single root Go module (`github.com/pavlith/arc/sdk`) and does **not** import the existing `github.com/pavlith/arc/sdk` module. Existing M0 services and CI keep using `sdk/`; no runtime migration is implied by adding `sdk/`.

## Packages

| Package | Responsibility |
| --- | --- |
| `sdk` | Approved instance registration, NATS Micro runtime, authenticated handler pipeline |
| `pkgs/service` | Typed service composition, module lifecycle and workers |
| `pkgs/module` | Typed query/command/event bindings and per-operation authorization |
| `pkgs/client` | Typed calls against approved operation subjects and schemas |
| `pkgs/contract` | Strict immutable manifest, JSON Schema, digest, compatibility |
| `pkgs/rpc` | NATS RPC envelope, error codes, signed invocation verification |
| `pkgs/events` | Domain-local transactional replay, outbox, inbox, JetStream delivery |
| `pkgs/security` | Ed25519 JWT, caller proof, JWKS and active-key verification |
| `pkgs/transport` | Low-level NATS Micro connection/endpoint |
| `pkgs/telemetry` | Optional safe observation hooks |

A process can host multiple service identities, but **each approved service** must have its own contract, account/credentials, permitted subjects and data ownership. `module.Module` is a code-composition unit, not a security identity. `Kind` is descriptive and never relaxes security.

## Service composition

```go
// In your service's service.go (illustrative, with real dependencies supplied):
cfg := service.Config{
    Definition: service.Definition{
        Name: "task", APIMajor: 1, Kind: service.Domain,
        Modules: []module.Module{tasks.New(deps)},
    },
    Runtime: pkgs.AppConfig{
        Artifact: approvedArtifact,
        Instance: instanceID,
        Registry: approvedFabricRegistry,
        Authorize: verifiedInvocationAuthorizer,
        SelfCheck: db.PingContext,
        Connection: natsConfig,
    },
}
app, err := service.Compose(cfg)
if err != nil { return err }
if err := app.Start(ctx); err != nil { return err }
defer app.Stop()
```

Module registration uses package-level generic functions because Go does not support methods with new type parameters:

- `module.BindQuery(r, module.Query[Req,Res]{ID: "..."}, policy, handler)`
- `module.BindCommand(r, module.Command[Req,Res]{ID: "..."}, policy, domainStore, transactionalHandler)`
- `module.EnqueueEvent` / `module.ConsumeEvent` for typed payloads in the domain-local outbox/inbox.
- `client.Query` / `client.Command` for schema-validated calls via exact contract subjects.

Every manifest operation needs exactly one binding. The policy is required, selected by signed operation identity, and uses the existing verified SDK envelope, schema validation and domain-owner ACL check. `Resource` must validate the resource/root relationship **before** checking ACL online; `Trusted` must implement a strict service-actor policy. An empty policy, unapproved operation or missing mandatory handler fails composition.

Workers start **after** service registration/readiness, stop with the service, and stop the service on unexpected failure. Worker registration is not a permit: event consumers must configure the source/subject/durable EventPermit through `events.Delivery.Permit`, and check it for each batch. External side effects still need stable idempotency keys and can be at least once.

The canonical, installed contract artifact remains the authority for API subjects/HTTP exposure, schemas, auth modes and service identity. Go DTO types are compile-time bindings, **not** a replacement for wire-level JSON Schema or contract compatibility testing. `service.Compose` deliberately cannot authorize anything outside an approved manifest.

## Verification

```bash
cd pkgs
go test -race ./...
go vet ./...
go build ./...
```

Integration with a real Arc Core, NATS and PostgreSQL remains governed by the existing M0 guardrails and must be repeated when moving the first service from `sdk/` to `sdk/`. The standalone package does not yet replace any existing deployment.
