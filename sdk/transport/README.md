# Arc native NATS service transport

Arc implements only the NATS Micro v1 **monitoring protocol** required by
Fabric: `$SRV.PING`, `$SRV.INFO`, `$SRV.STATS` (global, name and instance ID),
plus queue-group endpoints. The response field names and `io.nats.micro.v1.*`
type tags are compatible with NATS CLI monitoring.

Everything else is Arc-owned: signed Fabric installation/lease, contract
approval, schemas, verified invocation, ACL, typed operations, replay and
outbox/inbox are enforced by `sdk/app`, `sdk/rpc` and `sdk/events`.

We do **not** vendor the full upstream `nats.go/micro` code; the implementation
is deliberately narrower and written for Arc's single-service-per-process
design. Low-level NATS connection, JetStream, request/reply, reconnect
subscriptions and NKey/TLS are still delegated to `nats.go`.
Do not use this transport directly for public, unauthenticated business RPC:
domain handlers must be registered through `sdk/service.Compose`.
Core's privileged bootstrap uses `sdk.NewService`.

Monitor compatibility based on the public NATS Micro v1 protocol:
https://github.com/nats-io/nats.go/tree/main/micro

Run `go test -race ./sdk/transport ./sdk/rpc ./sdk` plus M0 integration
guardrails to exercise real credentials, approvals, routing and liveness.
