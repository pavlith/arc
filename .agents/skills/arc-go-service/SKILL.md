---
name: arc-go-service
description: Build Arc Go/Echo domain services, Core modules or SDK integrations. Use when Go code, NATS endpoints, migrations or service registration is requested.
---

# Arc Go service workflow

1. Confirm actual code layout before creating new packages; docs/ARCHITECTURE.md §11 describes one root Go module; do not invent legacy paths or separate modules.
2. Locate affected contract and its owning service. Use Go interfaces inside a process and NATS only between processes.
3. Prefer the smallest interface, no unnecessary abstraction or new dependencies. Preserve domain data ownership and explicit migrations.
4. Use Arc typed service/module composition over sdk/transport and official nats.go. The transport implements Micro-compatible monitoring; it is not an upstream micro wrapper. Do not register raw business endpoints or fork upstream code.
5. Include structured errors, cancellation/deadlines and the relevant authorization/security guardrails for boundary code.
6. Run focused Go formatting, compilation and package tests via arc-verify. Avoid full M7 integration tests unless asked.
