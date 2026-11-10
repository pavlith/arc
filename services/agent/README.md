# Arc Infrastructure Agent

Independent Linux process: `cmd/arc-agent` → `services/agent`. Core owns Runtime
state; SDK owns shared contracts. Agent has no Core database or inbound HTTP/RPC
listener and initiates private TLS/NKey NATS connections.

## Startup

```sh
go build -o /tmp/arc-agent ./cmd/arc-agent
/tmp/arc-agent -config /absolute/path/agent.json
```

Examples: [config](../../deploy/agent/config.example.json),
[systemd unit](../../deploy/agent/arc-agent.service). Operator installs binaries,
credentials, trust roots and units independently of Runtime.

- Provision a distinct active `arc-agent` service account, node binding and templates
  in Core. Explicitly enable RuntimeNodeRPC; new node enrollment needs Core restart.
- Config, 32-byte service seed and NKey seed belong to the process user, mode 0600.
  Snapshot public key is JSON-encoded base64 received through a trusted offline
  channel; it may differ from the Identity JWT key.
- State directory belongs to Agent, mode 0700. Journal holds exclusive flock for
  the process lifetime. Reject unknown/duplicate fields, unsafe templates and
  unsupported drivers.
- Broker publish: Identity service exchange and the node's three concrete subjects.
  Subscribe only `_INBOX.runtime.<node-id>.>`; Agent sets that InboxPrefix.

## Reconciliation

Each round obtains online inventory and fresh signed snapshots; no cached new
effect during Core/NATS outage and no delete inferred from missing inventory ID.
Effects are serial and bounded by snapshot expiry; failures back off up to a minute.
Logs contain IDs and fixed codes, not payloads/secrets.

Journal persists intent before effect. Inspector checks completed revisions before
drift repair, which still needs fresh online authorization. Inspection failure
denies effect. Report retries preserve event ID while running; pending reports are
in memory, so crash may create a new receipt while host operations remain idempotent.
New successful observations refresh liveness. Terminal failure needs a new desired
revision. SIGTERM/SIGINT release connections/journal and retain workloads.

## Systemd driver

Uses fixed `/usr/bin/systemctl show/start/stop`, without shell, inherited environment,
arbitrary arguments, installation or purge. System-level authorization is required.
Only preinstalled root-owned `/etc/systemd/system/arc-managed-<resource-id>.service`
is allowed, with resource ID matching template ID. Reject symlinks, writable
root paths, noncanonical fragment/ID, aliases/drop-ins, reverse stop propagation
and dependencies outside the driver's fixed allowlist.

Operator owns unit contents and resource/security limits. Running starts;
stopped/deleted stops and retains unit/data. Already satisfied state does not
restart. Explicit restart, enable/disable and unit edits are absent. Bootstrap/Agent
units are forbidden. Docker/LXD kinds exist in SDK but this binary rejects their
configuration because their drivers are not implemented. Full health/log reporting
after a terminal operation remains incomplete.

## Verification and limits

`make runtime-smoke` uses the NATS version pinned in Compose, real service
invocation/inventory and a separate Agent process; it checks graceful SIGTERM and
journal release. Focused race tests: `go test -race ./services/agent/... ./sdk/agent`.
Host effects use fake/command adapters; this does not establish live unit start/stop.

Optional read-only host check:
`ARC_AGENT_SYSTEMD_SMOKE=1 go test -count=1 -run TestSystemdMissingUnitReadOnly ./services/agent/drivers/systemd`.
It rejects a missing unit before start/stop. Remaining integrations are
[#13](https://github.com/pavlith/arc/issues/13); M7/production readiness is not claimed.
