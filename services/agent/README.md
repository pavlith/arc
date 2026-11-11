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

### Ubuntu node setup

Build `arc-agent` for the target architecture and copy the executable, the
[installer](../../deploy/agent/install.sh) and the systemd unit to the Ubuntu host.
Keep the installer and unit in the same directory. Provision the node in Core,
then install the root-owned config at `/etc/arc-agent/config.json` and provision
the keys and trust roots referenced by it. Run these commands on the target host.

```sh
bash install.sh list
bash install.sh plan
sudo bash install.sh apply /absolute/path/to/arc-agent
# Only for nodes explicitly intended to run Docker:
sudo bash install.sh apply /absolute/path/to/arc-agent --with-docker
```

The installer deploys Agent and systemd independently of Docker. Docker setup
is opt-in through `--with-docker`; the default path also works on a clean Ubuntu
host intended for LXD or package management. Pre-provision the node credentials,
trusted Core key and config through a secure operator channel first. This is
not unattended enrollment; see [host-management roadmap](../../docs/AGENT-HOST-ROADMAP.md).
Check correlated Agent logs for the first successful Runtime round with Core.
When updating only config or credentials, restart `arc-agent.service`.

### Node configuration

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

## Host inventory and APT planning

`arc-agent -host-info` prints bounded read-only JSON host facts without requiring
a connected Core. `arc-agent -apt-plan=curl,docker.io` simulates installation
locally and reports additions/removals without executing changes. Each online inventory round sends a validated host snapshot in
its first node-scoped RPC page. Core stores these facts separately from permissions;
they do not authorize any host actions. APT supports read-only installed-package
listing and a fixed-argv `apt-get -s` installation plan, including removal
warnings. Core can now store immutable manager-approved, node-scoped NodeProfiles
(versioned with revocation and exact package pins). The read-only
`apt.Manager.PlanProfilePackages` checks the supported Ubuntu release and
simulates pinned package versions, identifying removals and binding its
result to the profile digest. This does not execute Docker/LXD directives or
authorize any host changes. Neither API installs, removes nor updates packages;
Core-approved, signed host operations are a subsequent milestone.

## Reconciliation

`modules/reconcile` handles inventory, snapshot requests and reporting to Core.
`modules/runtime` binds a signed snapshot to the requested resource and uses the
SDK executor to journal and dispatch effects to the node-local driver for its
kind. A template requires a configured driver for that kind at startup.

Each round obtains online inventory and fresh signed snapshots; no cached new
effect during Core/NATS outage and no delete inferred from missing inventory ID.
Effects are serial and bounded by snapshot expiry; failures back off up to a minute.
Each online round uses one request/trace context across Identity and private
Runtime RPC. Reconciliation logs include duration and fixed codes, never payloads
or credentials; see [correlated diagnostics](../../docs/DEVELOPMENT.md#correlated-diagnostics).

Journal persists intent before effect. Inspector checks completed revisions before
drift repair, which still needs fresh online authorization. Inspection failure
denies effect. Pending Core receipts use atomic/fsynced per-resource files and
retain their event IDs across crashes. Identical observations have stable event
IDs and do not generate repeated receipts. Core updates node liveness from
authenticated Inventory at most once per minute, independently of receipts.

Revision high-water marks are stored in separate atomic files under
`state_directory/revisions/`. Existing `revisions.json` is read as a migration
baseline and is never rewritten by new agents. Preserve the entire state
directory across upgrades, including Docker ownership and pending receipts.

Transient host/timeout failures leave the operation pending; every retry first
fetches a new authorized snapshot. Explicit policy denials can still report
terminal failure, requiring a new desired revision. Host actions are bounded
by each short-lived snapshot and may complete over multiple online rounds.
SIGTERM/SIGINT release connections/journal and retain workloads.

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
units are forbidden. Full health/log reporting after a terminal operation
remains incomplete.

## Docker driver

Add a `docker.container` template to the local Agent config and approve the same
template revision in Core. Set `target` to a repository and immutable `@sha256:`
digest already available to the local Docker daemon. The Agent uses Engine API
v1.44 on `/var/run/docker.sock`. The daemon must support memory, swap, CPU and PID
limits and use the built-in seccomp profile.

The driver creates, starts, stops, replaces and scales its own containers. It
records a private creation intent and the Docker container ID under the Agent
state directory. Preserve this directory across upgrades and restarts. A lost
creation response is recovered by the saved name and validated container state.
Deletion removes owned containers without removing volumes. Images that declare
volumes are rejected.

This driver runs approved images as UID/GID 65532 with read-only root filesystems,
no network, no host mounts or published ports, and fixed CPU, memory, PID and log
limits. It reports running replica counts through the existing Core Runtime RPC.
Docker health status, log retrieval, networked services and one-shot jobs are
outside the current driver. Docker lifecycle tests use an isolated Engine API
fixture. On a dedicated Docker test node, set `ARC_AGENT_DOCKER_TEST_IMAGE` to an
approved local image digest whose entry point stays running under these limits
and run `go test -count=1 -run '^TestDockerEngineLifecycle$' ./services/agent/modules/docker`.
The smoke starts, inspects, stops and removes its test container. Live Docker
acceptance remains tracked in [#13](https://github.com/pavlith/arc/issues/13).

## Verification and limits

`make runtime-smoke` uses the NATS version pinned in Compose, real service
invocation/inventory and a separate Agent process; it checks graceful SIGTERM and
journal release. Focused race tests: `go test -race ./services/agent/... ./sdk/agent`.
Host effects use fake/command adapters; this does not establish live unit start/stop.

Optional read-only host check:
`ARC_AGENT_SYSTEMD_SMOKE=1 go test -count=1 -run TestSystemdMissingUnitReadOnly ./services/agent/modules/systemd`.
It rejects a missing unit before start/stop. Remaining integrations are
[#13](https://github.com/pavlith/arc/issues/13); M7/production readiness is not claimed.
