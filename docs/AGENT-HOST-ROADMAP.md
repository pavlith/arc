# Arc Agent: Ubuntu host management rollout

Status: implementation plan, not a claim of production readiness. The GitHub Issues board remains the source of truth for task status. See [Runtime architecture](ARCHITECTURE.md) §7 and [Infrastructure Agent](../services/agent/README.md).

## Goal

Enroll a new Ubuntu VPS, inspect it from Core, plan and approve host changes, and manage packages, systemd, Docker and LXD through typed, auditable operations. The managed node must remain recoverable by SSH/systemd when Core or NATS is unavailable.

## Delivery sequence

### 1. Host visibility (in progress, PR #20)

- Read-only `arc-agent -host-info` reports Ubuntu version, kernel, CPU threads, memory, root filesystem and presence of APT/systemd/Docker/LXD.
- Node-scoped authenticated `Inventory` delivers these facts. Core persists them via an additive migration and exposes them through its authorized node listing.
- Facts **never** grant tool access or override signed templates and service account bindings. Node liveness remains independent of operation receipts.
- APT adapter supports installed-package inspection and dry-run installation planning, with bounded output and fixed argv, without host mutation.
- `deploy/agent/install.sh apply <binary>` installs only Agent by default; Docker setup is separately opt-in.

### 2. Secure enrollment

- Add one-time, short-lived, single-node enrollment offers issued only by a non-delegated Arc administrator.
- Initial access to a bare host uses operator SSH or cloud-init with a pinned Core trust root; agent credentials are provisioned only after mutual verification and node binding.
- Never embed a reusable NATS NKey/private key in public scripts, logs or an HTTP URL.
- Restart/re-enrollment, key rotation, rejection of duplicate identities and cleanup of stale offers are mandatory integration tests.

### 3. Typed NodeProfile and package execution

Current: an administrator-only, immutable NodeProfile approval contract (versioned
per node) with a separate Core SQLite migration is available. This does not
permit Agent execution. A local read-only `PlanProfilePackages` helper
simulates version-pinned APT requests and binds output to the approved
profile digest. A typed, node-scoped NATS `profile.plan` RPC now returns a
30-second, domain-separated Core signature; the Agent supports a one-shot
`-preview-profile` CLI and never executes APT changes with this response.
Enrollment, signed **mutation** permits, actual package transactions and
Docker/LXD profile application are not implemented.

- Store a versioned and immutable approved `NodeProfile` in Core, with Ubuntu version constraints, exact apt package versions or approved repositories, system services, Docker/LXD enablement and update policy.
- `plan` must return the proposed package additions, upgrades, removals, held-package changes, service restarts, connectivity risks and reboot requirement; plans expire and bind to the observed node state and profile revision.
- `apply` must require online, audience-bound signed authorization, explicit approval for removals/SSH/firewall/kernel changes, stable idempotency key and durable execution journal.
- Prevent unattended release upgrades and unapproved APT sources; coordinate with APT/dpkg locks and existing unattended-upgrades.
- Treat an expired authorization as a stop-before-next-step boundary, not a license to keep issuing new host commands. Resume only after a fresh Core authorization.
- **No arbitrary shell** or caller-supplied command/env strings.

### 4. Docker and LXD management

- Expand Docker observation and health; support explicitly approved image digests, isolated networks, volumes and declarative Compose-equivalent specifications under Arc-owned resource namespaces.
- Implement LXD through `github.com/canonical/lxd/client` over the host-local Unix socket. Profiles, snapshots, storage, VM/container configuration and image fingerprints each need separate policy checks.
- Distinguish `discovered` (read-only) and `managed` (write) resources. Adoption requires explicit operator intent; never infer ownership from names or labels.
- Retain data/volumes by default. Destructive purge, backup restore and firewall/network changes require dedicated confirmation and audit.

### 5. Maintenance, observability and UI

- Report stale/degraded host health, package update candidates, reboot-required status, filesystem capacity, unit/container health, bounded logs and operation progress.
- Support maintenance windows, bounded retry/backoff, human approvals, rollbacks where supported and alerts on reconnect/failed updates.
- Add Gate-approved, online ACL-checked routes and a Svelte 5 dashboard for nodes, profiles, plans, operations and host resources.
- Host maintenance is an infrastructure-admin capability; workspace administrators cannot inherit it by default.

## Bootstrap and recovery guarantees

The Core/NATS/Gate/Agent bootstrap stack is independently installed and cannot be deleted by Runtime operations. A network or Core outage retains running workloads, but prevents **new** mutating operations. Avoid coupling host administration to the availability of a browser session. Never expose Docker/LXD sockets to the public network.

## Test acceptance gates

1. Clean Ubuntu 24.04/26.04 installation with no Docker preinstalled.
2. Node-scoped TLS/NKey request proof, cross-node rejection and revocation.
3. Host facts: malformed claims, schema migration upgrade/replay, unchanged observations, pagination.
4. APT simulation: argument injection, removals, package holds, locked dpkg and missing apt metadata.
5. Operator approval, stale/replayed profile, partial update and agent restart recovery.
6. Docker/LXD separate live test nodes: privilege escalation denial, unsafe mounts/networking, foreign resource protection and retained data.
7. Core/NATS outage, disconnected SSH recovery, agent self-update rollback and M7 crash/race/load suite.

Only step 1's read-only foundation is included in the initial host-management PR. Do not interpret this document as an authorization to execute host changes.
