# Ubuntu Agent rollout

Issue status is authoritative in [GitHub Issues](https://github.com/pavlith/arc/issues); this is a dependency/safety map, not an implementation checklist. See [Runtime architecture §7](ARCHITECTURE.md#7-runtime-control-and-infrastructure-agent) and [Agent](../services/agent/README.md).

## Delivered foundations (not remote production enrollment)
- Read-only Ubuntu/kernel/CPU/RAM/disk/APT/systemd/Docker/LXD inventory and bounded APT dry-run planning; authenticated node-scoped inventory does not grant mutation rights.
- Core's in-process single-use, key-bound enrollment tickets and identity/node binding; local enrollment keygen/claim helpers. Remote TLS enrollment, NATS provisioning and UI are **not** ready.
- Immutable administrator-approved NodeProfiles and signed, short-lived read-only `profile.plan` previews. These signatures do **not** authorize package changes.

## Next dependencies
1. **Enrollment:** operator SSH/cloud-init bootstrap with pinned Core trust; one-use node-bound offers, mutually authenticated TLS credential exchange, unique NKeys, expiry/replay/revoke/key rotation tests. Never publish reusable secrets.
2. **Typed APT apply:** immutable approved package versions/repositories and current observed host state; explicit online signed mutation permit, per-step reauthorization, durable journal, locks and restart recovery. Prompt for removals, SSH/firewall/kernel changes. Never accept arbitrary shell, env or unapproved sources.
3. **Docker/LXD:** operator-owned resource adoption only, approved immutable image digests and isolated networks/volumes; LXD via host-local Unix socket with independent profile/storage/VM/container checks. A discovered resource is not managed. Destructive purge/restore and network changes require separate approvals; preserve data by default.
4. **Observability/UI:** bounded logs/health, reboot/update proposals, maintenance windows and approval status through signed Gate APIs. Infrastructure authority cannot be inherited from a workspace-admin role.

## Non-negotiable recovery and acceptance
Core/NATS/Gate/Agent bootstrap is installed separately from managed workloads and must remain SSH/systemd-recoverable. Outages preserve already-running workloads but block new host mutations. Never expose Docker/LXD sockets publicly.

Test across clean Ubuntu 24.04/26.04 and distinct node identities: cross-node proof/revoke, malformed inventory, migration replay, APT holds/locks/injection, stale/replayed profiles, partial apply and restart, foreign container/volume isolation, SSH recovery and signed approvals. Live driver coverage and the M7 crash/race/load matrix remain separate; a read-only preview is not host-change authorization.
