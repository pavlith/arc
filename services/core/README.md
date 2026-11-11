# Standalone Arc Core

`cmd/arc-core` runs the existing Identity, Access, Fabric and Runtime modules in
one private process and one Core-owned SQLite file. It exposes no public HTTP,
administrative provisioning or Runtime node/management endpoint. Domain services
still require operator-approved contracts and their own credentials and databases.

## Startup

Use [configuration](../../deploy/core/config.example.json) with absolute paths.
Provision the owner directory, credentials and pinned trust roots independently
of Runtime, then run migrations explicitly before starting Core:

```sh
go build -o /tmp/arc-core ./cmd/arc-core
bash scripts/migrate.sh core /var/lib/arc/core/core.sqlite
/tmp/arc-core -config /etc/arc/core/config.json
```

Core requires an existing private database and the exact current Core migration
history. It never creates a database, runs migrations or provisions users/service
accounts. Operator provisioning uses the existing local Identity/Fabric APIs;
product provisioning remains #9. A fresh migrated database can start with an
explicit signed empty bootstrap policy; authenticated operations still require
provisioned accounts, public credentials and narrowly approved rules.

Configuration and referenced files must be regular files at absolute paths;
symlinks and group/other-writable files are rejected. Keep their directories
operator-controlled. The database, raw 32-byte Ed25519 seed files and NKey seed
must have mode 0600 (or stricter). Public trust roots, signed approvals and
configuration may be readable, but contain no inline private keys or passwords.

- `identity_key_file`: Core invocation/access signing seed.
- `identity_signing_kid`, `identity_key_expires_at`: explicit key ID and absolute
  RFC3339 expiry. Initial startup publishes only public metadata through the
  audited Identity API. Restart requires the same live key and expiry; it never
  extends validity, changes a key under an existing ID or revives revocation.
- `installation_approval_key_file`: JSON base64-encoded operator Ed25519 public
  key. Its private key stays offline and never enters the Core process.
- `contract_bootstrap_files`: one to 32 JSON `access.Approved` documents, each
  with `Payload` (an `access.Approval` JSON object) and `Signature` (base64 Ed25519
  signature over RFC 8785 canonical payload). Use explicit Identity/control
  rules only; business types/rules come from signed Fabric installations.
- `snapshot_key_file`, `snapshot_kid`: Fabric control/snapshot signing identity.
- `route_trust_key_file`: route-bundle trust signing seed, whose public key is
  pinned independently by Gate.
- `nats`: TLS URL without userinfo, private NKey seed and pinned CA paths. The
  broker identity is separate from Arc signing keys. No plaintext URL fallback.

Every bootstrap approval and persisted active installation is validated before
subscriptions are created. The process logs fixed startup/error messages rather
than configuration, key bytes, passwords, approvals or session tokens. Do not
reuse test keys or mount the operator approval private key into any service.

## Broker and lifecycle

Keep NATS private. Core subscribes to Identity/Access RPC, Fabric control subjects
and Micro monitoring; it publishes replies, Fabric probes and route-change hints.
Constrain these subjects to the Core broker identity. Gate and domain callers
retain separate broker permissions, Arc assertions/invocations and request proof.
Broker access alone never grants login, business or administrative authority.

Invitation onboarding requires a signed bootstrap rule for the provisioned Gate
account: audience `identity/v1`, operation `identity.v1.sessions.register_invited`,
actor kind `bootstrap`. Give that account broker publish permission for
`rpc.identity.v1.sessions.register_invited` and replies. Core additionally verifies
the live `gate` service definition. Existing deployments without this explicit
approval fail closed; do not grant wildcard Identity operations. The public
endpoint and one-time recovery behavior are described in
[architecture](../../docs/ARCHITECTURE.md#32-credential-boundaries).

Workspace invitation history additionally requires the exact bootstrap operation
`identity.v1.product.invitations.list` for Gate, audience `identity/v1`, actor kind
`bootstrap`, and its corresponding RPC broker permission. Core rechecks the
browser session and live workspace owner/admin role on every read.

Account management uses exact Gate bootstrap operations
`identity.v1.product.account.sessions.list`,
`identity.v1.product.account.sessions.revoke` and
`identity.v1.product.account.password.change`; recovery uses
`identity.v1.users.recover`. Each needs audience `identity/v1`, actor kind
`bootstrap`, and its corresponding broker RPC permission. These approvals enable
the API; Core still checks the live browser session, ownership/current password,
or one-time recovery code as appropriate. Password change and recovery revoke
all account sessions. Recovery returns the replacement code once and does not
create a session. See [Gate account APIs](../../docs/ARCHITECTURE.md#6-gate-and-protocol-adapters).

User lookup/list and account status management require exact Gate bootstrap
operations `identity.v1.product.users.list` and
`identity.v1.product.users.status`, audience `identity/v1`, actor kind `bootstrap`,
and their broker RPC permissions. The browser user must also appear in signed
`AdminUsers`; workspace administrators cannot enumerate global accounts or
change account status. Status changes recheck that authority before replay.
Disabling revokes sessions, refresh families and outstanding issued invitations
in the same transaction; re-enabling does not restore them. Browser self-disable
is rejected. No new migration is required.

Task ACL root discovery additionally uses the exact Gate bootstrap operation
`identity.v1.product.task_roots.managed.list` (audience `identity/v1`, actor kind
`bootstrap`) and matching RPC broker permission. Core returns only roots with live
ACL management authority, without requiring or granting content read permission.
Readable root discovery keeps its existing operation and filter. Both responses
include `can_read`, `can_write` and `can_manage` flags; these are UI hints and
subsequent domain operations remain independently authorized. This Core/Gate
addition needs no migration or Task artifact replacement.

Readiness is reported after all module subscriptions and broker permissions have
been checked. SIGINT/SIGTERM unsubscribe Fabric control and module handlers,
stop the SDK transport and close the database. A failed start also closes owned
resources. Runtime management, node RPC and host effects remain disabled because
this command does not install a trusted live Runtime policy; see #13.

Run `make core-smoke` with the pinned native NATS server. It migrates externally,
launches the real binary, checks signed login and negative policy/auth cases,
restarts with stable trust and verifies SIGTERM plus in-process cancellation
release subscriptions/SQLite. See the [verification guide](../../docs/DEVELOPMENT.md#verification).
Complete platform provisioning, Runtime integration and full M7 coverage are
separate deliveries; command startup does not establish production readiness.

## Profile, preferences and workspace addresses

Apply Core migration `000013_profile_settings` before starting this version. It
preserves IDs/membership and initializes names from existing email local parts
and workspace slugs from existing UUIDs. New provisioning/invited-registration
requests may provide optional `name`. The self profile includes `name`,
`display_name`, `revision`, nullable `avatar_url` and live `is_sysadmin` in addition
to ID/email. Workspace member/group profiles include names and profile revision
without the installation-admin flag. Avatar upload is a separate asset feature;
this migration alone does not create avatar storage.

Allow these exact Gate bootstrap operations, audience `identity/v1`, actor kind
`bootstrap`, with their matching broker RPC subjects:

- `identity.v1.product.account.profile.update`: POST
  `/api/v1/arc/identity/account/profile/update`, input `name`, `display_name` and
  current profile `revision`; updates only the live caller's profile.
- `identity.v1.product.account.preferences.get`: GET
  `/api/v1/arc/identity/account/preferences/get`, returns caller-only settings and
  revision (0 before the first stored update).
- `identity.v1.product.account.preferences.update`: POST at the matching
  `/api/v1/arc/identity/account/preferences/update`, input `revision` and `changes`;
  partial merge into the existing settings with audit/replay/CAS.
- `identity.v1.product.workspaces.by_slug`: GET
  `/api/v1/arc/identity/workspaces/by_slug?slug=<slug>`, concealed membership-bound
  lookup, returning canonical UUID/root/role/revision.

Known preference keys match the reused UI: `font_size`, `pointer_cursors`,
`theme_mode`, `light_theme`, `dark_theme`, `workflow_sort_mode`,
`workflow_sort_order`, `team_workflow_sort_overrides`, `recent_due_dates` and
`issues_group_by`. Font sizes are small/default/large; modes system/light/dark;
grouping status/priority/assignee/project/none. Theme names and workflow modes are
enumerated, override maps are capped at 100 UUID-keyed entries, and recent due
dates at 20 YYYY-MM-DD strings. Workflow preference order uses the UI categories
backlog/unstarted/started/completed/cancelled; it is presentation data and does
not change Task workflow categories or permissions. Total stored data is capped
at 32 KiB. Unknown keys, malformed values and null patches are rejected.

Existing workspace create/update operations accept optional `slug`; update
retains the current slug when omitted. UUID/root authorization and CSRF/command
requirements are unchanged. Slug changes may invalidate bookmarks; no old-alias
redirect is created. No Task artifact replacement is needed for this Core change.
