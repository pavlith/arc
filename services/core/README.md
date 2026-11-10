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
