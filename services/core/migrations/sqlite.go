// Package migrations owns the current core SQLite schema.
// Old upgrade chains are intentionally not replayed by this fresh baseline.
package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// SQLite is executed only by the separate owner migrator before traffic.
func SQLite() []*gormigrate.Migration {
	return []*gormigrate.Migration{{
		ID: "000001_core_baseline",
		Migrate: func(tx *gorm.DB) error {
			for _, sql := range baselineSchema {
				if err := tx.Exec(sql).Error; err != nil {
					return err
				}
			}
			return nil
		},
	}}
}

// Final table definitions, indexes, triggers and required static seed rows.
var baselineSchema = []string{
	`CREATE TABLE access_grants (id TEXT PRIMARY KEY, resource_id TEXT NOT NULL REFERENCES access_resources(id),
 principal_kind TEXT NOT NULL CHECK(principal_kind IN ('user','role','group','service','agent')),
 principal_id TEXT NOT NULL, action TEXT NOT NULL, expires_at DATETIME, revoked_at DATETIME,
 created_by TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
	`CREATE TABLE access_operations (
 actor TEXT NOT NULL, caller TEXT NOT NULL REFERENCES identity_service_accounts(id), operation TEXT NOT NULL,
 idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),
 request_hash BLOB NOT NULL CHECK(length(request_hash)=32), resource_id TEXT REFERENCES access_resources(id),
 state TEXT NOT NULL CHECK(state IN ('running','completed')), result BLOB,
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(actor,caller,operation,idempotency_key))`,
	`CREATE TABLE access_policy_audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL,
 caller TEXT NOT NULL REFERENCES identity_service_accounts(id), on_behalf_of TEXT REFERENCES identity_users(id),
 operation TEXT NOT NULL, resource_id TEXT REFERENCES access_resources(id),
 policy_revision INTEGER NOT NULL UNIQUE CHECK(policy_revision>0), change_kind TEXT NOT NULL,
 grant_id TEXT REFERENCES access_grants(id), change TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(change)),
 occurred_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
	`CREATE TABLE access_policy_state (singleton INTEGER PRIMARY KEY DEFAULT 1 CHECK(singleton=1), revision INTEGER NOT NULL DEFAULT 0 CHECK(revision>=0))`,
	`CREATE TABLE access_resource_types (
 type TEXT PRIMARY KEY, provider_service TEXT NOT NULL REFERENCES identity_service_accounts(id),
 contract_digest TEXT NOT NULL CHECK(length(contract_digest)=64 AND contract_digest NOT GLOB '*[^0-9a-f]*'),
 actions TEXT NOT NULL CHECK(json_valid(actions) AND json_type(actions)='array' AND json_array_length(actions)>0),
 share_action TEXT NOT NULL, create_action TEXT NOT NULL, delete_action TEXT NOT NULL, allow_inheritance INTEGER NOT NULL CHECK(allow_inheritance IN (0,1)),
 UNIQUE(type,provider_service))`,
	`CREATE TABLE access_resources (
 id TEXT PRIMARY KEY, type TEXT NOT NULL, provider_service TEXT NOT NULL,
 owner_kind TEXT NOT NULL CHECK(owner_kind IN ('user','workspace')), owner_id TEXT NOT NULL,
 owner_user_id TEXT REFERENCES identity_users(id), workspace_id TEXT REFERENCES identity_workspaces(id),
 acl_parent_id TEXT REFERENCES access_resources(id), inherit_acl INTEGER NOT NULL CHECK(inherit_acl IN (0,1)),
 state TEXT NOT NULL CHECK(state IN ('reserved','active','aborted','deleting','deleted')),
 policy_revision INTEGER NOT NULL CHECK(policy_revision>0),
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(type,provider_service) REFERENCES access_resource_types(type,provider_service),
 CHECK((owner_kind='user' AND owner_user_id IS NOT NULL AND owner_id=owner_user_id AND workspace_id IS NULL)
 OR (owner_kind='workspace' AND owner_user_id IS NULL AND workspace_id IS NOT NULL AND owner_id=workspace_id)),
 CHECK(acl_parent_id IS NULL OR acl_parent_id<>id))`,
	`CREATE TABLE core_schema_info (singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL DEFAULT 1 CHECK(schema_version>0))`,
	`CREATE TABLE fabric_command_results (
 actor TEXT NOT NULL, operation TEXT NOT NULL, idempotency_key TEXT NOT NULL,
 request_hash BLOB NOT NULL CHECK(length(request_hash)=32), result BLOB NOT NULL,
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(actor,operation,idempotency_key))`,
	`CREATE TABLE fabric_contracts (
 digest TEXT PRIMARY KEY CHECK(length(digest)=64 AND digest NOT GLOB '*[^0-9a-f]*'),
 service_name TEXT NOT NULL REFERENCES fabric_definitions(name),
 api_major INTEGER NOT NULL CHECK(api_major>0),
 artifact TEXT NOT NULL CHECK(json_valid(artifact)), installation TEXT NOT NULL CHECK(json_valid(installation)),
 signature BLOB NOT NULL CHECK(length(signature)=64),
 approved_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, revoked_at DATETIME,
 UNIQUE(service_name,api_major,digest))`,
	`CREATE TABLE fabric_definitions (name TEXT PRIMARY KEY, publisher TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
	`CREATE TABLE fabric_deployments (
 service_account_id TEXT NOT NULL REFERENCES identity_service_accounts(id),
 digest TEXT NOT NULL REFERENCES fabric_contracts(digest),
 subjects TEXT NOT NULL CHECK(json_valid(subjects) AND json_type(subjects)='array'),
 PRIMARY KEY(service_account_id,digest))`,
	`CREATE TABLE fabric_inbox (
 consumer TEXT NOT NULL, event_id TEXT NOT NULL, request_hash BLOB NOT NULL CHECK(length(request_hash)=32),
 received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(consumer,event_id))`,
	`CREATE TABLE fabric_instances (
 instance_id TEXT PRIMARY KEY, service_account_id TEXT NOT NULL REFERENCES identity_service_accounts(id),
 digest TEXT NOT NULL REFERENCES fabric_contracts(digest), build_version TEXT NOT NULL,
 ready INTEGER NOT NULL DEFAULT 0 CHECK(ready IN (0,1)), lease_until DATETIME NOT NULL,
 observed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
	`CREATE TABLE fabric_outbox (
 event_id TEXT PRIMARY KEY, subject TEXT NOT NULL, envelope TEXT NOT NULL CHECK(json_valid(envelope)),
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, published_at DATETIME)`,
	`CREATE TABLE fabric_route_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), revision INTEGER NOT NULL DEFAULT 0 CHECK(revision>=0))`,
	`CREATE TABLE identity_agent_identities (id TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL REFERENCES identity_users(id), workspace_id TEXT REFERENCES identity_workspaces(id), execution_scope TEXT NOT NULL, disabled_at DATETIME)`,
	`CREATE TABLE identity_assertion_nonces (namespace TEXT NOT NULL, nonce TEXT NOT NULL, expires_at DATETIME NOT NULL, PRIMARY KEY(namespace,nonce))`,
	`CREATE TABLE identity_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, actor TEXT NOT NULL, operation TEXT NOT NULL, target TEXT NOT NULL, outcome TEXT NOT NULL)`,
	`CREATE TABLE identity_command_results (actor TEXT NOT NULL, operation TEXT NOT NULL, idempotency_key TEXT NOT NULL, request_hash BLOB NOT NULL CHECK(length(request_hash)=32), result BLOB, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(actor,operation,idempotency_key))`,
	`CREATE TABLE identity_delegations (
 id TEXT PRIMARY KEY, grantor_user_id TEXT NOT NULL REFERENCES identity_users(id),
 grantee_kind TEXT NOT NULL CHECK(grantee_kind IN ('agent','service')), grantee_id TEXT NOT NULL,
 grantee_service_id TEXT REFERENCES identity_service_accounts(id), grantee_agent_id TEXT REFERENCES identity_agent_identities(id),
 resource_ids TEXT NOT NULL CHECK(json_valid(resource_ids) AND json_type(resource_ids)='array' AND json_array_length(resource_ids)>0),
 actions TEXT NOT NULL CHECK(json_valid(actions) AND json_type(actions)='array' AND json_array_length(actions)>0),
 expires_at DATETIME NOT NULL, revoked_at DATETIME,
 created_by TEXT NOT NULL REFERENCES identity_users(id), consent_method TEXT NOT NULL,
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CHECK(grantor_user_id<>grantee_id), CHECK(created_by=grantor_user_id),
 CHECK(expires_at>created_at), CHECK(consent_method='interactive_session'),
 CHECK((grantee_kind='service' AND grantee_service_id IS NOT NULL AND grantee_service_id=grantee_id AND grantee_agent_id IS NULL)
    OR (grantee_kind='agent' AND grantee_agent_id IS NOT NULL AND grantee_agent_id=grantee_id AND grantee_service_id IS NULL))
)`,
	`CREATE TABLE identity_group_members (workspace_id TEXT NOT NULL, group_id TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY(group_id,user_id), FOREIGN KEY(workspace_id,group_id) REFERENCES identity_groups(workspace_id,id), FOREIGN KEY(workspace_id,user_id) REFERENCES identity_memberships(workspace_id,user_id))`,
	`CREATE TABLE identity_groups (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES identity_workspaces(id), name TEXT NOT NULL, UNIQUE(workspace_id,name), UNIQUE(workspace_id,id))`,
	`CREATE TABLE identity_memberships (workspace_id TEXT NOT NULL REFERENCES identity_workspaces(id), user_id TEXT NOT NULL REFERENCES identity_users(id), role TEXT NOT NULL CHECK(role IN ('owner','admin','member','guest')), revoked_at DATETIME, PRIMARY KEY(workspace_id,user_id))`,
	`CREATE TABLE identity_password_credentials (user_id TEXT PRIMARY KEY REFERENCES identity_users(id), password_hash TEXT NOT NULL, recovery_hash BLOB UNIQUE, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
	`CREATE TABLE identity_rate_limits (bucket TEXT PRIMARY KEY, window_start DATETIME NOT NULL, attempts INTEGER NOT NULL CHECK(attempts>0))`,
	`CREATE TABLE identity_refresh_families (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES identity_sessions(id), expires_at DATETIME NOT NULL, revoked_at DATETIME)`,
	`CREATE TABLE identity_refresh_tokens (token_hash BLOB PRIMARY KEY, family_id TEXT NOT NULL REFERENCES identity_refresh_families(id), consumed_at DATETIME, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
	`CREATE TABLE identity_service_accounts (id TEXT PRIMARY KEY, service_definition TEXT NOT NULL, deployment TEXT NOT NULL, disabled_at DATETIME, UNIQUE(service_definition,deployment))`,
	`CREATE TABLE identity_service_credentials (kid TEXT PRIMARY KEY, service_account_id TEXT NOT NULL REFERENCES identity_service_accounts(id), public_key BLOB NOT NULL CHECK(length(public_key)=32), secret_reference TEXT NOT NULL, not_before DATETIME NOT NULL, expires_at DATETIME NOT NULL, revoked_at DATETIME, UNIQUE(service_account_id,kid), CHECK(expires_at>not_before))`,
	`CREATE TABLE identity_sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES identity_users(id), secret_hash BLOB NOT NULL UNIQUE, csrf_hash BLOB NOT NULL, expires_at DATETIME NOT NULL, revoked_at DATETIME, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, auth_channel TEXT NOT NULL CHECK(auth_channel IN ('browser','cli')))`,
	`CREATE TABLE identity_signing_key_metadata (kid TEXT PRIMARY KEY, public_key BLOB NOT NULL CHECK(length(public_key)=32), not_before DATETIME NOT NULL, expires_at DATETIME NOT NULL, revoked_at DATETIME, CHECK(expires_at>not_before))`,
	`CREATE TABLE identity_user_preferences(user_id TEXT PRIMARY KEY REFERENCES identity_users(id),data TEXT NOT NULL CHECK(json_valid(data)),revision INTEGER NOT NULL CHECK(revision>0),updated_at DATETIME NOT NULL)`,
	`CREATE TABLE identity_users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE CHECK(email=lower(email)), status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')), created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, name TEXT NOT NULL DEFAULT '', display_name TEXT NOT NULL DEFAULT '', profile_revision INTEGER NOT NULL DEFAULT 1 CHECK(profile_revision>0), avatar_ref TEXT CHECK(avatar_ref IS NULL OR json_valid(avatar_ref)))`,
	`CREATE TABLE identity_workspace_invitations (
			id TEXT PRIMARY KEY,
			workspace_id TEXT NOT NULL REFERENCES identity_workspaces(id),
			issuer_id TEXT NOT NULL REFERENCES identity_users(id),
			email TEXT NOT NULL CHECK(email=lower(email)),
			role TEXT NOT NULL CHECK(role IN ('member','guest')),
			token_hash BLOB NOT NULL UNIQUE CHECK(length(token_hash)=32),
			expires_at DATETIME NOT NULL,
			consumed_at DATETIME,
			revoked_at DATETIME
		)`,
	`CREATE TABLE identity_workspaces (id TEXT PRIMARY KEY, name TEXT NOT NULL CHECK(length(name)>0), revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0), acl_root_id TEXT REFERENCES access_resources(id)
			 CHECK(acl_root_id IS NULL OR acl_root_id=id), archived_at DATETIME, slug TEXT)`,
	`CREATE TABLE runtime_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL,
    target_id TEXT NOT NULL, operation_id TEXT, occurred_at DATETIME NOT NULL)`,
	`CREATE TABLE runtime_enrollment_offers (
				id TEXT PRIMARY KEY,
				node_id TEXT NOT NULL,
				service_account_id TEXT NOT NULL REFERENCES identity_service_accounts(id),
				kid TEXT NOT NULL,
				public_key BLOB NOT NULL CHECK(length(public_key)=32),
				capabilities TEXT NOT NULL CHECK(json_valid(capabilities) AND json_type(capabilities)='array'),
				token_hash TEXT NOT NULL UNIQUE CHECK(length(token_hash)=64 AND token_hash NOT GLOB '*[^0-9a-f]*'),
				approved_by TEXT NOT NULL,
				created_at DATETIME NOT NULL,
				expires_at DATETIME NOT NULL,
				redeemed_at DATETIME,
				revoked_at DATETIME,
				CHECK(expires_at>created_at),
				CHECK(redeemed_at IS NULL OR revoked_at IS NULL))`,
	`CREATE TABLE runtime_node_profiles (
				node_id TEXT NOT NULL REFERENCES runtime_nodes(id),
				id TEXT NOT NULL,
				revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
				spec TEXT NOT NULL CHECK(json_valid(spec) AND json_type(spec)='object'),
				digest TEXT NOT NULL CHECK(length(digest)=64 AND digest NOT GLOB '*[^0-9a-f]*'),
				revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
				approved_by TEXT NOT NULL,
				created_at DATETIME NOT NULL,
				PRIMARY KEY(node_id,id,revision),
				CHECK(json_extract(spec,'$.id') IS id AND json_extract(spec,'$.revision') IS revision))`,
	`CREATE TABLE runtime_nodes (
    id TEXT PRIMARY KEY, service_account_id TEXT NOT NULL UNIQUE REFERENCES identity_service_accounts(id),
    capabilities TEXT NOT NULL CHECK(json_valid(capabilities) AND json_type(capabilities)='array'),
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)), last_seen_at DATETIME,
    created_at DATETIME NOT NULL, host_inventory TEXT
			CHECK(host_inventory IS NULL OR (json_valid(host_inventory) AND json_type(host_inventory)='object')))`,
	`CREATE TABLE runtime_observations (
    resource_id TEXT PRIMARY KEY REFERENCES runtime_resources(id),
    node_id TEXT NOT NULL REFERENCES runtime_nodes(id), operation_id TEXT NOT NULL REFERENCES runtime_operations(id),
    revision INTEGER NOT NULL, payload TEXT NOT NULL CHECK(json_valid(payload)), received_at DATETIME NOT NULL)`,
	`CREATE TABLE runtime_operations (
    id TEXT PRIMARY KEY, resource_id TEXT NOT NULL REFERENCES runtime_resources(id),
    requested_revision INTEGER NOT NULL CHECK(requested_revision BETWEEN 1 AND 9007199254740991),
    actor TEXT NOT NULL, idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),
    request_hash TEXT NOT NULL CHECK(length(request_hash)=64),
    status TEXT NOT NULL CHECK(status IN ('pending','running','succeeded','failed','cancelled')),
    error_code TEXT NOT NULL DEFAULT '', result TEXT NOT NULL CHECK(json_valid(result)),
    created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL,
    UNIQUE(actor,idempotency_key), UNIQUE(resource_id,requested_revision))`,
	`CREATE TABLE runtime_outbox (
    event_id TEXT PRIMARY KEY REFERENCES runtime_operations(id), subject TEXT NOT NULL,
    payload TEXT NOT NULL CHECK(json_valid(payload)), created_at DATETIME NOT NULL, published_at DATETIME)`,
	`CREATE TABLE runtime_reports (
    node_id TEXT NOT NULL REFERENCES runtime_nodes(id), event_id TEXT NOT NULL,
    operation_id TEXT NOT NULL REFERENCES runtime_operations(id), digest TEXT NOT NULL CHECK(length(digest)=64),
    payload TEXT NOT NULL CHECK(json_valid(payload)), received_at DATETIME NOT NULL,
    PRIMARY KEY(node_id,event_id))`,
	`CREATE TABLE runtime_resources (
    id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES runtime_nodes(id),
    template_id TEXT NOT NULL, template_revision INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('docker.container','lxd.instance','systemd.service')),
    revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
    state TEXT NOT NULL CHECK(state IN ('running','stopped','deleted')),
    replicas INTEGER NOT NULL CHECK(replicas BETWEEN 0 AND 100),
    spec TEXT NOT NULL CHECK(json_valid(spec) AND json_type(spec)='object'),
    operation_id TEXT NOT NULL REFERENCES runtime_operations(id) DEFERRABLE INITIALLY DEFERRED,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY(node_id,template_id,template_revision) REFERENCES runtime_templates(node_id,id,revision),
    CHECK(json_extract(spec,'$.id') IS id AND json_extract(spec,'$.node_id') IS node_id
     AND json_extract(spec,'$.revision') IS revision AND json_extract(spec,'$.kind') IS kind
     AND json_extract(spec,'$.template_id') IS template_id AND json_extract(spec,'$.template_revision') IS template_revision
     AND json_extract(spec,'$.state') IS state AND json_extract(spec,'$.replicas') IS replicas),
    CHECK((state='running' AND replicas>0) OR (state IN ('stopped','deleted') AND replicas=0)))`,
	`CREATE TABLE runtime_revisions (
    resource_id TEXT NOT NULL REFERENCES runtime_resources(id), revision INTEGER NOT NULL,
    spec TEXT NOT NULL CHECK(json_valid(spec)), digest TEXT NOT NULL CHECK(length(digest)=64),
    operation_id TEXT NOT NULL UNIQUE REFERENCES runtime_operations(id), created_at DATETIME NOT NULL,
    PRIMARY KEY(resource_id,revision))`,
	`CREATE TABLE runtime_templates (
    node_id TEXT NOT NULL REFERENCES runtime_nodes(id), id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
    spec TEXT NOT NULL CHECK(json_valid(spec) AND json_type(spec)='object'),
    revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)), created_at DATETIME NOT NULL,
    PRIMARY KEY(node_id,id,revision))`,
	`CREATE INDEX access_grants_active ON access_grants(resource_id,action) WHERE revoked_at IS NULL`,
	`CREATE INDEX access_policy_audit_resource_revision ON access_policy_audit(resource_id,policy_revision)`,
	`CREATE INDEX access_resources_owner_active ON access_resources(owner_kind,owner_id,id) WHERE state='active'`,
	`CREATE INDEX access_resources_parent ON access_resources(acl_parent_id)`,
	`CREATE INDEX access_resources_workspace_active ON access_resources(workspace_id,id) WHERE state='active'`,
	`CREATE UNIQUE INDEX fabric_active_service_major ON fabric_contracts(service_name,api_major) WHERE revoked_at IS NULL`,
	`CREATE INDEX identity_assertion_nonces_expiry ON identity_assertion_nonces(expires_at)`,
	`CREATE INDEX identity_audit_time ON identity_audit(occurred_at)`,
	`CREATE INDEX identity_command_results_time ON identity_command_results(created_at)`,
	`CREATE INDEX identity_delegations_active_grantee ON identity_delegations(grantee_kind,grantee_id) WHERE revoked_at IS NULL`,
	`CREATE INDEX identity_memberships_active_user ON identity_memberships(user_id) WHERE revoked_at IS NULL`,
	`CREATE INDEX identity_refresh_tokens_family ON identity_refresh_tokens(family_id)`,
	`CREATE INDEX identity_sessions_active_user ON identity_sessions(user_id) WHERE revoked_at IS NULL`,
	`CREATE UNIQUE INDEX identity_workspace_slug ON identity_workspaces(COALESCE(slug,id))`,
	`CREATE INDEX runtime_enrollment_pending
				ON runtime_enrollment_offers(node_id,service_account_id,expires_at)`,
	`CREATE INDEX runtime_node_profiles_latest ON runtime_node_profiles(node_id,id,revision DESC)`,
	`CREATE INDEX runtime_resources_node ON runtime_resources(node_id,id)`,
	`CREATE TRIGGER access_policy_audit_immutable_delete BEFORE DELETE ON access_policy_audit BEGIN SELECT RAISE(ABORT,'policy audit append-only'); END`,
	`CREATE TRIGGER access_policy_audit_immutable_update BEFORE UPDATE ON access_policy_audit BEGIN SELECT RAISE(ABORT,'policy audit append-only'); END`,
	`CREATE TRIGGER access_resource_types_actions_insert BEFORE INSERT ON access_resource_types BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM json_each(NEW.actions) WHERE value=NEW.share_action)
 OR NOT EXISTS(SELECT 1 FROM json_each(NEW.actions) WHERE value=NEW.create_action)
 OR NOT EXISTS(SELECT 1 FROM json_each(NEW.actions) WHERE value=NEW.delete_action)
 OR NOT EXISTS(SELECT 1 FROM json_each(NEW.actions) WHERE value='access.grants.manage')
 THEN RAISE(ABORT,'resource actions invariant') END;
 END`,
	`CREATE TRIGGER access_resource_types_actions_update BEFORE UPDATE ON access_resource_types BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM json_each(NEW.actions) WHERE value=NEW.share_action)
 OR NOT EXISTS(SELECT 1 FROM json_each(NEW.actions) WHERE value=NEW.create_action)
 OR NOT EXISTS(SELECT 1 FROM json_each(NEW.actions) WHERE value=NEW.delete_action)
 OR NOT EXISTS(SELECT 1 FROM json_each(NEW.actions) WHERE value='access.grants.manage')
 THEN RAISE(ABORT,'resource actions invariant') END;
 END`,
	`CREATE TRIGGER access_resources_parent_insert BEFORE INSERT ON access_resources WHEN NEW.acl_parent_id IS NOT NULL BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM access_resources p
 WHERE p.id=NEW.acl_parent_id AND p.owner_kind=NEW.owner_kind AND p.owner_id=NEW.owner_id
 AND p.workspace_id IS NEW.workspace_id AND p.state='active')
 THEN RAISE(ABORT,'invalid ACL parent scope or state') END;
 SELECT CASE WHEN EXISTS(
 WITH RECURSIVE ancestry(id,parent_id,depth) AS (
  SELECT id,acl_parent_id,1 FROM access_resources WHERE id=NEW.acl_parent_id
  UNION ALL SELECT p.id,p.acl_parent_id,a.depth+1 FROM access_resources p JOIN ancestry a ON p.id=a.parent_id WHERE a.depth<65
 ) SELECT 1 FROM ancestry WHERE id=NEW.id OR depth>=64
 ) THEN RAISE(ABORT,'ACL cycle or depth exceeds 64') END;
 END`,
	`CREATE TRIGGER access_resources_parent_update BEFORE UPDATE ON access_resources BEGIN
 SELECT CASE WHEN NEW.type IS NOT OLD.type OR NEW.provider_service IS NOT OLD.provider_service
 OR NEW.owner_kind IS NOT OLD.owner_kind OR NEW.owner_id IS NOT OLD.owner_id
 OR NEW.workspace_id IS NOT OLD.workspace_id OR NEW.owner_user_id IS NOT OLD.owner_user_id
 OR NEW.acl_parent_id IS NOT OLD.acl_parent_id OR NEW.inherit_acl IS NOT OLD.inherit_acl
 THEN RAISE(ABORT,'resource scope immutable') END;
 SELECT CASE WHEN NEW.state<>OLD.state AND NOT (
 (OLD.state='reserved' AND NEW.state IN ('active','aborted')) OR
 (OLD.state='active' AND NEW.state='deleting') OR
 (OLD.state='deleting' AND NEW.state='deleted'))
 THEN RAISE(ABORT,'invalid resource transition') END;
 END`,
	`CREATE TRIGGER fabric_contracts_immutable BEFORE UPDATE ON fabric_contracts BEGIN
 SELECT CASE WHEN NEW.digest IS NOT OLD.digest OR NEW.service_name IS NOT OLD.service_name
 OR NEW.api_major IS NOT OLD.api_major OR NEW.artifact IS NOT OLD.artifact
 OR NEW.installation IS NOT OLD.installation OR NEW.signature IS NOT OLD.signature
 OR NEW.approved_at IS NOT OLD.approved_at
 THEN RAISE(ABORT,'immutable service contract') END;
 SELECT CASE WHEN OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at
 THEN RAISE(ABORT,'contract cannot be reactivated') END;
 END`,
	`CREATE TRIGGER fabric_contracts_no_delete BEFORE DELETE ON fabric_contracts BEGIN SELECT RAISE(ABORT,'contract deletion forbidden'); END`,
	`CREATE TRIGGER fabric_definitions_no_delete BEFORE DELETE ON fabric_definitions BEGIN SELECT RAISE(ABORT,'definition deletion forbidden'); END`,
	`CREATE TRIGGER fabric_deployments_no_delete BEFORE DELETE ON fabric_deployments BEGIN SELECT RAISE(ABORT,'deployment deletion forbidden'); END`,
	`CREATE TRIGGER runtime_audit_no_delete BEFORE DELETE ON runtime_audit BEGIN SELECT RAISE(ABORT,'runtime history retained'); END`,
	`CREATE TRIGGER runtime_audit_no_update BEFORE UPDATE ON runtime_audit BEGIN SELECT RAISE(ABORT,'runtime history immutable'); END`,
	`CREATE TRIGGER runtime_enrollment_immutable BEFORE UPDATE ON runtime_enrollment_offers BEGIN
				SELECT CASE WHEN NEW.id IS NOT OLD.id OR NEW.node_id IS NOT OLD.node_id
					OR NEW.service_account_id IS NOT OLD.service_account_id OR NEW.kid IS NOT OLD.kid
					OR NEW.public_key IS NOT OLD.public_key OR NEW.capabilities IS NOT OLD.capabilities
					OR NEW.token_hash IS NOT OLD.token_hash OR NEW.approved_by IS NOT OLD.approved_by
					OR NEW.created_at IS NOT OLD.created_at OR NEW.expires_at IS NOT OLD.expires_at
					OR OLD.redeemed_at IS NOT NULL OR OLD.revoked_at IS NOT NULL
					OR (NEW.redeemed_at IS NULL AND NEW.revoked_at IS NULL)
					OR (NEW.redeemed_at IS NOT NULL AND NEW.revoked_at IS NOT NULL)
				THEN RAISE(ABORT,'immutable runtime enrollment offer') END; END`,
	`CREATE TRIGGER runtime_enrollment_no_delete BEFORE DELETE ON runtime_enrollment_offers BEGIN
				SELECT RAISE(ABORT,'runtime enrollment history retained'); END`,
	`CREATE TRIGGER runtime_node_immutable BEFORE UPDATE ON runtime_nodes BEGIN
    SELECT CASE WHEN NEW.id IS NOT OLD.id OR NEW.service_account_id IS NOT OLD.service_account_id
     OR NEW.capabilities IS NOT OLD.capabilities OR NEW.created_at IS NOT OLD.created_at
     OR (OLD.active=0 AND NEW.active<>0) THEN RAISE(ABORT,'immutable runtime node binding') END; END`,
	`CREATE TRIGGER runtime_node_profiles_immutable BEFORE UPDATE ON runtime_node_profiles BEGIN
			   SELECT CASE WHEN NEW.node_id IS NOT OLD.node_id OR NEW.id IS NOT OLD.id
				OR NEW.revision IS NOT OLD.revision OR NEW.spec IS NOT OLD.spec
				OR NEW.digest IS NOT OLD.digest OR NEW.approved_by IS NOT OLD.approved_by
				OR NEW.created_at IS NOT OLD.created_at OR OLD.revoked=1
				OR NEW.revoked IS NOT 1
			   THEN RAISE(ABORT,'immutable runtime node profile') END; END`,
	`CREATE TRIGGER runtime_node_profiles_no_delete BEFORE DELETE ON runtime_node_profiles BEGIN
			   SELECT RAISE(ABORT,'node profile deletion forbidden'); END`,
	`CREATE TRIGGER runtime_nodes_no_delete BEFORE DELETE ON runtime_nodes BEGIN SELECT RAISE(ABORT,'runtime history retained'); END`,
	`CREATE TRIGGER runtime_operation_immutable BEFORE UPDATE ON runtime_operations BEGIN
    SELECT CASE WHEN NEW.id IS NOT OLD.id OR NEW.resource_id IS NOT OLD.resource_id
     OR NEW.requested_revision IS NOT OLD.requested_revision OR NEW.actor IS NOT OLD.actor
     OR NEW.idempotency_key IS NOT OLD.idempotency_key OR NEW.request_hash IS NOT OLD.request_hash
     OR NEW.result IS NOT OLD.result OR NEW.created_at IS NOT OLD.created_at
     THEN RAISE(ABORT,'immutable runtime operation') END;
    SELECT CASE WHEN NEW.status<>OLD.status AND NOT
     (OLD.status IN ('pending','running') AND NEW.status IN ('running','succeeded','failed','cancelled'))
     THEN RAISE(ABORT,'invalid runtime operation transition') END; END`,
	`CREATE TRIGGER runtime_operations_no_delete BEFORE DELETE ON runtime_operations BEGIN SELECT RAISE(ABORT,'runtime history retained'); END`,
	`CREATE TRIGGER runtime_outbox_immutable BEFORE UPDATE ON runtime_outbox BEGIN
 SELECT CASE WHEN NEW.event_id IS NOT OLD.event_id OR NEW.subject IS NOT OLD.subject
 OR NEW.payload IS NOT OLD.payload OR NEW.created_at IS NOT OLD.created_at
 OR (OLD.published_at IS NOT NULL AND NEW.published_at IS NOT OLD.published_at)
 THEN RAISE(ABORT,'immutable runtime hint') END; END`,
	`CREATE TRIGGER runtime_outbox_no_delete BEFORE DELETE ON runtime_outbox BEGIN SELECT RAISE(ABORT,'runtime history retained'); END`,
	`CREATE TRIGGER runtime_reports_no_delete BEFORE DELETE ON runtime_reports BEGIN SELECT RAISE(ABORT,'runtime history retained'); END`,
	`CREATE TRIGGER runtime_reports_no_update BEFORE UPDATE ON runtime_reports BEGIN SELECT RAISE(ABORT,'runtime history immutable'); END`,
	`CREATE TRIGGER runtime_resource_revision BEFORE UPDATE ON runtime_resources BEGIN
    SELECT CASE WHEN NEW.id IS NOT OLD.id OR NEW.node_id IS NOT OLD.node_id OR NEW.kind IS NOT OLD.kind
     OR NEW.revision<>OLD.revision+1 OR OLD.state='deleted'
     THEN RAISE(ABORT,'invalid runtime resource revision') END; END`,
	`CREATE TRIGGER runtime_resources_no_delete BEFORE DELETE ON runtime_resources BEGIN SELECT RAISE(ABORT,'runtime history retained'); END`,
	`CREATE TRIGGER runtime_revisions_no_delete BEFORE DELETE ON runtime_revisions BEGIN SELECT RAISE(ABORT,'runtime history retained'); END`,
	`CREATE TRIGGER runtime_revisions_no_update BEFORE UPDATE ON runtime_revisions BEGIN SELECT RAISE(ABORT,'runtime history immutable'); END`,
	`CREATE TRIGGER runtime_template_immutable BEFORE UPDATE ON runtime_templates BEGIN
    SELECT CASE WHEN NEW.node_id IS NOT OLD.node_id OR NEW.id IS NOT OLD.id OR NEW.revision IS NOT OLD.revision
     OR NEW.spec IS NOT OLD.spec OR NEW.created_at IS NOT OLD.created_at OR (OLD.revoked=1 AND NEW.revoked<>1)
     THEN RAISE(ABORT,'immutable runtime template') END; END`,
	`CREATE TRIGGER runtime_templates_no_delete BEFORE DELETE ON runtime_templates BEGIN SELECT RAISE(ABORT,'runtime history retained'); END`,
	`INSERT INTO "access_policy_state"("singleton","revision") VALUES(1,0)`,
	`INSERT INTO "identity_service_accounts"("id","service_definition","deployment","disabled_at") VALUES('00000000-0000-4000-8000-00000000a001','arc-core','workspace-registry',CURRENT_TIMESTAMP)`,
	`INSERT INTO "access_resource_types"("type","provider_service","contract_digest","actions","share_action","create_action","delete_action","allow_inheritance") VALUES('arc.workspace','00000000-0000-4000-8000-00000000a001','0000000000000000000000000000000000000000000000000000000000000000','["arc.workspace.manage","access.grants.manage"]','arc.workspace.manage','arc.workspace.manage','arc.workspace.manage',0)`,
	`INSERT INTO "core_schema_info"("singleton","schema_version") VALUES(1,1)`,
	`INSERT INTO "fabric_route_state"("singleton","revision") VALUES(1,0)`,
}
