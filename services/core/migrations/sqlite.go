// Package migrations owns Core's complete file-backed SQLite schema.
// This package is independent from the legacy PostgreSQL SQL migrations.
// Migrations must be run by the Core owner migrator before Core starts.
package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// SQLite returns explicitly ordered, atomic migrations for Core's four modules.
// Tables use module prefixes: SQLite has no PostgreSQL schemas or SQL roles.
func SQLite() []*gormigrate.Migration {
	return []*gormigrate.Migration{
		{ID: "000001_bootstrap", Migrate: func(tx *gorm.DB) error {
			for _, query := range []string{
				"CREATE TABLE core_schema_info (singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL DEFAULT 1 CHECK(schema_version>0))",
				"INSERT INTO core_schema_info(singleton,schema_version) VALUES(1,1)",
			} {
				if err := tx.Exec(query).Error; err != nil {
					return err
				}
			}
			return nil
		}},
		{ID: "000002_identity", Migrate: func(tx *gorm.DB) error {
			for _, query := range []string{
				"CREATE TABLE identity_users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE CHECK(email=lower(email)), status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')), created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)",
				"CREATE TABLE identity_password_credentials (user_id TEXT PRIMARY KEY REFERENCES identity_users(id), password_hash TEXT NOT NULL, recovery_hash BLOB UNIQUE, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)",
				"CREATE TABLE identity_sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES identity_users(id), secret_hash BLOB NOT NULL UNIQUE, csrf_hash BLOB NOT NULL, expires_at DATETIME NOT NULL, revoked_at DATETIME, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)",
				"CREATE INDEX identity_sessions_active_user ON identity_sessions(user_id) WHERE revoked_at IS NULL",
				"CREATE TABLE identity_refresh_families (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES identity_sessions(id), expires_at DATETIME NOT NULL, revoked_at DATETIME)",
				"CREATE TABLE identity_refresh_tokens (token_hash BLOB PRIMARY KEY, family_id TEXT NOT NULL REFERENCES identity_refresh_families(id), consumed_at DATETIME, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)",
				"CREATE INDEX identity_refresh_tokens_family ON identity_refresh_tokens(family_id)",
				"CREATE TABLE identity_workspaces (id TEXT PRIMARY KEY, name TEXT NOT NULL CHECK(length(name)>0), revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0))",
				"CREATE TABLE identity_memberships (workspace_id TEXT NOT NULL REFERENCES identity_workspaces(id), user_id TEXT NOT NULL REFERENCES identity_users(id), role TEXT NOT NULL CHECK(role IN ('owner','admin','member','guest')), revoked_at DATETIME, PRIMARY KEY(workspace_id,user_id))",
				"CREATE INDEX identity_memberships_active_user ON identity_memberships(user_id) WHERE revoked_at IS NULL",
				"CREATE TABLE identity_groups (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES identity_workspaces(id), name TEXT NOT NULL, UNIQUE(workspace_id,name), UNIQUE(workspace_id,id))",
				"CREATE TABLE identity_group_members (workspace_id TEXT NOT NULL, group_id TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY(group_id,user_id), FOREIGN KEY(workspace_id,group_id) REFERENCES identity_groups(workspace_id,id), FOREIGN KEY(workspace_id,user_id) REFERENCES identity_memberships(workspace_id,user_id))",
				"CREATE TABLE identity_service_accounts (id TEXT PRIMARY KEY, service_definition TEXT NOT NULL, deployment TEXT NOT NULL, disabled_at DATETIME, UNIQUE(service_definition,deployment))",
				"CREATE TABLE identity_service_credentials (kid TEXT PRIMARY KEY, service_account_id TEXT NOT NULL REFERENCES identity_service_accounts(id), public_key BLOB NOT NULL CHECK(length(public_key)=32), secret_reference TEXT NOT NULL, not_before DATETIME NOT NULL, expires_at DATETIME NOT NULL, revoked_at DATETIME, UNIQUE(service_account_id,kid), CHECK(expires_at>not_before))",
				"CREATE TABLE identity_agent_identities (id TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL REFERENCES identity_users(id), workspace_id TEXT REFERENCES identity_workspaces(id), execution_scope TEXT NOT NULL, disabled_at DATETIME)",
				"CREATE TABLE identity_delegations (\n id TEXT PRIMARY KEY, grantor_user_id TEXT NOT NULL REFERENCES identity_users(id),\n grantee_kind TEXT NOT NULL CHECK(grantee_kind IN ('agent','service')), grantee_id TEXT NOT NULL,\n grantee_service_id TEXT REFERENCES identity_service_accounts(id), grantee_agent_id TEXT REFERENCES identity_agent_identities(id),\n resource_ids TEXT NOT NULL CHECK(json_valid(resource_ids) AND json_type(resource_ids)='array' AND json_array_length(resource_ids)>0),\n actions TEXT NOT NULL CHECK(json_valid(actions) AND json_type(actions)='array' AND json_array_length(actions)>0),\n expires_at DATETIME NOT NULL, revoked_at DATETIME,\n created_by TEXT NOT NULL REFERENCES identity_users(id), consent_method TEXT NOT NULL,\n created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,\n CHECK(grantor_user_id<>grantee_id), CHECK(created_by=grantor_user_id),\n CHECK(expires_at>created_at), CHECK(consent_method='interactive_session'),\n CHECK((grantee_kind='service' AND grantee_service_id IS NOT NULL AND grantee_service_id=grantee_id AND grantee_agent_id IS NULL)\n    OR (grantee_kind='agent' AND grantee_agent_id IS NOT NULL AND grantee_agent_id=grantee_id AND grantee_service_id IS NULL))\n)",
				"CREATE INDEX identity_delegations_active_grantee ON identity_delegations(grantee_kind,grantee_id) WHERE revoked_at IS NULL",
				"CREATE TABLE identity_signing_key_metadata (kid TEXT PRIMARY KEY, public_key BLOB NOT NULL CHECK(length(public_key)=32), not_before DATETIME NOT NULL, expires_at DATETIME NOT NULL, revoked_at DATETIME, CHECK(expires_at>not_before))",
				"CREATE TABLE identity_assertion_nonces (namespace TEXT NOT NULL, nonce TEXT NOT NULL, expires_at DATETIME NOT NULL, PRIMARY KEY(namespace,nonce))",
				"CREATE INDEX identity_assertion_nonces_expiry ON identity_assertion_nonces(expires_at)",
				"CREATE TABLE identity_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, actor TEXT NOT NULL, operation TEXT NOT NULL, target TEXT NOT NULL, outcome TEXT NOT NULL)",
				"CREATE INDEX identity_audit_time ON identity_audit(occurred_at)",
				"CREATE TABLE identity_rate_limits (bucket TEXT PRIMARY KEY, window_start DATETIME NOT NULL, attempts INTEGER NOT NULL CHECK(attempts>0))",
				"CREATE TABLE identity_command_results (actor TEXT NOT NULL, operation TEXT NOT NULL, idempotency_key TEXT NOT NULL, request_hash BLOB NOT NULL CHECK(length(request_hash)=32), result BLOB, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(actor,operation,idempotency_key))",
				"CREATE INDEX identity_command_results_time ON identity_command_results(created_at)",
			} {
				if err := tx.Exec(query).Error; err != nil {
					return err
				}
			}
			return nil
		}},
		{ID: "000003_access", Migrate: func(tx *gorm.DB) error {
			for _, query := range []string{
				"CREATE TABLE access_policy_state (singleton INTEGER PRIMARY KEY DEFAULT 1 CHECK(singleton=1), revision INTEGER NOT NULL DEFAULT 0 CHECK(revision>=0))",
				"INSERT INTO access_policy_state(singleton) VALUES(1)",
				"CREATE TABLE access_resource_types (\n type TEXT PRIMARY KEY, provider_service TEXT NOT NULL REFERENCES identity_service_accounts(id),\n contract_digest TEXT NOT NULL CHECK(length(contract_digest)=64 AND contract_digest NOT GLOB '*[^0-9a-f]*'),\n actions TEXT NOT NULL CHECK(json_valid(actions) AND json_type(actions)='array' AND json_array_length(actions)>0),\n share_action TEXT NOT NULL, create_action TEXT NOT NULL, delete_action TEXT NOT NULL, allow_inheritance INTEGER NOT NULL CHECK(allow_inheritance IN (0,1)),\n UNIQUE(type,provider_service))",
				"CREATE TRIGGER access_resource_types_actions_insert BEFORE INSERT ON access_resource_types BEGIN\n SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM json_each(NEW.actions) WHERE value=NEW.share_action)\n OR NOT EXISTS(SELECT 1 FROM json_each(NEW.actions) WHERE value=NEW.create_action)\n OR NOT EXISTS(SELECT 1 FROM json_each(NEW.actions) WHERE value=NEW.delete_action)\n OR NOT EXISTS(SELECT 1 FROM json_each(NEW.actions) WHERE value='access.grants.manage')\n THEN RAISE(ABORT,'resource actions invariant') END;\n END",
				"CREATE TRIGGER access_resource_types_actions_update BEFORE UPDATE ON access_resource_types BEGIN\n SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM json_each(NEW.actions) WHERE value=NEW.share_action)\n OR NOT EXISTS(SELECT 1 FROM json_each(NEW.actions) WHERE value=NEW.create_action)\n OR NOT EXISTS(SELECT 1 FROM json_each(NEW.actions) WHERE value=NEW.delete_action)\n OR NOT EXISTS(SELECT 1 FROM json_each(NEW.actions) WHERE value='access.grants.manage')\n THEN RAISE(ABORT,'resource actions invariant') END;\n END",
				"CREATE TABLE access_resources (\n id TEXT PRIMARY KEY, type TEXT NOT NULL, provider_service TEXT NOT NULL,\n owner_kind TEXT NOT NULL CHECK(owner_kind IN ('user','workspace')), owner_id TEXT NOT NULL,\n owner_user_id TEXT REFERENCES identity_users(id), workspace_id TEXT REFERENCES identity_workspaces(id),\n acl_parent_id TEXT REFERENCES access_resources(id), inherit_acl INTEGER NOT NULL CHECK(inherit_acl IN (0,1)),\n state TEXT NOT NULL CHECK(state IN ('reserved','active','aborted','deleting','deleted')),\n policy_revision INTEGER NOT NULL CHECK(policy_revision>0),\n created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,\n FOREIGN KEY(type,provider_service) REFERENCES access_resource_types(type,provider_service),\n CHECK((owner_kind='user' AND owner_user_id IS NOT NULL AND owner_id=owner_user_id AND workspace_id IS NULL)\n OR (owner_kind='workspace' AND owner_user_id IS NULL AND workspace_id IS NOT NULL AND owner_id=workspace_id)),\n CHECK(acl_parent_id IS NULL OR acl_parent_id<>id))",
				"CREATE INDEX access_resources_parent ON access_resources(acl_parent_id)",
				"CREATE INDEX access_resources_workspace_active ON access_resources(workspace_id,id) WHERE state='active'",
				"CREATE INDEX access_resources_owner_active ON access_resources(owner_kind,owner_id,id) WHERE state='active'",
				"CREATE TRIGGER access_resources_parent_insert BEFORE INSERT ON access_resources WHEN NEW.acl_parent_id IS NOT NULL BEGIN\n SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM access_resources p\n WHERE p.id=NEW.acl_parent_id AND p.owner_kind=NEW.owner_kind AND p.owner_id=NEW.owner_id\n AND p.workspace_id IS NEW.workspace_id AND p.state='active')\n THEN RAISE(ABORT,'invalid ACL parent scope or state') END;\n SELECT CASE WHEN EXISTS(\n WITH RECURSIVE ancestry(id,parent_id,depth) AS (\n  SELECT id,acl_parent_id,1 FROM access_resources WHERE id=NEW.acl_parent_id\n  UNION ALL SELECT p.id,p.acl_parent_id,a.depth+1 FROM access_resources p JOIN ancestry a ON p.id=a.parent_id WHERE a.depth<65\n ) SELECT 1 FROM ancestry WHERE id=NEW.id OR depth>=64\n ) THEN RAISE(ABORT,'ACL cycle or depth exceeds 64') END;\n END",
				"CREATE TRIGGER access_resources_parent_update BEFORE UPDATE ON access_resources BEGIN\n SELECT CASE WHEN NEW.type IS NOT OLD.type OR NEW.provider_service IS NOT OLD.provider_service\n OR NEW.owner_kind IS NOT OLD.owner_kind OR NEW.owner_id IS NOT OLD.owner_id\n OR NEW.workspace_id IS NOT OLD.workspace_id OR NEW.owner_user_id IS NOT OLD.owner_user_id\n OR NEW.acl_parent_id IS NOT OLD.acl_parent_id OR NEW.inherit_acl IS NOT OLD.inherit_acl\n THEN RAISE(ABORT,'resource scope immutable') END;\n SELECT CASE WHEN NEW.state<>OLD.state AND NOT (\n (OLD.state='reserved' AND NEW.state IN ('active','aborted')) OR\n (OLD.state='active' AND NEW.state='deleting') OR\n (OLD.state='deleting' AND NEW.state='deleted'))\n THEN RAISE(ABORT,'invalid resource transition') END;\n END",
				"CREATE TABLE access_grants (id TEXT PRIMARY KEY, resource_id TEXT NOT NULL REFERENCES access_resources(id),\n principal_kind TEXT NOT NULL CHECK(principal_kind IN ('user','role','group','service','agent')),\n principal_id TEXT NOT NULL, action TEXT NOT NULL, expires_at DATETIME, revoked_at DATETIME,\n created_by TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)",
				"CREATE INDEX access_grants_active ON access_grants(resource_id,action) WHERE revoked_at IS NULL",
				"CREATE TABLE access_operations (\n actor TEXT NOT NULL, caller TEXT NOT NULL REFERENCES identity_service_accounts(id), operation TEXT NOT NULL,\n idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),\n request_hash BLOB NOT NULL CHECK(length(request_hash)=32), resource_id TEXT REFERENCES access_resources(id),\n state TEXT NOT NULL CHECK(state IN ('running','completed')), result BLOB,\n created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,\n PRIMARY KEY(actor,caller,operation,idempotency_key))",
				"CREATE TABLE access_policy_audit (\n id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL,\n caller TEXT NOT NULL REFERENCES identity_service_accounts(id), on_behalf_of TEXT REFERENCES identity_users(id),\n operation TEXT NOT NULL, resource_id TEXT REFERENCES access_resources(id),\n policy_revision INTEGER NOT NULL UNIQUE CHECK(policy_revision>0), change_kind TEXT NOT NULL,\n grant_id TEXT REFERENCES access_grants(id), change TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(change)),\n occurred_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)",
				"CREATE INDEX access_policy_audit_resource_revision ON access_policy_audit(resource_id,policy_revision)",
				"CREATE TRIGGER access_policy_audit_immutable_update BEFORE UPDATE ON access_policy_audit BEGIN SELECT RAISE(ABORT,'policy audit append-only'); END",
				"CREATE TRIGGER access_policy_audit_immutable_delete BEFORE DELETE ON access_policy_audit BEGIN SELECT RAISE(ABORT,'policy audit append-only'); END",
			} {
				if err := tx.Exec(query).Error; err != nil {
					return err
				}
			}
			return nil
		}},
		{ID: "000004_fabric", Migrate: func(tx *gorm.DB) error {
			for _, query := range []string{
				"CREATE TABLE fabric_definitions (name TEXT PRIMARY KEY, publisher TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)",
				"CREATE TABLE fabric_contracts (\n digest TEXT PRIMARY KEY CHECK(length(digest)=64 AND digest NOT GLOB '*[^0-9a-f]*'),\n service_name TEXT NOT NULL REFERENCES fabric_definitions(name),\n api_major INTEGER NOT NULL CHECK(api_major>0),\n artifact TEXT NOT NULL CHECK(json_valid(artifact)), installation TEXT NOT NULL CHECK(json_valid(installation)),\n signature BLOB NOT NULL CHECK(length(signature)=64),\n approved_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, revoked_at DATETIME,\n UNIQUE(service_name,api_major,digest))",
				"CREATE UNIQUE INDEX fabric_active_service_major ON fabric_contracts(service_name,api_major) WHERE revoked_at IS NULL",
				"CREATE TABLE fabric_deployments (\n service_account_id TEXT NOT NULL REFERENCES identity_service_accounts(id),\n digest TEXT NOT NULL REFERENCES fabric_contracts(digest),\n subjects TEXT NOT NULL CHECK(json_valid(subjects) AND json_type(subjects)='array'),\n PRIMARY KEY(service_account_id,digest))",
				"CREATE TABLE fabric_instances (\n instance_id TEXT PRIMARY KEY, service_account_id TEXT NOT NULL REFERENCES identity_service_accounts(id),\n digest TEXT NOT NULL REFERENCES fabric_contracts(digest), build_version TEXT NOT NULL,\n ready INTEGER NOT NULL DEFAULT 0 CHECK(ready IN (0,1)), lease_until DATETIME NOT NULL,\n observed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)",
				"CREATE TABLE fabric_route_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), revision INTEGER NOT NULL DEFAULT 0 CHECK(revision>=0))",
				"INSERT INTO fabric_route_state(singleton,revision) VALUES(1,0)",
				"CREATE TRIGGER fabric_contracts_immutable BEFORE UPDATE ON fabric_contracts BEGIN\n SELECT CASE WHEN NEW.digest IS NOT OLD.digest OR NEW.service_name IS NOT OLD.service_name\n OR NEW.api_major IS NOT OLD.api_major OR NEW.artifact IS NOT OLD.artifact\n OR NEW.installation IS NOT OLD.installation OR NEW.signature IS NOT OLD.signature\n OR NEW.approved_at IS NOT OLD.approved_at\n THEN RAISE(ABORT,'immutable service contract') END;\n SELECT CASE WHEN OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at\n THEN RAISE(ABORT,'contract cannot be reactivated') END;\n END",
				"CREATE TABLE fabric_command_results (\n actor TEXT NOT NULL, operation TEXT NOT NULL, idempotency_key TEXT NOT NULL,\n request_hash BLOB NOT NULL CHECK(length(request_hash)=32), result BLOB NOT NULL,\n created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,\n PRIMARY KEY(actor,operation,idempotency_key))",
				"CREATE TABLE fabric_outbox (\n event_id TEXT PRIMARY KEY, subject TEXT NOT NULL, envelope TEXT NOT NULL CHECK(json_valid(envelope)),\n created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, published_at DATETIME)",
				"CREATE TABLE fabric_inbox (\n consumer TEXT NOT NULL, event_id TEXT NOT NULL, request_hash BLOB NOT NULL CHECK(length(request_hash)=32),\n received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(consumer,event_id))",
				"CREATE TRIGGER fabric_contracts_no_delete BEFORE DELETE ON fabric_contracts BEGIN SELECT RAISE(ABORT,'contract deletion forbidden'); END",
				"CREATE TRIGGER fabric_definitions_no_delete BEFORE DELETE ON fabric_definitions BEGIN SELECT RAISE(ABORT,'definition deletion forbidden'); END",
				"CREATE TRIGGER fabric_deployments_no_delete BEFORE DELETE ON fabric_deployments BEGIN SELECT RAISE(ABORT,'deployment deletion forbidden'); END",
			} {
				if err := tx.Exec(query).Error; err != nil {
					return err
				}
			}
			return nil
		}},
		{ID: "000005_runtime", Migrate: func(tx *gorm.DB) error {
			for _, query := range []string{
				"CREATE TABLE runtime_desired_deployments (\n id TEXT PRIMARY KEY CHECK(length(id) BETWEEN 1 AND 128),\n service_name TEXT NOT NULL CHECK(length(service_name) BETWEEN 1 AND 128),\n spec TEXT NOT NULL CHECK(json_valid(spec)),\n replicas INTEGER NOT NULL CHECK(replicas>=0),\n revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),\n updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)",
			} {
				if err := tx.Exec(query).Error; err != nil {
					return err
				}
			}
			return nil
		}},
	}
}
