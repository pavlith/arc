package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func workspaceRoots() *gormigrate.Migration {
	return &gormigrate.Migration{ID: "000008_workspace_roots", Migrate: func(tx *gorm.DB) error {
		for _, statement := range []string{
			`ALTER TABLE identity_workspaces ADD COLUMN acl_root_id TEXT REFERENCES access_resources(id)
			 CHECK(acl_root_id IS NULL OR acl_root_id=id)`,
			`ALTER TABLE identity_workspaces ADD COLUMN archived_at DATETIME`,
			// This disabled identity only supplies the registry and audit foreign keys.
			`INSERT INTO identity_service_accounts(id,service_definition,deployment,disabled_at)
			 VALUES('00000000-0000-4000-8000-00000000a001','arc-core','workspace-registry',CURRENT_TIMESTAMP)`,
			`INSERT INTO access_resource_types(type,provider_service,contract_digest,actions,share_action,create_action,delete_action,allow_inheritance)
			 VALUES('arc.workspace','00000000-0000-4000-8000-00000000a001',lower(hex(zeroblob(32))),
			 '["arc.workspace.manage","access.grants.manage"]','arc.workspace.manage','arc.workspace.manage','arc.workspace.manage',0)`,
			`INSERT INTO access_resources(id,type,provider_service,owner_kind,owner_id,workspace_id,inherit_acl,state,policy_revision)
			 SELECT id,'arc.workspace','00000000-0000-4000-8000-00000000a001','workspace',id,id,0,'active',
			 (SELECT revision FROM access_policy_state WHERE singleton=1)+ROW_NUMBER() OVER (ORDER BY id)
			 FROM identity_workspaces`,
			`UPDATE identity_workspaces SET acl_root_id=id`,
			`INSERT INTO access_policy_audit(actor,caller,operation,resource_id,policy_revision,change_kind)
			 SELECT 'core','00000000-0000-4000-8000-00000000a001','workspaces.backfill_root',id,policy_revision,'workspace_root_created'
			 FROM access_resources WHERE type='arc.workspace'`,
			`UPDATE access_policy_state SET revision=revision+(SELECT count(*) FROM identity_workspaces) WHERE singleton=1`,
		} {
			if err := tx.Exec(statement).Error; err != nil {
				return err
			}
		}
		return nil
	}}
}
