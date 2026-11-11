package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func templates() *gormigrate.Migration {
	return &gormigrate.Migration{ID: "000008_work_templates", Migrate: func(tx *gorm.DB) error {
		for _, q := range []string{
			"CREATE TABLE work_templates (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, acl_root_id TEXT NOT NULL, team_id TEXT NOT NULL, name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 128), definition TEXT NOT NULL CHECK(json_valid(definition) AND json_type(definition)='object'), revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0), created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, archived_at DATETIME, FOREIGN KEY(team_id,workspace_id,acl_root_id) REFERENCES teams(id,workspace_id,acl_root_id), FOREIGN KEY(acl_root_id,workspace_id) REFERENCES roots(acl_root_id,workspace_id))",
			"CREATE INDEX work_templates_scope ON work_templates(workspace_id,acl_root_id,id)",
		} {
			if err := tx.Exec(q).Error; err != nil {
				return err
			}
		}
		return nil
	}}
}
