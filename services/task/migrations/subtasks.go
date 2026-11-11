package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func subtasks() *gormigrate.Migration {
	return &gormigrate.Migration{ID: "000006_subtasks", Migrate: func(tx *gorm.DB) error {
		for _, q := range []string{
			`CREATE TABLE task_parents(task_id TEXT PRIMARY KEY, parent_id TEXT NOT NULL, workspace_id TEXT NOT NULL, acl_root_id TEXT NOT NULL,
    CHECK(task_id<>parent_id),
    FOREIGN KEY(task_id,workspace_id,acl_root_id) REFERENCES tasks(id,workspace_id,acl_root_id),
    FOREIGN KEY(parent_id,workspace_id,acl_root_id) REFERENCES tasks(id,workspace_id,acl_root_id))`,
			`CREATE INDEX task_parent_children ON task_parents(parent_id,task_id)`,
		} {
			if err := tx.Exec(q).Error; err != nil {
				return err
			}
		}
		return nil
	}}
}
