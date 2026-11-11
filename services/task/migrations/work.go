package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func workItems() *gormigrate.Migration {
	return &gormigrate.Migration{ID: "000003_work_items", Migrate: func(tx *gorm.DB) error {
		for _, q := range []string{
			`ALTER TABLE teams ADD COLUMN sequence INTEGER NOT NULL DEFAULT 0 CHECK(sequence>=0)`,
			`CREATE UNIQUE INDEX task_scope_unique ON tasks(id,workspace_id,acl_root_id)`,
			`CREATE TABLE task_details (
				task_id TEXT PRIMARY KEY REFERENCES tasks(id),workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,
				team_id TEXT NOT NULL,status_id TEXT NOT NULL,identifier TEXT NOT NULL,
				description TEXT NOT NULL DEFAULT '',priority INTEGER NOT NULL DEFAULT 0 CHECK(priority BETWEEN 0 AND 4),
				due_date DATETIME,sort_order INTEGER NOT NULL DEFAULT 0 CHECK(sort_order>=0),
				revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),archived_at DATETIME,
				UNIQUE(workspace_id,identifier),
				FOREIGN KEY(task_id,workspace_id,acl_root_id) REFERENCES tasks(id,workspace_id,acl_root_id),
				FOREIGN KEY(team_id,workspace_id,acl_root_id) REFERENCES teams(id,workspace_id,acl_root_id),
				FOREIGN KEY(status_id,team_id,workspace_id,acl_root_id) REFERENCES workflow_statuses(id,team_id,workspace_id,acl_root_id))`,
			`CREATE TABLE task_assignees(task_id TEXT NOT NULL REFERENCES task_details(task_id),user_id TEXT NOT NULL,PRIMARY KEY(task_id,user_id))`,
			`CREATE INDEX task_details_root ON task_details(workspace_id,acl_root_id,task_id)`,
			`CREATE INDEX task_assignees_user ON task_assignees(user_id,task_id)`,
		} {
			if err := tx.Exec(q).Error; err != nil {
				return err
			}
		}
		return nil
	}}
}
