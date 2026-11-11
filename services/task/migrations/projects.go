package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func projects() *gormigrate.Migration {
	return &gormigrate.Migration{ID: "000004_projects_labels", Migrate: func(tx *gorm.DB) error {
		for _, q := range []string{
			`CREATE TABLE team_members(team_id TEXT NOT NULL,workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,user_id TEXT NOT NULL,created_at DATETIME NOT NULL,
				PRIMARY KEY(team_id,user_id),FOREIGN KEY(team_id,workspace_id,acl_root_id) REFERENCES teams(id,workspace_id,acl_root_id))`,
			`CREATE TABLE projects (
				id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,team_id TEXT,
				name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 128),description TEXT NOT NULL DEFAULT '',color TEXT NOT NULL DEFAULT '',
				status TEXT NOT NULL CHECK(status IN ('planned','active','paused','completed','cancelled')),start_date DATETIME,due_date DATETIME,
				revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),created_at DATETIME NOT NULL,updated_at DATETIME NOT NULL,archived_at DATETIME,
				UNIQUE(id,workspace_id,acl_root_id),FOREIGN KEY(acl_root_id,workspace_id) REFERENCES roots(acl_root_id,workspace_id),
				FOREIGN KEY(team_id,workspace_id,acl_root_id) REFERENCES teams(id,workspace_id,acl_root_id))`,
			`CREATE INDEX projects_root ON projects(workspace_id,acl_root_id,id)`,
			`CREATE TABLE labels(id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,
				name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 128),color TEXT NOT NULL DEFAULT '',
				revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),created_at DATETIME NOT NULL,updated_at DATETIME NOT NULL,archived_at DATETIME,
				UNIQUE(id,workspace_id,acl_root_id),FOREIGN KEY(acl_root_id,workspace_id) REFERENCES roots(acl_root_id,workspace_id))`,
			`CREATE INDEX labels_root ON labels(workspace_id,acl_root_id,id)`,
			`ALTER TABLE task_details ADD COLUMN project_id TEXT REFERENCES projects(id)`,
			`CREATE UNIQUE INDEX task_details_scope ON task_details(task_id,workspace_id,acl_root_id)`,
			`CREATE TABLE task_labels(task_id TEXT NOT NULL,workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,label_id TEXT NOT NULL,
				PRIMARY KEY(task_id,label_id),FOREIGN KEY(task_id,workspace_id,acl_root_id) REFERENCES task_details(task_id,workspace_id,acl_root_id),
				FOREIGN KEY(label_id,workspace_id,acl_root_id) REFERENCES labels(id,workspace_id,acl_root_id))`,
			`CREATE INDEX task_labels_filter ON task_labels(label_id,task_id)`,
			`CREATE TRIGGER task_project_insert BEFORE INSERT ON task_details WHEN NEW.project_id IS NOT NULL AND NOT EXISTS(
				SELECT 1 FROM projects p WHERE p.id=NEW.project_id AND p.workspace_id=NEW.workspace_id AND p.acl_root_id=NEW.acl_root_id AND (p.team_id IS NULL OR p.team_id=NEW.team_id)) BEGIN SELECT RAISE(ABORT,'project scope mismatch'); END`,
			`CREATE TRIGGER task_project_update BEFORE UPDATE OF project_id,team_id,workspace_id,acl_root_id ON task_details WHEN NEW.project_id IS NOT NULL AND NOT EXISTS(
				SELECT 1 FROM projects p WHERE p.id=NEW.project_id AND p.workspace_id=NEW.workspace_id AND p.acl_root_id=NEW.acl_root_id AND (p.team_id IS NULL OR p.team_id=NEW.team_id)) BEGIN SELECT RAISE(ABORT,'project scope mismatch'); END`,
		} {
			if err := tx.Exec(q).Error; err != nil {
				return err
			}
		}
		return nil
	}}
}
