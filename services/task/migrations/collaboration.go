package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func collaboration() *gormigrate.Migration {
	return &gormigrate.Migration{ID: "000005_collaboration", Migrate: func(tx *gorm.DB) error {
		for _, q := range []string{
			`ALTER TABLE product_audit ADD COLUMN fields_changed TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(fields_changed))`,
			`CREATE TABLE task_comments(id TEXT PRIMARY KEY,task_id TEXT NOT NULL,workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,
			parent_id TEXT,author_id TEXT NOT NULL,body TEXT NOT NULL CHECK(length(trim(body)) BETWEEN 1 AND 15000),
			resolved BOOLEAN NOT NULL DEFAULT 0,revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),created_at DATETIME NOT NULL,updated_at DATETIME NOT NULL,archived_at DATETIME,
			UNIQUE(id,task_id,workspace_id,acl_root_id),FOREIGN KEY(task_id,workspace_id,acl_root_id) REFERENCES tasks(id,workspace_id,acl_root_id),
			FOREIGN KEY(parent_id,task_id,workspace_id,acl_root_id) REFERENCES task_comments(id,task_id,workspace_id,acl_root_id))`,
			`CREATE INDEX task_comments_scope ON task_comments(task_id,id)`,
			`CREATE INDEX product_task_history ON product_audit(workspace_id,acl_root_id,entity_kind,entity_id,id)`,
			`CREATE TABLE saved_views(id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,owner_id TEXT NOT NULL,
			name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 128),description TEXT NOT NULL DEFAULT '',
			filters TEXT NOT NULL CHECK(json_valid(filters)),is_shared BOOLEAN NOT NULL DEFAULT 0,
			revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),created_at DATETIME NOT NULL,updated_at DATETIME NOT NULL,archived_at DATETIME,
			FOREIGN KEY(acl_root_id,workspace_id) REFERENCES roots(acl_root_id,workspace_id))`,
			`CREATE INDEX saved_views_scope ON saved_views(workspace_id,acl_root_id,id)`,
		} {
			if err := tx.Exec(q).Error; err != nil {
				return err
			}
		}
		return nil
	}}
}
