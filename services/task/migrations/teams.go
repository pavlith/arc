package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func teams() *gormigrate.Migration {
	return &gormigrate.Migration{ID: "000002_teams", Migrate: func(tx *gorm.DB) error {
		for _, q := range []string{
			`CREATE TABLE teams (
				id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, acl_root_id TEXT NOT NULL,
				name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 128),
				key TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', color TEXT NOT NULL DEFAULT '',
				revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),
				created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, archived_at DATETIME,
				UNIQUE(workspace_id,key), UNIQUE(id,workspace_id,acl_root_id),
				FOREIGN KEY(acl_root_id,workspace_id) REFERENCES roots(acl_root_id,workspace_id))`,
			`CREATE INDEX teams_root ON teams(workspace_id,acl_root_id,id)`,
			`CREATE TABLE workflow_statuses (
				id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, acl_root_id TEXT NOT NULL, team_id TEXT NOT NULL,
				name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 128),
				category TEXT NOT NULL CHECK(category IN ('backlog','todo','in_progress','in_review','done','cancelled')),
				color TEXT NOT NULL DEFAULT '', position INTEGER NOT NULL DEFAULT 0 CHECK(position>=0),
				is_default BOOLEAN NOT NULL DEFAULT 0, revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),
				created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, archived_at DATETIME,
				UNIQUE(id,team_id,workspace_id,acl_root_id),
				FOREIGN KEY(team_id,workspace_id,acl_root_id) REFERENCES teams(id,workspace_id,acl_root_id))`,
			`CREATE UNIQUE INDEX workflow_one_default ON workflow_statuses(team_id) WHERE is_default=1 AND archived_at IS NULL`,
			`CREATE INDEX workflow_team ON workflow_statuses(team_id,position,id)`,
			`CREATE TABLE product_audit (
				id INTEGER PRIMARY KEY AUTOINCREMENT, workspace_id TEXT NOT NULL, acl_root_id TEXT NOT NULL,
				entity_kind TEXT NOT NULL, entity_id TEXT NOT NULL, actor TEXT NOT NULL,
				operation TEXT NOT NULL, revision INTEGER NOT NULL,
				request_id TEXT NOT NULL, traceparent TEXT NOT NULL, created_at DATETIME NOT NULL)`,
			`ALTER TABLE outbox RENAME TO outbox_legacy`,
			`CREATE TABLE outbox (
				event_id TEXT PRIMARY KEY,
				subject TEXT NOT NULL CHECK(subject IN ('evt.task.task.created.v1','evt.task.catalog.changed.v1')),
				envelope BLOB NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, published_at DATETIME)`,
			`INSERT INTO outbox SELECT event_id,subject,envelope,created_at,published_at FROM outbox_legacy`,
			`DROP TABLE outbox_legacy`,
			`CREATE INDEX task_pending_outbox ON outbox(created_at,event_id) WHERE published_at IS NULL`,
		} {
			if err := tx.Exec(q).Error; err != nil {
				return err
			}
		}
		return nil
	}}
}
