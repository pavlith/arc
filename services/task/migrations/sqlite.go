// Package migrations contains the independently deployed Task SQLite schema.
// Its migrations are explicit, immutable, and never run during service startup.
package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// SQLite returns the owner-local Task schema (no PostgreSQL schema prefixes).
func SQLite() []*gormigrate.Migration {
	return []*gormigrate.Migration{{
		ID: "000001_task",
		Migrate: func(tx *gorm.DB) error {
			statements := []string{
				`CREATE TABLE roots (
					acl_root_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL,
					state TEXT NOT NULL CHECK(state IN ('prepared','active')),
					UNIQUE(acl_root_id,workspace_id)
				)`,
				`CREATE TABLE tasks (
					id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, acl_root_id TEXT NOT NULL,
					title TEXT NOT NULL CHECK(length(trim(title)) BETWEEN 1 AND 300),
					status TEXT NOT NULL DEFAULT 'open' CHECK(status='open'),
					created_by TEXT NOT NULL, created_at DATETIME NOT NULL,
					updated_at DATETIME NOT NULL,
					FOREIGN KEY(acl_root_id,workspace_id) REFERENCES roots(acl_root_id,workspace_id),
					CHECK(updated_at >= created_at)
				)`,
				`CREATE INDEX task_workspace_user ON tasks(workspace_id,acl_root_id,created_by,created_at,id)`,
				`CREATE TABLE audit (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					task_id TEXT NOT NULL REFERENCES tasks(id),
					actor TEXT NOT NULL, operation TEXT NOT NULL, request_id TEXT NOT NULL,
					traceparent TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
				)`,
				`CREATE TABLE command_results (
					actor TEXT NOT NULL, operation TEXT NOT NULL, idempotency_key TEXT NOT NULL,
					request_hash BLOB NOT NULL CHECK(length(request_hash)=32),
					result BLOB, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
					PRIMARY KEY(actor,operation,idempotency_key)
				)`,
				`CREATE TABLE outbox (
					event_id TEXT PRIMARY KEY, subject TEXT NOT NULL CHECK(subject='evt.task.task.created.v1'),
					envelope BLOB NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
					published_at DATETIME
				)`,
				`CREATE INDEX task_pending_outbox ON outbox(created_at,event_id) WHERE published_at IS NULL`,
			}
			for _, statement := range statements {
				if err := tx.Exec(statement).Error; err != nil {
					return err
				}
			}
			return nil
		},
	}}
}
