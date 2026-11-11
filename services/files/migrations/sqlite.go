// Package migrations owns the current files SQLite schema.
// Old upgrade chains are intentionally not replayed by this fresh baseline.
package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// SQLite is executed only by the separate owner migrator before traffic.
func SQLite() []*gormigrate.Migration {
	return []*gormigrate.Migration{{
		ID: "000001_baseline",
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
	`CREATE TABLE audit (
					id INTEGER PRIMARY KEY AUTOINCREMENT, workspace_id TEXT NOT NULL,
					acl_root_id TEXT NOT NULL, folder_id TEXT NOT NULL,
					actor TEXT NOT NULL, operation TEXT NOT NULL, revision INTEGER NOT NULL,
					request_id TEXT NOT NULL, traceparent TEXT NOT NULL, created_at DATETIME NOT NULL)`,
	`CREATE TABLE command_results (
					actor TEXT NOT NULL, operation TEXT NOT NULL, idempotency_key TEXT NOT NULL,
					request_hash BLOB NOT NULL CHECK(length(request_hash)=32),
					result BLOB, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
					PRIMARY KEY(actor,operation,idempotency_key))`,
	`CREATE TABLE files (
					id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, acl_root_id TEXT NOT NULL,
					folder_id TEXT, filename TEXT NOT NULL, mime TEXT NOT NULL,
					size INTEGER NOT NULL CHECK(size >= 0), sha256 TEXT NOT NULL,
					blob_key TEXT NOT NULL UNIQUE, revision INTEGER NOT NULL CHECK(revision > 0),
					state TEXT NOT NULL CHECK(state IN ('ready','archived')),
					created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, archived_at DATETIME,
					UNIQUE(id,workspace_id,acl_root_id),
					FOREIGN KEY(acl_root_id,workspace_id) REFERENCES roots(acl_root_id,workspace_id),
					FOREIGN KEY(folder_id,workspace_id,acl_root_id) REFERENCES folders(id,workspace_id,acl_root_id))`,
	`CREATE TABLE folders (
					id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL,
					acl_root_id TEXT NOT NULL, parent_id TEXT,
					name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 256),
					revision INTEGER NOT NULL CHECK(revision > 0),
					created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, archived_at DATETIME,
					UNIQUE(id,workspace_id,acl_root_id),
					FOREIGN KEY(acl_root_id,workspace_id) REFERENCES roots(acl_root_id,workspace_id),
					FOREIGN KEY(parent_id,workspace_id,acl_root_id) REFERENCES folders(id,workspace_id,acl_root_id))`,
	`CREATE TABLE outbox (
					event_id TEXT PRIMARY KEY,
					subject TEXT NOT NULL CHECK(subject='evt.files.catalog.changed.v1'),
					envelope BLOB NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
					published_at DATETIME)`,
	`CREATE TABLE roots (
					acl_root_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL,
					state TEXT NOT NULL CHECK(state IN ('prepared','active')), owner_id TEXT NOT NULL DEFAULT '',
					UNIQUE(acl_root_id,workspace_id))`,
	`CREATE TABLE uploads (
					id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, acl_root_id TEXT NOT NULL,
					folder_id TEXT, actor_id TEXT NOT NULL, session_id TEXT NOT NULL,
					filename TEXT NOT NULL, declared_mime TEXT NOT NULL,
					expected_size INTEGER NOT NULL CHECK(expected_size >= 0 AND expected_size <= 1073741824),
					expected_sha256 TEXT NOT NULL DEFAULT '', temp_key TEXT NOT NULL UNIQUE,
					offset INTEGER NOT NULL DEFAULT 0 CHECK(offset >= 0 AND offset <= expected_size),
					state TEXT NOT NULL CHECK(state IN ('pending','completed','aborted','expired')),
					idempotency_key TEXT NOT NULL, expires_at DATETIME NOT NULL,
					created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, cleaned_at DATETIME,
					FOREIGN KEY(acl_root_id,workspace_id) REFERENCES roots(acl_root_id,workspace_id),
					FOREIGN KEY(folder_id,workspace_id,acl_root_id) REFERENCES folders(id,workspace_id,acl_root_id),
					UNIQUE(actor_id,idempotency_key))`,
	`CREATE INDEX files_folder ON files(workspace_id,acl_root_id,folder_id,id) WHERE state='ready'`,
	`CREATE INDEX files_pending_outbox ON outbox(created_at,event_id) WHERE published_at IS NULL`,
	`CREATE INDEX files_personal_owners ON roots(owner_id,acl_root_id) WHERE workspace_id=''`,
	`CREATE UNIQUE INDEX folders_active_siblings ON folders(workspace_id,acl_root_id,coalesce(parent_id,''),name) WHERE archived_at IS NULL`,
	`CREATE INDEX folders_tree ON folders(workspace_id,acl_root_id,parent_id,id) WHERE archived_at IS NULL`,
	`CREATE INDEX uploads_cleanup_queue ON uploads(expires_at,id) WHERE cleaned_at IS NULL`,
	`CREATE INDEX uploads_expiry ON uploads(expires_at,id) WHERE state='pending'`,
}
