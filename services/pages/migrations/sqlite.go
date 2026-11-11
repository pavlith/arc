package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func SQLite() []*gormigrate.Migration {
	return []*gormigrate.Migration{{ID: "000001_pages", Migrate: func(tx *gorm.DB) error {
		for _, q := range []string{
			`CREATE TABLE roots(acl_root_id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,owner_id TEXT NOT NULL DEFAULT '',state TEXT NOT NULL CHECK(state IN ('prepared','active')),UNIQUE(acl_root_id,workspace_id),CHECK((workspace_id='' AND owner_id<>'') OR (workspace_id<>'' AND owner_id='')))`,
			`CREATE TABLE pages(id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,parent_id TEXT,title TEXT NOT NULL CHECK(length(trim(title)) BETWEEN 1 AND 256),document TEXT NOT NULL CHECK(json_valid(document)),revision INTEGER NOT NULL CHECK(revision>0),created_at DATETIME NOT NULL,updated_at DATETIME NOT NULL,archived_at DATETIME,UNIQUE(id,workspace_id,acl_root_id),FOREIGN KEY(acl_root_id,workspace_id) REFERENCES roots(acl_root_id,workspace_id),FOREIGN KEY(parent_id,workspace_id,acl_root_id) REFERENCES pages(id,workspace_id,acl_root_id))`,
			`CREATE INDEX pages_tree ON pages(workspace_id,acl_root_id,parent_id,id) WHERE archived_at IS NULL`,
			`CREATE TABLE versions(page_id TEXT NOT NULL REFERENCES pages(id),revision INTEGER NOT NULL,title TEXT NOT NULL,document TEXT NOT NULL CHECK(json_valid(document)),created_at DATETIME NOT NULL,PRIMARY KEY(page_id,revision))`,
			`CREATE TABLE templates(id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,title TEXT NOT NULL,document TEXT NOT NULL CHECK(json_valid(document)),revision INTEGER NOT NULL CHECK(revision>0),archived_at DATETIME,FOREIGN KEY(acl_root_id,workspace_id) REFERENCES roots(acl_root_id,workspace_id))`,
			`CREATE TABLE audit(id INTEGER PRIMARY KEY AUTOINCREMENT,workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,entity_id TEXT NOT NULL,actor TEXT NOT NULL,operation TEXT NOT NULL,revision INTEGER NOT NULL,created_at DATETIME NOT NULL)`,
			`CREATE TABLE command_results(actor TEXT NOT NULL,operation TEXT NOT NULL,idempotency_key TEXT NOT NULL,request_hash BLOB NOT NULL CHECK(length(request_hash)=32),result BLOB,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(actor,operation,idempotency_key))`,
			`CREATE TABLE outbox(event_id TEXT PRIMARY KEY,subject TEXT NOT NULL CHECK(subject='evt.pages.catalog.changed.v1'),envelope BLOB NOT NULL,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,published_at DATETIME)`,
			`CREATE INDEX pages_outbox_pending ON outbox(created_at,event_id) WHERE published_at IS NULL`,
		} {
			if err := tx.Exec(q).Error; err != nil {
				return err
			}
		}
		return nil
	}}}
}
