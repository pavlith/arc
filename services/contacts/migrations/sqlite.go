// Package migrations owns the Contacts SQLite schema.
package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// SQLite is executed only by the separate owner migrator before traffic.
func SQLite() []*gormigrate.Migration {
	return []*gormigrate.Migration{{ID: "000001_contacts_baseline", Migrate: func(tx *gorm.DB) error {
		for _, sql := range baselineSchema {
			if err := tx.Exec(sql).Error; err != nil {
				return err
			}
		}
		return nil
	}}}
}

var baselineSchema = []string{
	`CREATE TABLE roots(acl_root_id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,owner_id TEXT NOT NULL DEFAULT '',state TEXT NOT NULL CHECK(state IN ('prepared','active')),name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 256),revision INTEGER NOT NULL CHECK(revision>0),UNIQUE(acl_root_id,workspace_id),CHECK((workspace_id='' AND owner_id<>'') OR (workspace_id<>'' AND owner_id='')))`,
	`CREATE TABLE contacts(id TEXT PRIMARY KEY,uid TEXT NOT NULL CHECK(length(uid) BETWEEN 1 AND 255),workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,display_name TEXT NOT NULL CHECK(length(trim(display_name)) BETWEEN 1 AND 256),organization TEXT NOT NULL,role TEXT NOT NULL,fields TEXT NOT NULL CHECK(json_valid(fields)),search_text TEXT NOT NULL,revision INTEGER NOT NULL CHECK(revision>0),created_at DATETIME NOT NULL,updated_at DATETIME NOT NULL,deleted_at DATETIME,UNIQUE(workspace_id,acl_root_id,uid),FOREIGN KEY(acl_root_id,workspace_id) REFERENCES roots(acl_root_id,workspace_id))`,
	`CREATE INDEX contacts_active ON contacts(workspace_id,acl_root_id,id) WHERE deleted_at IS NULL`,
	`CREATE TABLE audit(id INTEGER PRIMARY KEY AUTOINCREMENT,workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,entity_id TEXT NOT NULL,actor TEXT NOT NULL,operation TEXT NOT NULL,revision INTEGER NOT NULL,created_at DATETIME NOT NULL)`,
	`CREATE TABLE command_results(actor TEXT NOT NULL,operation TEXT NOT NULL,idempotency_key TEXT NOT NULL,request_hash BLOB NOT NULL CHECK(length(request_hash)=32),result BLOB,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(actor,operation,idempotency_key))`,
	`CREATE TABLE outbox(event_id TEXT PRIMARY KEY,subject TEXT NOT NULL CHECK(subject='evt.contacts.catalog.changed.v1'),envelope BLOB NOT NULL,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,published_at DATETIME)`,
	`CREATE INDEX contacts_outbox_pending ON outbox(created_at,event_id) WHERE published_at IS NULL`,
}
