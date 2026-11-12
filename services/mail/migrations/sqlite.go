// Package migrations owns the Mail SQLite schema; startup never migrates.
package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func SQLite() []*gormigrate.Migration {
	return []*gormigrate.Migration{{ID: "000001_mail_baseline", Migrate: func(tx *gorm.DB) error {
		for _, sql := range baseline {
			if err := tx.Exec(sql).Error; err != nil {
				return err
			}
		}
		return nil
	}}}
}

var baseline = []string{
	`CREATE TABLE accounts(acl_root_id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL CHECK(workspace_id=''),owner_id TEXT NOT NULL,lifecycle TEXT NOT NULL CHECK(lifecycle IN ('prepared','active')),name TEXT NOT NULL,host TEXT NOT NULL,port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),login TEXT NOT NULL,email TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('enabled','paused','disconnected')),revision INTEGER NOT NULL CHECK(revision>0),generation INTEGER NOT NULL CHECK(generation>0),credential_version INTEGER NOT NULL DEFAULT 0 CHECK(credential_version>=0),key_id TEXT NOT NULL DEFAULT '',ciphertext BLOB,CHECK((ciphertext IS NULL AND key_id='') OR (length(ciphertext)>=28 AND length(key_id)=64)),CHECK(state<>'disconnected' OR ciphertext IS NULL))`,
	`CREATE TABLE audit(id INTEGER PRIMARY KEY AUTOINCREMENT,acl_root_id TEXT NOT NULL,actor TEXT NOT NULL,operation TEXT NOT NULL,revision INTEGER NOT NULL,generation INTEGER NOT NULL,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
	`CREATE TABLE command_results(actor TEXT NOT NULL,operation TEXT NOT NULL,idempotency_key TEXT NOT NULL,request_hash BLOB NOT NULL CHECK(length(request_hash)=32),result BLOB,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(actor,operation,idempotency_key))`,
	`CREATE TABLE outbox(event_id TEXT PRIMARY KEY,subject TEXT NOT NULL CHECK(subject='evt.mail.accounts.changed.v1'),envelope BLOB NOT NULL,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,published_at DATETIME)`,
	`CREATE INDEX mail_outbox_pending ON outbox(created_at,event_id) WHERE published_at IS NULL`,
}
