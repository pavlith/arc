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
	}}, {ID: "000002_mail_account_provisioning", Migrate: func(tx *gorm.DB) error {
		return tx.Exec(`CREATE TABLE account_provisions(actor TEXT NOT NULL,idempotency_key TEXT NOT NULL,request_hash BLOB NOT NULL CHECK(length(request_hash)=32),acl_root_id TEXT NOT NULL UNIQUE REFERENCES accounts(acl_root_id),created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(actor,idempotency_key))`).Error
	}}, {ID: "000003_mail_message_index", Migrate: func(tx *gorm.DB) error {
		for _, statement := range messageIndex {
			if err := tx.Exec(statement).Error; err != nil {
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

var messageIndex = []string{
	`CREATE TABLE mail_folders(id TEXT PRIMARY KEY,acl_root_id TEXT NOT NULL REFERENCES accounts(acl_root_id),generation INTEGER NOT NULL,wire_name TEXT NOT NULL,revision INTEGER NOT NULL,uid_validity INTEGER NOT NULL,uid_next INTEGER NOT NULL,remote_count INTEGER NOT NULL,next_before_uid INTEGER NOT NULL,low_uid INTEGER NOT NULL,high_uid INTEGER NOT NULL,status TEXT NOT NULL,updated_at DATETIME NOT NULL,UNIQUE(acl_root_id,generation,wire_name))`,
	`CREATE TABLE mail_messages(id TEXT PRIMARY KEY,folder_id TEXT NOT NULL REFERENCES mail_folders(id),uid_validity INTEGER NOT NULL,uid INTEGER NOT NULL,present INTEGER NOT NULL CHECK(present IN (0,1)),summary BLOB NOT NULL CHECK(length(summary)<=65536),UNIQUE(folder_id,uid_validity,uid))`,
	`CREATE INDEX mail_message_page ON mail_messages(folder_id,uid_validity,present,uid DESC)`,
	`CREATE TABLE mail_refresh_staging(actor TEXT NOT NULL,idempotency_key TEXT NOT NULL,request_hash BLOB NOT NULL CHECK(length(request_hash)=32),acl_root_id TEXT NOT NULL REFERENCES accounts(acl_root_id),snapshot BLOB NOT NULL CHECK(length(snapshot)<=163840),created_unix INTEGER NOT NULL,PRIMARY KEY(actor,idempotency_key))`,
	`CREATE INDEX mail_refresh_pending ON mail_refresh_staging(acl_root_id,created_unix)`,
	`CREATE TABLE mail_outbox_next(event_id TEXT PRIMARY KEY,subject TEXT NOT NULL CHECK(subject IN ('evt.mail.accounts.changed.v1','evt.mail.messages.changed.v1')),envelope BLOB NOT NULL,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,published_at DATETIME)`,
	`INSERT INTO mail_outbox_next SELECT event_id,subject,envelope,created_at,published_at FROM outbox`,
	`DROP TABLE outbox`,
	`ALTER TABLE mail_outbox_next RENAME TO outbox`,
	`CREATE INDEX mail_outbox_pending ON outbox(created_at,event_id) WHERE published_at IS NULL`,
}
