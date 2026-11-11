// Package migrations owns the current notify SQLite schema.
// Old upgrade chains are intentionally not replayed by this fresh baseline.
package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// SQLite is executed only by the separate owner migrator before traffic.
func SQLite() []*gormigrate.Migration {
	return []*gormigrate.Migration{{
		ID: "000001_notify_baseline",
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
	`CREATE TABLE command_results(actor TEXT NOT NULL,operation TEXT NOT NULL,idempotency_key TEXT NOT NULL,request_hash BLOB NOT NULL CHECK(length(request_hash)=32),result BLOB,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(actor,operation,idempotency_key))`,
	`CREATE TABLE delivery_intents (
 notification_id TEXT NOT NULL REFERENCES notifications(id),recipient_user_id TEXT NOT NULL,
 channel TEXT NOT NULL CHECK(channel IN ('fake','webhook')),dedup_key TEXT NOT NULL UNIQUE,
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),delivered_at DATETIME,
 claim_token TEXT,lease_until DATETIME,next_attempt_at DATETIME,failed_at DATETIME,
 PRIMARY KEY(notification_id,recipient_user_id,channel))`,
	`CREATE TABLE inbox (
					consumer TEXT NOT NULL, event_id TEXT NOT NULL,
					request_hash BLOB NOT NULL CHECK(length(request_hash)=32),
					received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
					PRIMARY KEY(consumer,event_id)
				)`,
	`CREATE TABLE "notifications" (
 id TEXT PRIMARY KEY, recipient_user_id TEXT NOT NULL,event_id TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('task.created','page.created','page.updated','page.restored','file.uploaded')),
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,read_at DATETIME,
 workspace_id TEXT,acl_root_id TEXT,archived_at DATETIME,snoozed_until DATETIME,
 revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),
 resource_kind TEXT NOT NULL CHECK(resource_kind IN ('task','page','file')),
 resource_id TEXT,UNIQUE(recipient_user_id,event_id,kind))`,
	`CREATE TABLE outbox (
				event_id TEXT PRIMARY KEY,
				subject TEXT NOT NULL CHECK(subject='evt.notify.inbox.changed.v1'),
				envelope BLOB NOT NULL,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				published_at DATETIME)`,
	`CREATE TABLE subscriptions (
					workspace_id TEXT NOT NULL, acl_root_id TEXT NOT NULL,
					recipient_user_id TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)), resource_kind TEXT NOT NULL CHECK(resource_kind IN ('task','page','file')),
					PRIMARY KEY(workspace_id,acl_root_id,recipient_user_id)
				)`,
	`CREATE TABLE user_audit(id INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT NOT NULL,operation TEXT NOT NULL,target TEXT NOT NULL,created_at DATETIME NOT NULL)`,
	`CREATE INDEX delivery_pending ON delivery_intents(channel,next_attempt_at,lease_until) WHERE delivered_at IS NULL AND failed_at IS NULL`,
	`CREATE INDEX notifications_user_page ON notifications(recipient_user_id,id)`,
	`CREATE INDEX notifications_user_unread ON notifications(recipient_user_id,acl_root_id) WHERE read_at IS NULL AND archived_at IS NULL`,
	`CREATE INDEX notify_pending_outbox ON outbox(created_at,event_id) WHERE published_at IS NULL`,
}
