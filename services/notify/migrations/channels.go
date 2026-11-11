package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func channels() *gormigrate.Migration {
	return &gormigrate.Migration{ID: "000004_channels", Migrate: func(tx *gorm.DB) error {
		for _, q := range []string{
			`ALTER TABLE subscriptions ADD COLUMN resource_kind TEXT NOT NULL DEFAULT 'task' CHECK(resource_kind IN ('task','page','file'))`,
			`CREATE TABLE delivery_backup AS SELECT * FROM delivery_intents`,
			`DROP TABLE delivery_intents`,
			`CREATE TABLE notifications_next (
 id TEXT PRIMARY KEY, recipient_user_id TEXT NOT NULL,event_id TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('task.created','page.created','page.updated','page.restored','file.uploaded')),
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,read_at DATETIME,
 workspace_id TEXT,acl_root_id TEXT,task_id TEXT,archived_at DATETIME,snoozed_until DATETIME,
 revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),
 resource_kind TEXT NOT NULL DEFAULT 'task' CHECK(resource_kind IN ('task','page','file')),
 resource_id TEXT,UNIQUE(recipient_user_id,event_id,kind))`,
			`INSERT INTO notifications_next SELECT id,recipient_user_id,event_id,kind,created_at,read_at,workspace_id,acl_root_id,task_id,archived_at,snoozed_until,revision,'task',task_id FROM notifications`,
			`DROP TABLE notifications`,
			`ALTER TABLE notifications_next RENAME TO notifications`,
			`CREATE INDEX notifications_user_page ON notifications(recipient_user_id,id)`,
			`CREATE INDEX notifications_user_unread ON notifications(recipient_user_id,acl_root_id) WHERE read_at IS NULL AND archived_at IS NULL`,
			`CREATE TABLE delivery_intents (
 notification_id TEXT NOT NULL REFERENCES notifications(id),recipient_user_id TEXT NOT NULL,
 channel TEXT NOT NULL CHECK(channel IN ('fake','webhook')),dedup_key TEXT NOT NULL UNIQUE,
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),delivered_at DATETIME,
 claim_token TEXT,lease_until DATETIME,next_attempt_at DATETIME,failed_at DATETIME,
 PRIMARY KEY(notification_id,recipient_user_id,channel))`,
			`INSERT INTO delivery_intents(notification_id,recipient_user_id,channel,dedup_key,attempts,delivered_at) SELECT notification_id,recipient_user_id,channel,dedup_key,attempts,delivered_at FROM delivery_backup`,
			`DROP TABLE delivery_backup`,
			`CREATE INDEX delivery_pending ON delivery_intents(channel,next_attempt_at,lease_until) WHERE delivered_at IS NULL AND failed_at IS NULL`,
		} {
			if err := tx.Exec(q).Error; err != nil {
				return err
			}
		}
		return nil
	}}
}
