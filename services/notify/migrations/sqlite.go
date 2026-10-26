// Package migrations contains the independently deployed Notify SQLite schema.
package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// SQLite returns the notification inbox and operator-owned addressing schema.
func SQLite() []*gormigrate.Migration {
	return []*gormigrate.Migration{{
		ID: "000001_notify",
		Migrate: func(tx *gorm.DB) error {
			statements := []string{
				`CREATE TABLE inbox (
					consumer TEXT NOT NULL, event_id TEXT NOT NULL,
					request_hash BLOB NOT NULL CHECK(length(request_hash)=32),
					received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
					PRIMARY KEY(consumer,event_id)
				)`,
				`CREATE TABLE subscriptions (
					workspace_id TEXT NOT NULL, acl_root_id TEXT NOT NULL,
					recipient_user_id TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
					PRIMARY KEY(workspace_id,acl_root_id,recipient_user_id)
				)`,
				`CREATE TABLE notifications (
					id TEXT PRIMARY KEY, recipient_user_id TEXT NOT NULL, event_id TEXT NOT NULL,
					kind TEXT NOT NULL CHECK(kind='task.created'),
					created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, read_at DATETIME,
					UNIQUE(recipient_user_id,event_id,kind)
				)`,
				`CREATE TABLE delivery_intents (
					notification_id TEXT NOT NULL REFERENCES notifications(id),
					recipient_user_id TEXT NOT NULL, channel TEXT NOT NULL CHECK(channel='fake'),
					dedup_key TEXT NOT NULL UNIQUE, attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),
					delivered_at DATETIME, PRIMARY KEY(notification_id,recipient_user_id,channel)
				)`,
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
