package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func userInbox() *gormigrate.Migration {
	return &gormigrate.Migration{ID: "000002_user_inbox", Migrate: func(tx *gorm.DB) error {
		for _, q := range []string{
			`ALTER TABLE notifications ADD COLUMN workspace_id TEXT`,
			`ALTER TABLE notifications ADD COLUMN acl_root_id TEXT`,
			`ALTER TABLE notifications ADD COLUMN task_id TEXT`,
			`ALTER TABLE notifications ADD COLUMN archived_at DATETIME`,
			`ALTER TABLE notifications ADD COLUMN snoozed_until DATETIME`,
			`ALTER TABLE notifications ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0)`,
			`CREATE INDEX notifications_user_page ON notifications(recipient_user_id,id)`,
			`CREATE INDEX notifications_user_unread ON notifications(recipient_user_id,acl_root_id) WHERE read_at IS NULL AND archived_at IS NULL`,
			`CREATE TABLE command_results(actor TEXT NOT NULL,operation TEXT NOT NULL,idempotency_key TEXT NOT NULL,request_hash BLOB NOT NULL CHECK(length(request_hash)=32),result BLOB,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(actor,operation,idempotency_key))`,
			`CREATE TABLE user_audit(id INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT NOT NULL,operation TEXT NOT NULL,target TEXT NOT NULL,created_at DATETIME NOT NULL)`,
		} {
			if err := tx.Exec(q).Error; err != nil {
				return err
			}
		}
		return nil
	}}
}
