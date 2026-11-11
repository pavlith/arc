package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func notifyOutbox() *gormigrate.Migration {
	return &gormigrate.Migration{ID: "000003_notify_outbox", Migrate: func(tx *gorm.DB) error {
		for _, statement := range []string{
			`CREATE TABLE outbox (
				event_id TEXT PRIMARY KEY,
				subject TEXT NOT NULL CHECK(subject='evt.notify.inbox.changed.v1'),
				envelope BLOB NOT NULL,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				published_at DATETIME)`,
			`CREATE INDEX notify_pending_outbox ON outbox(created_at,event_id) WHERE published_at IS NULL`,
		} {
			if err := tx.Exec(statement).Error; err != nil {
				return err
			}
		}
		return nil
	}}
}
