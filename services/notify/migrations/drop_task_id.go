package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// Keep task targets only in resource_kind/resource_id after the v1 inbox migration.
// SQLite DROP COLUMN retains notification identities, indexes and delivery references.
func retireTaskID() *gormigrate.Migration {
	return &gormigrate.Migration{ID: "000005_retire_task_id", Migrate: func(tx *gorm.DB) error {
		return tx.Exec("ALTER TABLE notifications DROP COLUMN task_id").Error
	}}
}
