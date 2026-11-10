package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// Host facts are observations, never sources of authorization. Backfill NULL
// for existing trusted nodes; first authenticated Inventory populates them.
func runtimeHost() *gormigrate.Migration {
	return &gormigrate.Migration{ID: "000010_runtime_host", Migrate: func(tx *gorm.DB) error {
		return tx.Exec(`ALTER TABLE runtime_nodes ADD COLUMN host_inventory TEXT
			CHECK(host_inventory IS NULL OR (json_valid(host_inventory) AND json_type(host_inventory)='object'))`).Error
	}}
}
