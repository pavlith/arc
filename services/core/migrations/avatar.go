package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func avatarAssets() *gormigrate.Migration {
	return &gormigrate.Migration{ID: "000014_avatar_assets", Migrate: func(tx *gorm.DB) error {
		return tx.Exec("ALTER TABLE identity_users ADD COLUMN avatar_ref TEXT CHECK(avatar_ref IS NULL OR json_valid(avatar_ref))").Error
	}}
}
