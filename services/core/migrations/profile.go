package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func profileSettings() *gormigrate.Migration {
	return &gormigrate.Migration{ID: "000013_profile_settings", Migrate: func(tx *gorm.DB) error {
		for _, q := range []string{
			`ALTER TABLE identity_users ADD COLUMN name TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE identity_users ADD COLUMN display_name TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE identity_users ADD COLUMN profile_revision INTEGER NOT NULL DEFAULT 1 CHECK(profile_revision>0)`,
			`UPDATE identity_users SET name=substr(email,1,instr(email,'@')-1),display_name=substr(email,1,instr(email,'@')-1)`,
			`ALTER TABLE identity_workspaces ADD COLUMN slug TEXT`,
			`UPDATE identity_workspaces SET slug=id`,
			`CREATE UNIQUE INDEX identity_workspace_slug ON identity_workspaces(COALESCE(slug,id))`,
			`CREATE TABLE identity_user_preferences(user_id TEXT PRIMARY KEY REFERENCES identity_users(id),data TEXT NOT NULL CHECK(json_valid(data)),revision INTEGER NOT NULL CHECK(revision>0),updated_at DATETIME NOT NULL)`,
		} {
			if err := tx.Exec(q).Error; err != nil {
				return err
			}
		}
		return nil
	}}
}
