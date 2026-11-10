package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func workspaceInvitations() *gormigrate.Migration {
	return &gormigrate.Migration{ID: "000009_workspace_invitations", Migrate: func(tx *gorm.DB) error {
		return tx.Exec(`CREATE TABLE identity_workspace_invitations (
			id TEXT PRIMARY KEY,
			workspace_id TEXT NOT NULL REFERENCES identity_workspaces(id),
			issuer_id TEXT NOT NULL REFERENCES identity_users(id),
			email TEXT NOT NULL CHECK(email=lower(email)),
			role TEXT NOT NULL CHECK(role IN ('member','guest')),
			token_hash BLOB NOT NULL UNIQUE CHECK(length(token_hash)=32),
			expires_at DATETIME NOT NULL,
			consumed_at DATETIME,
			revoked_at DATETIME
		)`).Error
	}}
}
