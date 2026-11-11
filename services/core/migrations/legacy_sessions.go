package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// Retire old dual-channel credentials without rewriting historical migrations.
// Existing users and password/recovery credentials are retained; legacy
// sessions and their refresh families become unusable before runtime rollout.
func retireLegacySessions() *gormigrate.Migration {
	return &gormigrate.Migration{ID: "000015_retire_legacy_sessions", Migrate: func(tx *gorm.DB) error {
		for _, statement := range []string{
			`UPDATE identity_refresh_families SET revoked_at=CURRENT_TIMESTAMP WHERE revoked_at IS NULL
			  AND session_id IN (SELECT id FROM identity_sessions WHERE auth_channel='legacy')`,
			`UPDATE identity_sessions SET revoked_at=CURRENT_TIMESTAMP
			  WHERE revoked_at IS NULL AND auth_channel='legacy'`,
			`CREATE TRIGGER identity_sessions_no_legacy_insert BEFORE INSERT ON identity_sessions
			  WHEN NEW.auth_channel NOT IN ('browser','cli')
			  BEGIN SELECT RAISE(ABORT,'explicit auth channel required'); END`,
			`CREATE TRIGGER identity_sessions_no_legacy_update BEFORE UPDATE OF auth_channel ON identity_sessions
			  WHEN NEW.auth_channel NOT IN ('browser','cli')
			  BEGIN SELECT RAISE(ABORT,'explicit auth channel required'); END`,
		} {
			if err := tx.Exec(statement).Error; err != nil {
				return err
			}
		}
		return nil
	}}
}
