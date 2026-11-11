package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// Each enrollment ticket is pre-approved by an infrastructure administrator.
// Core stores only a domain-separated hash of the one-time secret.
func runtimeEnrollment() *gormigrate.Migration {
	return &gormigrate.Migration{ID: "000012_runtime_enrollment", Migrate: func(tx *gorm.DB) error {
		for _, query := range []string{
			`CREATE TABLE runtime_enrollment_offers (
				id TEXT PRIMARY KEY,
				node_id TEXT NOT NULL,
				service_account_id TEXT NOT NULL REFERENCES identity_service_accounts(id),
				kid TEXT NOT NULL,
				public_key BLOB NOT NULL CHECK(length(public_key)=32),
				capabilities TEXT NOT NULL CHECK(json_valid(capabilities) AND json_type(capabilities)='array'),
				token_hash TEXT NOT NULL UNIQUE CHECK(length(token_hash)=64 AND token_hash NOT GLOB '*[^0-9a-f]*'),
				approved_by TEXT NOT NULL,
				created_at DATETIME NOT NULL,
				expires_at DATETIME NOT NULL,
				redeemed_at DATETIME,
				revoked_at DATETIME,
				CHECK(expires_at>created_at),
				CHECK(redeemed_at IS NULL OR revoked_at IS NULL))`,
			`CREATE INDEX runtime_enrollment_pending
				ON runtime_enrollment_offers(node_id,service_account_id,expires_at)`,
			`CREATE TRIGGER runtime_enrollment_immutable BEFORE UPDATE ON runtime_enrollment_offers BEGIN
				SELECT CASE WHEN NEW.id IS NOT OLD.id OR NEW.node_id IS NOT OLD.node_id
					OR NEW.service_account_id IS NOT OLD.service_account_id OR NEW.kid IS NOT OLD.kid
					OR NEW.public_key IS NOT OLD.public_key OR NEW.capabilities IS NOT OLD.capabilities
					OR NEW.token_hash IS NOT OLD.token_hash OR NEW.approved_by IS NOT OLD.approved_by
					OR NEW.created_at IS NOT OLD.created_at OR NEW.expires_at IS NOT OLD.expires_at
					OR OLD.redeemed_at IS NOT NULL OR OLD.revoked_at IS NOT NULL
					OR (NEW.redeemed_at IS NULL AND NEW.revoked_at IS NULL)
					OR (NEW.redeemed_at IS NOT NULL AND NEW.revoked_at IS NOT NULL)
				THEN RAISE(ABORT,'immutable runtime enrollment offer') END; END`,
			`CREATE TRIGGER runtime_enrollment_no_delete BEFORE DELETE ON runtime_enrollment_offers BEGIN
				SELECT RAISE(ABORT,'runtime enrollment history retained'); END`,
		} {
			if err := tx.Exec(query).Error; err != nil {
				return err
			}
		}
		return nil
	}}
}
