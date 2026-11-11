package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// Profiles are immutable approved declarations and never execution permits.
func runtimeNodeProfiles() *gormigrate.Migration {
	return &gormigrate.Migration{ID: "000011_runtime_node_profiles", Migrate: func(tx *gorm.DB) error {
		for _, query := range []string{
			`CREATE TABLE runtime_node_profiles (
				node_id TEXT NOT NULL REFERENCES runtime_nodes(id),
				id TEXT NOT NULL,
				revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
				spec TEXT NOT NULL CHECK(json_valid(spec) AND json_type(spec)='object'),
				digest TEXT NOT NULL CHECK(length(digest)=64 AND digest NOT GLOB '*[^0-9a-f]*'),
				revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
				approved_by TEXT NOT NULL,
				created_at DATETIME NOT NULL,
				PRIMARY KEY(node_id,id,revision),
				CHECK(json_extract(spec,'$.id') IS id AND json_extract(spec,'$.revision') IS revision))`,
			`CREATE INDEX runtime_node_profiles_latest ON runtime_node_profiles(node_id,id,revision DESC)`,
			`CREATE TRIGGER runtime_node_profiles_immutable BEFORE UPDATE ON runtime_node_profiles BEGIN
			   SELECT CASE WHEN NEW.node_id IS NOT OLD.node_id OR NEW.id IS NOT OLD.id
				OR NEW.revision IS NOT OLD.revision OR NEW.spec IS NOT OLD.spec
				OR NEW.digest IS NOT OLD.digest OR NEW.approved_by IS NOT OLD.approved_by
				OR NEW.created_at IS NOT OLD.created_at OR OLD.revoked=1
				OR NEW.revoked IS NOT 1
			   THEN RAISE(ABORT,'immutable runtime node profile') END; END`,
			`CREATE TRIGGER runtime_node_profiles_no_delete BEFORE DELETE ON runtime_node_profiles BEGIN
			   SELECT RAISE(ABORT,'node profile deletion forbidden'); END`,
		} {
			if err := tx.Exec(query).Error; err != nil {
				return err
			}
		}
		return nil
	}}
}
