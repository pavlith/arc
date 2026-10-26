package database

import (
	"context"
	"fmt"
	"regexp"

	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

var migrationID = regexp.MustCompile(`^[0-9]{6}_[a-z][a-z0-9_]*$`)

// Migrate runs an explicit, ordered set of migrations for ONE service database.
// It is meant for a standalone migrator command, never a service import/start.
// Unknown previously applied migrations fail closed to avoid schema downgrades.
// Gormigrate does not provide cross-process migration locking; the orchestrator
// must ensure only one migrator owns this database at a time.
func Migrate(ctx context.Context, db *gorm.DB, migrations []*gormigrate.Migration) error {
	if ctx == nil || ctx.Err() != nil || db == nil || len(migrations) == 0 {
		return ErrInvalid
	}
	previous := ""
	for _, m := range migrations {
		if m == nil || m.Migrate == nil || !migrationID.MatchString(m.ID) || m.ID <= previous {
			return fmt.Errorf("database: unordered, duplicated, or invalid migration after %q: %w", previous, ErrInvalid)
		}
		previous = m.ID
	}
	migrator := gormigrate.New(db.WithContext(ctx), &gormigrate.Options{
		TableName:                 "schema_migrations",
		IDColumnName:              "id",
		IDColumnSize:              255,
		UseTransaction:            true,
		ValidateUnknownMigrations: true,
	}, migrations)
	return migrator.Migrate()
}
