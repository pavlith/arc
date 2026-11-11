package services_test

import (
	"context"
	"testing"

	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/pavlith/arc/sdk/database"
	coremigrations "github.com/pavlith/arc/services/core/migrations"
	filesmigrations "github.com/pavlith/arc/services/files/migrations"
	notifymigrations "github.com/pavlith/arc/services/notify/migrations"
	pagesmigrations "github.com/pavlith/arc/services/pages/migrations"
	taskmigrations "github.com/pavlith/arc/services/task/migrations"
)

func TestOneBaselinePerOwnerRejectsOldHistory(t *testing.T) {
	for _, owner := range []struct {
		name       string
		migrations []*gormigrate.Migration
	}{
		{"core", coremigrations.SQLite()},
		{"task", taskmigrations.SQLite()},
		{"notify", notifymigrations.SQLite()},
		{"files", filesmigrations.SQLite()},
		{"pages", pagesmigrations.SQLite()},
	} {
		t.Run(owner.name, func(t *testing.T) {
			if len(owner.migrations) != 1 || owner.migrations[0].ID != "000001_"+owner.name+"_baseline" {
				t.Fatalf("expected only current baseline: %+v", owner.migrations)
			}
			ctx := context.Background()
			db := serviceDB(t, owner.name+"-old")
			if err := db.Exec("CREATE TABLE schema_migrations(id TEXT PRIMARY KEY)").Error; err != nil {
				t.Fatal(err)
			}
			if err := db.Exec("INSERT INTO schema_migrations(id) VALUES('000001_old_owner')").Error; err != nil {
				t.Fatal(err)
			}
			if err := database.Migrate(ctx, db, owner.migrations); err == nil {
				t.Fatal("old schema history silently initialized as a new owner database")
			}
		})
	}
}
