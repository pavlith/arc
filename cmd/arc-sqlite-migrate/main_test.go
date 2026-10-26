package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/pavlith/arc/sdk/database"
)

func TestOwnerMigrations(t *testing.T) {
	for _, owner := range []string{"core", "task", "notify"} {
		t.Run(owner, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), owner+".sqlite")
			if err := run(context.Background(), owner, path); err != nil {
				t.Fatal(err)
			}
			if err := run(context.Background(), owner, path); err != nil {
				t.Fatalf("repeat migration: %v", err)
			}
			db, err := database.Open(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close(db)
			if !db.Migrator().HasTable("schema_migrations") {
				t.Fatal("missing migration history")
			}
			table := "tasks"
			if owner == "notify" {
				table = "notifications"
			}
			if owner == "core" {
				table = "identity_users"
			}
			if !db.Migrator().HasTable(table) {
				t.Fatalf("missing owner table %q", table)
			}
		})
	}
}

func TestRejectUnknownMigrationOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unknown.sqlite")
	if err := run(context.Background(), "unknown", path); err == nil {
		t.Fatal("unsupported owner accepted")
	}
	if err := run(context.Background(), "task", "relative.sqlite"); err == nil {
		t.Fatal("relative path accepted")
	}
}
