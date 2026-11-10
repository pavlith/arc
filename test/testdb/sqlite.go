// Package testdb supplies migrated, isolated owner databases for guardrails.
package testdb

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/pavlith/arc/sdk/database"
	core "github.com/pavlith/arc/services/core/migrations"
	notify "github.com/pavlith/arc/services/notify/migrations"
	task "github.com/pavlith/arc/services/task/migrations"
	"gorm.io/gorm"
)

func Open(t *testing.T, owner string) (*gorm.DB, *sql.DB) {
	t.Helper()
	var migrations []*gormigrate.Migration
	switch owner {
	case "core":
		migrations = core.SQLite()
	case "task":
		migrations = task.SQLite()
	case "notify":
		migrations = notify.SQLite()
	case "fixture":
		migrations = []*gormigrate.Migration{{ID: "000001_fixture", Migrate: func(tx *gorm.DB) error {
			for _, query := range []string{
				"CREATE TABLE command_results (actor TEXT NOT NULL, operation TEXT NOT NULL, idempotency_key TEXT NOT NULL, request_hash BLOB NOT NULL, result BLOB, PRIMARY KEY(actor,operation,idempotency_key))",
				"CREATE TABLE inbox (consumer TEXT NOT NULL, event_id TEXT NOT NULL, request_hash BLOB NOT NULL, PRIMARY KEY(consumer,event_id))",
				"CREATE TABLE outbox (event_id TEXT PRIMARY KEY, subject TEXT NOT NULL, envelope TEXT NOT NULL CHECK(json_valid(envelope)), created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, published_at DATETIME)",
			} {
				if err := tx.Exec(query).Error; err != nil {
					return err
				}
			}
			return nil
		}}}
	default:
		t.Fatalf("unknown database owner %q", owner)
	}
	db, err := database.Open(context.Background(), filepath.Join(t.TempDir(), owner+".sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(db) })
	if err = database.Migrate(context.Background(), db, migrations); err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	return db, sqlDB
}

func Path(t *testing.T, db *sql.DB) string {
	t.Helper()
	var sequence int
	var name, path string
	if err := db.QueryRow("PRAGMA database_list").Scan(&sequence, &name, &path); err != nil {
		t.Fatal(err)
	}
	return path
}
