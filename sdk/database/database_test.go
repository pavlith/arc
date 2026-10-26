package database_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/pavlith/arc/sdk/database"
	"gorm.io/gorm"
)

func open(t *testing.T, name string) *gorm.DB {
	t.Helper()
	db, err := database.Open(context.Background(), filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(db) })
	return db
}

func TestOpenRequiresPrivateFileBackedOwner(t *testing.T) {
	if _, err := database.Open(context.Background(), ":memory:"); !errors.Is(err, database.ErrInvalid) {
		t.Fatalf("memory database accepted: %v", err)
	}
	if _, err := database.Open(context.Background(), "shared.sqlite"); !errors.Is(err, database.ErrInvalid) {
		t.Fatalf("relative path accepted: %v", err)
	}
	db := open(t, "core.sqlite")
	sqlDB, _ := db.DB()
	var mode string
	if err := sqlDB.QueryRowContext(context.Background(), "PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("expected WAL, got %q: %v", mode, err)
	}
	var foreignKeys, busyTimeout int
	if err := sqlDB.QueryRowContext(context.Background(), "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil || foreignKeys != 1 {
		t.Fatalf("foreign keys disabled: %d (%v)", foreignKeys, err)
	}
	if err := sqlDB.QueryRowContext(context.Background(), "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil || busyTimeout != 10000 {
		t.Fatalf("busy timeout: %d (%v)", busyTimeout, err)
	}
}

func TestConnectionReplacementKeepsPragmas(t *testing.T) {
	db := open(t, "owner #1%.sqlite")
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	// Force each statement to open a new physical connection.
	sqlDB.SetMaxIdleConns(0)
	for i := 0; i < 3; i++ {
		var enabled, timeout int
		if err := sqlDB.QueryRow("PRAGMA foreign_keys").Scan(&enabled); err != nil || enabled != 1 {
			t.Fatalf("replacement connection disabled foreign keys: %d %v", enabled, err)
		}
		if err := sqlDB.QueryRow("PRAGMA busy_timeout").Scan(&timeout); err != nil || timeout != 10000 {
			t.Fatalf("replacement connection lost busy timeout: %d %v", timeout, err)
		}
	}
}

func TestMigrateVersionedAndTransactional(t *testing.T) {
	ctx := context.Background()
	db := open(t, "task.sqlite")
	migrations := []*gormigrate.Migration{
		{ID: "000001_create", Migrate: func(tx *gorm.DB) error {
			return tx.Exec("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL)").Error
		}},
		{ID: "000002_seed", Migrate: func(tx *gorm.DB) error {
			return tx.Exec("INSERT INTO items(id,name) VALUES(1,?)", "first").Error
		}},
	}
	if err := database.Migrate(ctx, db, migrations); err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx, db, migrations); err != nil {
		t.Fatalf("idempotent rerun: %v", err)
	}
	var count int64
	if err := db.Table("items").Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("unexpected rows: %d (%v)", count, err)
	}
	changed := []*gormigrate.Migration{{ID: "000001_create", Migrate: migrations[0].Migrate}}
	if err := database.Migrate(ctx, db, changed); err == nil {
		t.Fatal("unknown migration accepted")
	}
	rollback := append(migrations, &gormigrate.Migration{
		ID: "000003_failed", Migrate: func(tx *gorm.DB) error {
			if err := tx.Exec("INSERT INTO items(id,name) VALUES(2,'rolled back')").Error; err != nil {
				return err
			}
			return errors.New("induced failure")
		},
	})
	if err := database.Migrate(ctx, db, rollback); err == nil {
		t.Fatal("failed migration accepted")
	}
	if err := db.Table("items").Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("failed migration committed writes: %d (%v)", count, err)
	}
}

func TestSeparateServiceDatabases(t *testing.T) {
	core := open(t, "core.sqlite")
	task := open(t, "task.sqlite")
	if err := core.Exec("CREATE TABLE only_core (id INTEGER PRIMARY KEY)").Error; err != nil {
		t.Fatal(err)
	}
	if task.Migrator().HasTable("only_core") {
		t.Fatal("another service's table was visible")
	}
}
