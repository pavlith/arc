// Package database provides per-service SQLite connections and explicit migrations.
// It deliberately contains no business models, service wiring, or migration side effects.
package database

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var ErrInvalid = errors.New("database: invalid configuration")

// Open opens one service-owned, file-backed SQLite database. The caller must
// choose a unique absolute path for its service and owns the returned handle.
// Driver options reapply connection-local PRAGMAs after reconnects as well.
// SQLite WAL supports readers alongside one writer; it does not support multiple
// concurrent writers, so consumers must retry transient SQLITE_BUSY failures.
func Open(ctx context.Context, path string) (*gorm.DB, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(path) ||
		strings.TrimSpace(path) != path || strings.ContainsAny(path, "?\x00") ||
		strings.HasPrefix(path, "file:") || path == "" {
		return nil, ErrInvalid
	}
	if info, err := os.Stat(filepath.Dir(path)); err != nil || !info.IsDir() {
		return nil, ErrInvalid
	}
	// New databases are private to their owner, not world-readable by default.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("database: open file: %w", err)
	}
	if err = f.Close(); err != nil {
		return nil, fmt.Errorf("database: close file: %w", err)
	}
	dsn := (&url.URL{Scheme: "file", Path: path}).String() + "?_foreign_keys=on&_busy_timeout=10000&_journal_mode=WAL"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.New(log.New(os.Stderr, "", log.LstdFlags), logger.Config{
			SlowThreshold: time.Second, LogLevel: logger.Warn,
			IgnoreRecordNotFoundError: true, ParameterizedQueries: true,
		}),
	})
	if err != nil {
		return nil, fmt.Errorf("database: initialize sqlite: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	fail := func(e error) (*gorm.DB, error) {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("database: sqlite setup: %w", e)
	}
	// SQLite PRAGMA foreign_keys and busy_timeout are connection-scoped.
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	if err = sqlDB.PingContext(ctx); err != nil {
		return fail(err)
	}
	var mode string
	if err = sqlDB.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&mode); err != nil {
		return fail(err)
	}
	if !strings.EqualFold(mode, "wal") {
		return fail(errors.New("WAL journal mode unavailable"))
	}
	if _, err = sqlDB.ExecContext(ctx, "PRAGMA busy_timeout=10000"); err != nil {
		return fail(err)
	}
	if _, err = sqlDB.ExecContext(ctx, "PRAGMA foreign_keys=ON"); err != nil {
		return fail(err)
	}
	var enabled int
	if err = sqlDB.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&enabled); err != nil || enabled != 1 {
		return fail(errors.New("SQLite foreign keys not enforced"))
	}
	return db, nil
}

// Close releases a connection opened by Open.
func Close(db *gorm.DB) error {
	if db == nil {
		return nil
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
