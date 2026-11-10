// Command arc-sqlite-migrate applies one owner's versioned SQLite migrations.
// Run it before deploying the service, never concurrently for the same file.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/pavlith/arc/sdk/database"
	coremigrations "github.com/pavlith/arc/services/core/migrations"
	notifymigrations "github.com/pavlith/arc/services/notify/migrations"
	taskmigrations "github.com/pavlith/arc/services/task/migrations"
)

func ownerMigrations(owner string) ([]*gormigrate.Migration, error) {
	switch owner {
	case "core":
		return coremigrations.SQLite(), nil
	case "task":
		return taskmigrations.SQLite(), nil
	case "notify":
		return notifymigrations.SQLite(), nil
	default:
		return nil, fmt.Errorf("unsupported SQLite owner %q (core, task, notify)", owner)
	}
}

func run(ctx context.Context, owner, path string) error {
	if owner == "" || path == "" {
		return fmt.Errorf("service and SQLite path are required")
	}
	migrations, err := ownerMigrations(owner)
	if err != nil {
		return err
	}
	db, err := database.Open(ctx, path)
	if err != nil {
		return err
	}
	defer database.Close(db)
	return database.Migrate(ctx, db, migrations)
}

func main() {
	owner := flag.String("service", "", "SQLite service owner: core, task or notify")
	path := flag.String("db", "", "absolute path to the service-owned SQLite file")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := run(ctx, *owner, *path); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("migrations applied: %s (%s)\n", *owner, *path)
}
