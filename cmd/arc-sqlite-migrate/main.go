// Command arc-sqlite-migrate applies one owner service's Gormigrate migrations.
// Run it before deploying that service, never concurrently for the same file.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/pavlith/arc/sdk/database"
	notifymigrations "github.com/pavlith/arc/services/notify/migrations"
	taskmigrations "github.com/pavlith/arc/services/task/migrations"
)

func main() {
	owner := flag.String("service", "", "service owner: task or notify")
	path := flag.String("db", "", "absolute path to service-owned SQLite file")
	flag.Parse()
	var migrations []*gormigrate.Migration
	switch *owner {
	case "task":
		migrations = taskmigrations.SQLite()
	case "notify":
		migrations = notifymigrations.SQLite()
	default:
		fmt.Fprintln(os.Stderr, "sqlite migration not supported for service; choose task or notify")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := database.Open(ctx, *path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer database.Close(db)
	if err := database.Migrate(ctx, db, migrations); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("migrations applied: %s (%s)\n", *owner, *path)
}
