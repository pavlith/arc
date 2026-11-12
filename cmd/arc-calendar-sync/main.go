// Command arc-calendar-sync prepares owner sync metadata after explicit migration.
// The service must be stopped; no credentials or public management API are used.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/pavlith/arc/sdk/database"
	calendar "github.com/pavlith/arc/services/calendar/modules/calendar"
)

func run(ctx context.Context, path string, reset bool) (int, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, fmt.Errorf("Calendar database must be an existing regular file")
	}
	db, err := database.Open(ctx, path)
	if err != nil {
		return 0, err
	}
	defer database.Close(db)
	return (&calendar.Module{DB: db}).BootstrapSync(ctx, reset)
}
func main() {
	path := flag.String("db", "", "absolute path to the migrated Calendar SQLite database")
	reset := flag.Bool("reset", false, "rotate all collection generations after restore or representation changes")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	count, err := run(ctx, *path, *reset)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("calendar sync roots prepared: %d\n", count)
}
