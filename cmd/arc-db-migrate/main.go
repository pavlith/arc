// Command arc-db-migrate runs owner-local SQLite migrations before service startup.
// Never run concurrently with another migrator or an active service process.
package main

import (
 "context"
 "errors"
 "flag"
 "fmt"
 "os"
 "os/signal"
 "syscall"

 "github.com/go-gormigrate/gormigrate/v2"
 "github.com/pavlith/arc/sdk/database"
 notifymigrations "github.com/pavlith/arc/services/notify/migrations"
 taskmigrations "github.com/pavlith/arc/services/task/migrations"
)

func migrations(owner string) ([]*gormigrate.Migration, error) {
 switch owner {
 case "task":
  return taskmigrations.SQLite(), nil
 case "notify":
  return notifymigrations.SQLite(), nil
 default:
  return nil, fmt.Errorf("unsupported SQLite migration owner %q (supported: task, notify)", owner)
 }
}

func run(ctx context.Context, owner, path string) error {
 if owner == "" || path == "" {
  return errors.New("both -service and -db are required")
 }
 steps, err := migrations(owner)
 if err != nil { return err }
 db, err := database.Open(ctx, path)
 if err != nil { return err }
 defer database.Close(db)
 if err := database.Migrate(ctx, db, steps); err != nil {
  return fmt.Errorf("migrate %s: %w", owner, err)
 }
 return nil
}

func main() {
 owner := flag.String("service", "", "SQLite owner: task or notify")
 path := flag.String("db", "", "absolute path to the owner's SQLite file")
 flag.Parse()
 ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
 defer stop()
 if err := run(ctx, *owner, *path); err != nil {
  fmt.Fprintln(os.Stderr, err)
  os.Exit(1)
 }
 fmt.Printf("%s SQLite migrations applied to %s\n", *owner, *path)
}
