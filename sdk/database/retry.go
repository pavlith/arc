package database

import (
	"context"
	"errors"
	"time"

	"github.com/mattn/go-sqlite3"
)

// RetryBusy retries a complete short write transaction after SQLite lock
// contention. Callers must restart the WHOLE transaction, not a failed SQL
// statement inside it; use unique keys to make replays deterministic.
func RetryBusy(ctx context.Context, fn func() error) error {
	if ctx == nil || fn == nil {
		return ErrInvalid
	}
	wait := 10 * time.Millisecond
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := fn()
		if err == nil || attempt >= 8 || !IsBusy(err) {
			return err
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
		if wait < 160*time.Millisecond {
			wait *= 2
		}
	}
}

// IsBusy recognizes both SQLITE_BUSY and SQLITE_LOCKED (including extended
// result codes), without fragile database error-string matching.
func IsBusy(err error) bool {
	var sqliteErr sqlite3.Error
	return errors.As(err, &sqliteErr) &&
		(sqliteErr.Code == sqlite3.ErrBusy || sqliteErr.Code == sqlite3.ErrLocked)
}
