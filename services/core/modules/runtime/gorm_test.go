package runtime_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/migrations"
	"github.com/pavlith/arc/services/core/modules/runtime"
)

func TestRuntimeSQLiteCompareAndSwapAcrossConnections(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "core.sqlite")
	db, err := database.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(db)
	if err := database.Migrate(ctx, db, migrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	other, err := database.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(other)
	authorize := func(context.Context, string, string) error { return nil }
	first := &runtime.Module{GormDB: db, Authorize: authorize}
	second := &runtime.Module{GormDB: other, Authorize: authorize}
	desired := runtime.Desired{
		ID: "task-prod", ServiceName: "task", Spec: json.RawMessage(`{"b":2,"a":1}`), Replicas: 1,
	}
	created, err := first.Put(ctx, desired, 0)
	if err != nil || created.Revision != 1 || string(created.Spec) != `{"a":1,"b":2}` {
		t.Fatalf("create: %+v (%v)", created, err)
	}
	if _, err := second.Put(ctx, desired, 0); !errors.Is(err, runtime.ErrConflict) {
		t.Fatalf("duplicate create: %v", err)
	}
	got, err := second.Get(ctx, desired.ID)
	if err != nil || got.Revision != 1 || got.Replicas != 1 {
		t.Fatalf("read: %+v (%v)", got, err)
	}

	const concurrent = 10
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, concurrent)
	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			target := first
			if n%2 == 0 {
				target = second
			}
			want := desired
			want.Replicas = n + 2
			_, err := target.Put(ctx, want, 1)
			results <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, runtime.ErrConflict):
		default:
			t.Errorf("unexpected concurrent failure: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly one CAS winner, got %d", successes)
	}
	latest, err := first.Get(ctx, desired.ID)
	if err != nil || latest.Revision != 2 {
		t.Fatalf("monotonic revision: %+v (%v)", latest, err)
	}
	if _, err := second.Put(ctx, desired, 1); !errors.Is(err, runtime.ErrConflict) {
		t.Fatalf("stale writer succeeded: %v", err)
	}
}

func TestRuntimeSQLiteAuthorizationIsFailClosed(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "core.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(db)
	if err := database.Migrate(ctx, db, migrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	want := runtime.Desired{ID: "d", ServiceName: "task", Spec: json.RawMessage(`{}`), Replicas: 1}
	denied := &runtime.Module{GormDB: db}
	if _, err := denied.Put(ctx, want, 0); !errors.Is(err, security.ErrUnavailable) {
		t.Fatalf("missing authorizer accepted: %v", err)
	}
	denied.Authorize = func(context.Context, string, string) error { return security.ErrDenied }
	if _, err := denied.Put(ctx, want, 0); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("denied write accepted: %v", err)
	}
	if _, err := denied.Get(ctx, want.ID); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("denied read accepted: %v", err)
	}
}
