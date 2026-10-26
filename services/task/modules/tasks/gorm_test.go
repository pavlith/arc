package tasks

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
	taskmigrations "github.com/pavlith/arc/services/task/migrations"
)

func TestSQLiteTaskCreateReplayAtomicOutbox(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "task.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(db)
	if err := database.Migrate(ctx, db, taskmigrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	workspace := "00000000-0000-4000-8000-000000000001"
	root := "00000000-0000-4000-8000-000000000002"
	user := "00000000-0000-4000-8000-000000000003"
	if err := db.Exec("INSERT INTO roots(acl_root_id,workspace_id,state) VALUES(?,?,'active')", root, workspace).Error; err != nil {
		t.Fatal(err)
	}
	compiled, err := contract.Compile(taskv1.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{GormDB: db, Contract: compiled}
	auth := rpc.RemoteInvocationAuthorizer(func(context.Context, string, []byte) (security.Claims, error) {
		return security.Claims{
			Subject: "user:" + user, Operation: Create, WorkspaceID: workspace,
		}, nil
	})
	request := CreateRequest{Scope: Scope{WorkspaceID: workspace, RootID: root}, Title: "test"}
	verified := func(key string, q CreateRequest) context.Context {
		t.Helper()
		payload, _ := json.Marshal(q)
		envelope, _ := json.Marshal(map[string]any{
			"request_id": "test", "operation": Create, "proof": map[string]any{},
			"payload": json.RawMessage(payload), "idempotency_key": key,
		})
		v, err := auth(ctx, "rpc.task.v1.create", envelope)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	store := events.GormStore{DB: db}
	first, err := events.CommandGORM(verified("create-once", request), store, compiled, Create, request, svc.createGORM)
	if err != nil {
		t.Fatal(err)
	}
	second, err := events.CommandGORM(verified("create-once", request), store, compiled, Create, request, svc.createGORM)
	if err != nil || second.ID != first.ID {
		t.Fatalf("replayed different result: %+v %v", second, err)
	}
	var tasks, audits, outbox int64
	db.Table("tasks").Count(&tasks)
	db.Table("audit").Count(&audits)
	db.Table("outbox").Count(&outbox)
	if tasks != 1 || audits != 1 || outbox != 1 {
		t.Fatalf("non-atomic replay tasks=%d audit=%d outbox=%d", tasks, audits, outbox)
	}
	changed := request
	changed.Title = "different"
	if _, err := events.CommandGORM(verified("create-once", changed), store, compiled, Create, changed, svc.createGORM); err == nil {
		t.Fatal("changed request with same replay key accepted")
	}
	empty := request
	empty.Title = "   "
	if _, err := events.CommandGORM(verified("failed-create", empty), store, compiled, Create, empty, svc.createGORM); err == nil {
		t.Fatal("invalid title accepted")
	}
	if _, err := events.CommandGORM(verified("failed-create", request), store, compiled, Create, request, svc.createGORM); err != nil {
		t.Fatalf("failed reservation not rolled back: %v", err)
	}
}
