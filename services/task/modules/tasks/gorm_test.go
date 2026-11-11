package tasks

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

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
	team, status := "00000000-0000-4000-8000-000000000004", "00000000-0000-4000-8000-000000000005"
	now := time.Now().UTC()
	if err := db.Exec(`INSERT INTO teams(id,workspace_id,acl_root_id,name,key,revision,created_at,updated_at)
	  VALUES(?,?,?,'Test','TEST',1,?,?)`, team, workspace, root, now, now).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO workflow_statuses(id,workspace_id,acl_root_id,team_id,name,category,is_default,revision,created_at,updated_at)
	  VALUES(?,?,?,?,'Todo','todo',1,1,?,?)`, status, workspace, root, team, now, now).Error; err != nil {
		t.Fatal(err)
	}
	svc := &Service{GormDB: db, Contract: compiled}
	auth := rpc.RemoteInvocationAuthorizer(func(context.Context, string, []byte) (security.Claims, error) {
		return security.Claims{
			Subject: "user:" + user, Operation: taskv1.WorkCreate.ID, WorkspaceID: workspace,
		}, nil
	})
	request := taskv1.WorkCreateRequest{Scope: Scope{WorkspaceID: workspace, RootID: root}, WorkInput: taskv1.WorkInput{Title: "test", TeamID: team}}
	verified := func(key string, q taskv1.WorkCreateRequest) context.Context {
		t.Helper()
		payload, _ := json.Marshal(q)
		envelope, _ := json.Marshal(map[string]any{
			"request_id": "test", "operation": taskv1.WorkCreate.ID, "proof": map[string]any{},
			"payload": json.RawMessage(payload), "idempotency_key": key,
		})
		v, err := auth(ctx, "rpc.task.v1.work.create", envelope)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	store := events.Store{DB: db}
	first, err := events.Command(verified("create-once", request), store, compiled, taskv1.WorkCreate.ID, request, svc.createWork)
	if err != nil {
		t.Fatal(err)
	}
	second, err := events.Command(verified("create-once", request), store, compiled, taskv1.WorkCreate.ID, request, svc.createWork)
	if err != nil || second.ID != first.ID {
		t.Fatalf("replayed different result: %+v %v", second, err)
	}
	var tasks, audits, outbox int64
	db.Table("tasks").Count(&tasks)
	db.Table("audit").Count(&audits)
	db.Table("outbox").Count(&outbox)
	if tasks != 1 || audits != 1 || outbox != 2 {
		t.Fatalf("non-atomic replay tasks=%d audit=%d outbox=%d", tasks, audits, outbox)
	}
	changed := request
	changed.Title = "different"
	if _, err := events.Command(verified("create-once", changed), store, compiled, taskv1.WorkCreate.ID, changed, svc.createWork); err == nil {
		t.Fatal("changed request with same replay key accepted")
	}
	empty := request
	empty.Title = "   "
	if _, err := events.Command(verified("failed-create", empty), store, compiled, taskv1.WorkCreate.ID, empty, svc.createWork); err == nil {
		t.Fatal("invalid title accepted")
	}
	if _, err := events.Command(verified("failed-create", request), store, compiled, taskv1.WorkCreate.ID, request, svc.createWork); err != nil {
		t.Fatalf("failed reservation not rolled back: %v", err)
	}
}
