package folders

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/migrations"
	"gorm.io/gorm"
)

func TestPersonalRootBindingAndTransactionAuthorization(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "files.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(db)
	if err := database.Migrate(ctx, db, migrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	calls := 0
	s := &Service{GormDB: db, Check: func(context.Context, string, string) error { calls++; return nil }}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PreparePersonalRoot(ctx, testRoot, testWorkspace, key, "test-key", "provider"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PreparePersonalRoot(ctx, testRoot, otherRoot, key, "test-key", "provider"); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatalf("owner changed: %v", err)
	}
	if err := s.ActivateRoot(ctx, v1.Scope{RootID: testRoot}); err != nil {
		t.Fatal(err)
	}
	verified := func(op, workspace string) context.Context {
		auth := rpc.RemoteInvocationAuthorizer(func(context.Context, string, []byte) (security.Claims, error) {
			return security.Claims{Subject: "user:owner", SessionID: "active", Operation: op, WorkspaceID: workspace}, nil
		})
		raw, _ := json.Marshal(map[string]any{"operation": op, "proof": security.Proof{Kid: "fixture"}, "auth": "fixture", "payload": v1.Scope{WorkspaceID: workspace, RootID: testRoot}})
		out, e := auth(ctx, "fixture", raw)
		if e != nil {
			t.Fatal(e)
		}
		return out
	}
	pc := verified(v1.PersonalFolderGet.ID, "")
	bounded, cancel := context.WithTimeout(pc, time.Second)
	defer cancel()
	if err := db.Transaction(func(tx *gorm.DB) error {
		return s.Authorize(database.TransactionContext(bounded, db, tx), testRoot, "files.read")
	}); err != nil {
		t.Fatalf("root auth deadlocked inside owner transaction: %v", err)
	}
	if calls != 1 {
		t.Fatalf("live ACL skipped: %d", calls)
	}
	for _, c := range []context.Context{verified(v1.FolderGet.ID, ""), verified(v1.PersonalFolderGet.ID, testWorkspace), verified(v1.FolderGet.ID, testWorkspace)} {
		if !errors.Is(s.Authorize(c, testRoot, "files.read"), security.ErrDenied) {
			t.Fatal("root kind/scope substitution passed")
		}
	}
	if calls != 1 {
		t.Fatal("invalid scope reached live ACL")
	}
}
