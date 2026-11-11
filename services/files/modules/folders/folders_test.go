package folders

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/migrations"
	"gorm.io/gorm"
)

const (
	testWorkspace = "00000000-0000-4000-8000-000000000001"
	testRoot      = "00000000-0000-4000-8000-000000000002"
	otherRoot     = "00000000-0000-4000-8000-000000000003"
)

func TestFolderScopedMutationsAndOutbox(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "files.sqlite")
	db, err := database.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(db)
	if err = database.Migrate(ctx, db, migrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	if err = database.Migrate(ctx, db, migrations.SQLite()); err != nil {
		t.Fatalf("migration replay: %v", err)
	}
	compiled, err := contract.Compile(filesv1.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.Manifest.Operations) != 12 {
		t.Fatal("unexpected public Files surface")
	}
	s := &Service{GormDB: db, Contract: compiled}
	scope := filesv1.Scope{WorkspaceID: testWorkspace, RootID: testRoot}
	for _, root := range []string{testRoot, otherRoot} {
		if err := db.Exec("INSERT INTO roots(acl_root_id,workspace_id,state) VALUES(?,?,'active')",
			root, testWorkspace).Error; err != nil {
			t.Fatal(err)
		}
	}
	create := func(q filesv1.FolderCreateRequest) (filesv1.Folder, error) {
		var out filesv1.Folder
		err := db.Transaction(func(tx *gorm.DB) error {
			var err error
			out, err = s.create(ctx, tx, q)
			return err
		})
		return out, err
	}
	parent, err := create(filesv1.FolderCreateRequest{Scope: scope, Name: "Documents"})
	if err != nil {
		t.Fatal(err)
	}
	child, err := create(filesv1.FolderCreateRequest{
		Scope: scope, ParentID: parent.ID, Name: "Projects",
	})
	if err != nil {
		t.Fatal(err)
	}
	if child.ParentID != parent.ID || child.Revision != 1 {
		t.Fatal("created folder lost parent binding")
	}
	if _, err := create(filesv1.FolderCreateRequest{Scope: scope, Name: "Documents"}); err == nil {
		t.Fatal("duplicate active sibling accepted")
	}
	if _, err := create(filesv1.FolderCreateRequest{
		Scope:    filesv1.Scope{WorkspaceID: testWorkspace, RootID: otherRoot},
		ParentID: parent.ID, Name: "Cross root",
	}); err == nil {
		t.Fatal("cross-root parent accepted")
	}
	var changed filesv1.Folder
	err = db.Transaction(func(tx *gorm.DB) error {
		var err error
		changed, err = s.move(ctx, tx, filesv1.FolderMoveRequest{
			FolderRef: filesv1.FolderRef{Scope: scope, FolderID: parent.ID},
			ParentID:  child.ID, Revision: parent.Revision,
		})
		return err
	})
	if err == nil {
		t.Fatal("cycle accepted", changed)
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		_, err := s.archive(ctx, tx, filesv1.FolderArchiveRequest{
			FolderRef: filesv1.FolderRef{Scope: scope, FolderID: parent.ID},
			Revision:  parent.Revision,
		})
		return err
	})
	if err == nil {
		t.Fatal("nonempty parent archived")
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		var err error
		changed, err = s.rename(ctx, tx, filesv1.FolderRenameRequest{
			FolderRef: filesv1.FolderRef{Scope: scope, FolderID: child.ID},
			Name:      "Projects2", Revision: child.Revision,
		})
		return err
	})
	if err != nil || changed.Revision != 2 || changed.Name != "Projects2" {
		t.Fatalf("rename CAS: %+v: %v", changed, err)
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		_, err := s.rename(ctx, tx, filesv1.FolderRenameRequest{
			FolderRef: filesv1.FolderRef{Scope: scope, FolderID: child.ID},
			Name:      "stale", Revision: child.Revision,
		})
		return err
	})
	if err == nil || rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatalf("stale revision accepted: %v", err)
	}
	child = changed
	err = db.Transaction(func(tx *gorm.DB) error {
		var err error
		changed, err = s.move(ctx, tx, filesv1.FolderMoveRequest{
			FolderRef: filesv1.FolderRef{Scope: scope, FolderID: child.ID},
			Revision:  child.Revision,
		})
		return err
	})
	if err != nil || changed.ParentID != "" || changed.Revision != 3 {
		t.Fatalf("move to root: %+v %v", changed, err)
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		var err error
		changed, err = s.archive(ctx, tx, filesv1.FolderArchiveRequest{
			FolderRef: filesv1.FolderRef{Scope: scope, FolderID: parent.ID},
			Revision:  parent.Revision,
		})
		return err
	})
	if err != nil || !changed.Archived {
		t.Fatalf("archive leaf: %+v %v", changed, err)
	}
	list, err := s.list(ctx, filesv1.FolderListRequest{Scope: scope, Limit: 1})
	if err != nil || len(list.Folders) != 1 || list.Folders[0].ID != child.ID {
		t.Fatalf("active root folder list: %+v %v", list, err)
	}
	if _, err := s.get(ctx, filesv1.FolderRef{
		Scope: filesv1.Scope{WorkspaceID: testWorkspace, RootID: otherRoot}, FolderID: child.ID,
	}); rpc.ErrorCode(err) != rpc.CodeNotFound {
		t.Fatalf("known cross-root ID leaked: %v", err)
	}
	var auditCount, outboxCount int64
	if err := db.Table("audit").Count(&auditCount).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Table("outbox").Count(&outboxCount).Error; err != nil {
		t.Fatal(err)
	}
	if auditCount != 5 || outboxCount != 5 {
		t.Fatalf("transactional audit/outbox counts: %d / %d", auditCount, outboxCount)
	}
	var payload []byte
	if err := db.Raw("SELECT envelope FROM outbox ORDER BY created_at LIMIT 1").Row().Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Payload json.RawMessage `json:"payload"`
	}
	if json.Unmarshal(payload, &envelope) != nil || len(envelope.Payload) == 0 {
		t.Fatal("missing bounded event")
	}
	if err := compiled.Validate("schemas/catalog-event.json", envelope.Payload); err != nil {
		t.Fatalf("unapproved outbox event: %v", err)
	}
	if !errors.Is(s.Authorize(ctx, testRoot, "files.read"), security.ErrUnauthenticated) {
		t.Fatal("unsigned request passed Files authorization")
	}
}

func TestFolderOutboxRollback(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "files.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(db)
	if err := database.Migrate(ctx, db, migrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO roots(acl_root_id,workspace_id,state) VALUES(?,?,'active')", testRoot, testWorkspace).Error; err != nil {
		t.Fatal(err)
	}
	compiled, err := contract.Compile(filesv1.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{GormDB: db, Contract: compiled}
	if err := db.Exec("CREATE TRIGGER reject_outbox BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fixture'); END").Error; err != nil {
		t.Fatal(err)
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		_, err := s.create(ctx, tx, filesv1.FolderCreateRequest{
			Scope: filesv1.Scope{WorkspaceID: testWorkspace, RootID: testRoot}, Name: "Must roll back",
		})
		return err
	})
	if err == nil {
		t.Fatal("outbox error ignored")
	}
	var folders, audit int64
	_ = db.Table("folders").Count(&folders).Error
	_ = db.Table("audit").Count(&audit).Error
	if folders != 0 || audit != 0 {
		t.Fatalf("partial folder mutation persisted: folders=%d audit=%d", folders, audit)
	}
}
