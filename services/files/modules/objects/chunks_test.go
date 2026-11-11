package objects

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/migrations"
	"github.com/pavlith/arc/services/files/models"
	"github.com/pavlith/arc/services/files/storage"
	"gorm.io/gorm"
)

func TestAppendChunkAuthenticatedScopedAndRecoverable(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "files.sqlite"))
	if err != nil { t.Fatal(err) }
	defer database.Close(db)
	if err := database.Migrate(ctx, db, migrations.SQLite()); err != nil { t.Fatal(err) }
	for _, rid := range []string{root, otherRoot} {
		if err := db.Exec("INSERT INTO roots(acl_root_id,workspace_id,state) VALUES(?,?,'active')",rid,workspace).Error; err != nil {t.Fatal(err)}
	}
	bytes, err := storage.OpenLocal(filepath.Join(t.TempDir(), "bytes"))
	if err != nil {t.Fatal(err)}
	defer bytes.Close()
	compiled, err := contract.Compile(filesv1.Artifact())
	if err != nil {t.Fatal(err)}
	var allow = true
	checks := 0
	s := &Module{
		DB: db, Contract: compiled, Storage: bytes,
		Authorize: func(_ context.Context, rid, action string) error {
			checks++
			if !allow || rid != root || action != "files.create" {return security.ErrDenied}
			return nil
		},
	}
	scope := filesv1.Scope{WorkspaceID: workspace, RootID: root}
	init := actorContext(t, filesv1.UploadInitiate.ID,"alice","session-a")
	var upload filesv1.Upload
	err = db.Transaction(func(tx *gorm.DB) error {
		var err error
		upload, err = s.initiate(init, tx, filesv1.UploadInitiateRequest{
			Scope:scope,Filename:"chunk.bin",MIME:"application/octet-stream",ExpectedSize:9,
		})
		return err
	})
	if err != nil {t.Fatal(err)}
	reference := filesv1.UploadRef{Scope:scope,UploadID:upload.ID}
	idctx := actorContext(t, filesv1.UploadGet.ID,"alice","session-a")
	updated, err := s.AppendChunk(idctx,reference,0,3,strings.NewReader("abc"))
	if err != nil || updated.Offset != 3 {t.Fatalf("first chunk %+v %v",updated,err)}
	var sqlOffset int64
	if err := db.Model(&models.Upload{}).Select("offset").Where("id=?",upload.ID).Scan(&sqlOffset).Error;err!=nil{t.Fatal(err)}
	if sqlOffset != 3 {t.Fatalf("SQL offset %d",sqlOffset)}
	if _, err := s.AppendChunk(idctx,reference,0,3,strings.NewReader("abc"));rpc.ErrorCode(err)!=rpc.CodeConflict {
		t.Fatalf("replayed stale offset: %v",err)
	}
	if offset,err := bytes.Offset(ctx,upload.ID);err!=nil||offset!=3{t.Fatalf("stale replay wrote %d %v",offset,err)}
	if _, err := s.AppendChunk(actorContext(t,filesv1.UploadGet.ID,"bob","session-a"),
		reference,3,3,strings.NewReader("def"));rpc.ErrorCode(err)!=rpc.CodeNotFound{
		t.Fatalf("foreign actor accepted: %v",err)
	}
	if _, err := s.AppendChunk(actorContext(t,filesv1.UploadGet.ID,"alice","session-b"),
		reference,3,3,strings.NewReader("def"));rpc.ErrorCode(err)!=rpc.CodeNotFound{
		t.Fatalf("foreign session accepted: %v",err)
	}
	if _, err := s.AppendChunk(idctx,filesv1.UploadRef{
		Scope:filesv1.Scope{WorkspaceID:workspace,RootID:otherRoot},UploadID:upload.ID,
	},3,3,strings.NewReader("def")); !errors.Is(err,security.ErrDenied){
		t.Fatalf("cross-root accepted: %v",err)
	}
	allow=false
	if _, err := s.AppendChunk(idctx,reference,3,3,strings.NewReader("def")); !errors.Is(err,security.ErrDenied){
		t.Fatalf("revoked ACL accepted: %v",err)
	}
	allow=true
	// Simulate a process crash after disk fsync, before SQL commit.
	if _,err:=bytes.Append(ctx,upload.ID,3,3,strings.NewReader("bad"));err!=nil{t.Fatal(err)}
	updated,err=s.AppendChunk(idctx,reference,3,3,strings.NewReader("def"))
	if err!=nil||updated.Offset!=6{t.Fatalf("uncommitted tail not recovered %+v %v",updated,err)}
	if size,err:=bytes.Offset(ctx,upload.ID);err!=nil||size!=6{t.Fatalf("recovered size %d %v",size,err)}
	// A failed SQL write must rewind a successful physical append.
	if err:=db.Exec("CREATE TRIGGER reject_offset BEFORE UPDATE OF offset ON uploads BEGIN SELECT RAISE(ABORT,'fixture'); END").Error;err!=nil{t.Fatal(err)}
	if _,err:=s.AppendChunk(idctx,reference,6,3,strings.NewReader("ghi"));err==nil{t.Fatal("SQL failure was accepted")}
	if size,err:=bytes.Offset(ctx,upload.ID);err!=nil||size!=6{t.Fatalf("SQL failure left bytes %d %v",size,err)}
	if err:=db.Exec("DROP TRIGGER reject_offset").Error;err!=nil{t.Fatal(err)}
	if _,err:=s.AppendChunk(idctx,reference,6,3,strings.NewReader("g"));err==nil{t.Fatal("short chunk accepted")}
	if size,err:=bytes.Offset(ctx,upload.ID);err!=nil||size!=6{t.Fatalf("short body left bytes %d %v",size,err)}
	if err:=db.Model(&models.Upload{}).Where("id=?",upload.ID).Update("expires_at",time.Now().Add(-time.Hour)).Error;err!=nil{t.Fatal(err)}
	if _,err:=s.AppendChunk(idctx,reference,6,3,strings.NewReader("ghi"));rpc.ErrorCode(err)!=rpc.CodeConflict{
		t.Fatalf("expired upload accepted: %v",err)
	}
	if checks < 8 {t.Fatalf("ACL checks were skipped: %d",checks)}
}
