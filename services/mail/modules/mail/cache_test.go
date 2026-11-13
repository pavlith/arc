package mail

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/mail/api/v1"
	"github.com/pavlith/arc/services/mail/credentials"
	"github.com/pavlith/arc/services/mail/imapclient"
)

func cacheInvocation(t *testing.T, subject, op, key string, q any) context.Context {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"operation": op, "auth": "fixture", "proof": security.Proof{}, "payload": q, "idempotency_key": key})
	authorize := rpc.RemoteInvocationAuthorizer(func(context.Context, string, []byte) (security.Claims, error) {
		return security.Claims{Subject: subject, SessionID: "session", Operation: op}, nil
	})
	ctx, err := authorize(context.Background(), "fixture", raw)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}
func TestCachePruneOwnerReplayIsolationAndIdentity(t *testing.T) {
	s, scope, _ := fixture(t)
	info, err := s.key(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := credentials.Seal(info.PublicInfo, []byte("unique sensitive fixture password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = command(t, s, v1.SetCredentials.ID, "mail.connection.manage", "cache-credential", v1.SetCredential{Scope: scope, Revision: 1, KeyID: info.KeyID, Sealed: sealed}, s.setCredentials); err != nil {
		t.Fatal(err)
	}
	original, err := s.root(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	otherRoot, folder, otherFolder := newID(), newID(), newID()
	if err = s.DB.Exec(`INSERT INTO accounts(acl_root_id,workspace_id,owner_id,lifecycle,name,host,port,login,email,state,revision,generation) SELECT ?,'',owner_id,'active',name,host,port,login,email,'enabled',1,1 FROM accounts WHERE acl_root_id=?`, otherRoot, scope.RootID).Error; err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct{ id, root string }{{folder, scope.RootID}, {otherFolder, otherRoot}} {
		if err = s.DB.Exec(`INSERT INTO mail_folders(id,acl_root_id,generation,wire_name,revision,uid_validity,uid_next,remote_count,next_before_uid,low_uid,high_uid,status,updated_at) VALUES(?,?,1,'SU5CT1g',3,77,103,2,101,101,102,'ok',CURRENT_TIMESTAMP)`, f.id, f.root).Error; err != nil {
			t.Fatal(err)
		}
	}
	oldIDs := []string{newID(), newID()}
	insert := func(id, folder string, uid, validity uint32, present bool) {
		message := imapclient.Message{UID: uid, InternalDate: time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC), Flags: []string{}, From: []imapclient.Address{}, To: []imapclient.Address{}, Subject: "Seed"}
		raw, _ := json.Marshal(message)
		if err = s.DB.Exec("INSERT INTO mail_messages(id,folder_id,uid_validity,uid,present,summary,internal_unix) VALUES(?,?,?,?,?,?,?)", id, folder, validity, uid, present, raw, message.InternalDate.UnixMicro()).Error; err != nil {
			t.Fatal(err)
		}
	}
	insert(oldIDs[0], folder, 101, 77, true)
	insert(oldIDs[1], folder, 102, 77, true)
	insert(newID(), folder, 101, 76, false)
	insert(newID(), otherFolder, 101, 77, true)
	if err = s.DB.Exec("INSERT INTO mail_refresh_staging(actor,idempotency_key,request_hash,acl_root_id,snapshot,created_unix) VALUES(?,'pending',zeroblob(32),?,'{}',?)", "user:"+owner, scope.RootID, time.Now().Unix()).Error; err != nil {
		t.Fatal(err)
	}
	getStatus := func() v1.CacheStatus {
		t.Helper()
		ctx := cacheInvocation(t, "user:"+owner, v1.GetCacheStatus.ID, "", scope)
		if err := s.Authorize(ctx, scope.RootID, "mail.connection.manage"); err != nil {
			t.Fatal(err)
		}
		out, err := s.cacheStatus(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	initial := getStatus()
	if initial.Usage.Messages != 3 || initial.Usage.ActiveMessages != 2 || initial.Usage.ObsoleteMessages != 1 || initial.Usage.PendingBatches != 1 || initial.Usage.Limits.SummaryBytes != indexTotalBytes {
		t.Fatal(initial)
	}
	prune := func(q v1.CachePrune, key string) (v1.CachePruned, error) {
		ctx := cacheInvocation(t, "user:"+owner, v1.PruneCache.ID, key, q)
		if err := s.Authorize(ctx, scope.RootID, "mail.connection.manage"); err != nil {
			return v1.CachePruned{}, err
		}
		return events.Command(ctx, events.Store{DB: s.DB}, s.Contract, v1.PruneCache.ID, q, s.pruneCache)
	}
	q := v1.CachePrune{Scope: scope, Revision: 2, Generation: 1, Mode: "obsolete", Limit: 1}
	// The fixture Check callback allows management; the separate owner guard must still deny.
	nonOwner := cacheInvocation(t, "user:"+newID(), v1.PruneCache.ID, "foreign", q)
	if err := s.Authorize(nonOwner, scope.RootID, "mail.connection.manage"); rpc.ErrorCode(err) != rpc.CodePermissionDenied {
		t.Fatal("non-owner manager accepted", err)
	}
	first, err := prune(q, "obsolete")
	if err != nil {
		t.Fatal(err)
	}
	if first.RemovedMessages != 1 || first.RemovedBatches != 1 || first.More || first.Revision != 3 || first.Usage.Messages != 2 || first.Usage.ActiveMessages != 2 {
		t.Fatal(first)
	}
	replay, err := prune(q, "obsolete")
	if err != nil || replay.Revision != first.Revision || getStatus().Usage.Messages != 2 {
		t.Fatal("prune replay repeated effects", replay, err)
	}
	if _, err = prune(q, "stale"); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatal("stale revision accepted", err)
	}
	var retained []string
	if err = s.DB.Model(&indexMessage{}).Where("folder_id=? AND present=1", folder).Pluck("id", &retained).Error; err != nil || len(retained) != 2 {
		t.Fatal(retained, err)
	}
	q.Revision = 3
	q.Mode = "all"
	partial, err := prune(q, "all-1")
	if err != nil || !partial.More || partial.RemovedMessages != 1 || partial.Usage.FolderBindings != 1 {
		t.Fatal(partial, err)
	}
	q.Revision = partial.Revision
	complete, err := prune(q, "all-2")
	if err != nil || complete.More || complete.RemovedMessages != 1 || complete.RemovedFolders != 1 || complete.Usage.Messages != 0 || complete.Usage.FolderBindings != 0 {
		t.Fatal(complete, err)
	}
	var count int64
	if err = s.DB.Model(&indexMessage{}).Where("folder_id=?", otherFolder).Count(&count).Error; err != nil || count != 1 {
		t.Fatal("prune crossed account", count, err)
	}
	current, err := s.root(context.Background(), scope)
	if err != nil || current.Generation != original.Generation || current.CredentialVersion != original.CredentialVersion || current.State != original.State || !bytes.Equal(current.Ciphertext, original.Ciphertext) {
		t.Fatal("cache prune changed connection/credentials", err)
	}
	if err = s.DB.Table("outbox").Count(&count).Error; err != nil || count != 4 {
		t.Fatal("non-atomic or duplicated prune events", count, err)
	}
	refresh := v1.RefreshMessages{MessageListQuery: v1.MessageListQuery{Scope: scope, Generation: 1, MessageQuery: imapclient.MessageQuery{WireName: "SU5CT1g", UIDWindow: 2}}}
	if _, err = command(t, s, v1.RefreshMessageIndex.ID, "mail.read", "reindex", refresh, s.refreshIndex); err != nil {
		t.Fatal(err)
	}
	for _, id := range oldIDs {
		get := v1.CachedGetQuery{Scope: scope, Generation: 1, MessageID: id}
		if _, err = s.getCached(invocation(t, v1.GetCachedMessage.ID, "", "", get), get); rpc.ErrorCode(err) != rpc.CodeNotFound {
			t.Fatal("forgotten UUID retargeted", err)
		}
	}
}
