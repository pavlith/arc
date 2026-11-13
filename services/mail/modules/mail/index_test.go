package mail

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/rpc"
	v1 "github.com/pavlith/arc/services/mail/api/v1"
	"github.com/pavlith/arc/services/mail/credentials"
	"github.com/pavlith/arc/services/mail/imapclient"
	"github.com/pavlith/arc/test/imapfixture"
)

func TestIndexReconciliationNamespacesReplayAndFencing(t *testing.T) {
	s, scope, _ := fixture(t)
	info, err := s.key(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := credentials.Seal(info.PublicInfo, []byte("unique sensitive fixture password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = command(t, s, v1.SetCredentials.ID, "mail.connection.manage", "index-credential", v1.SetCredential{Scope: scope, Revision: 1, KeyID: info.KeyID, Sealed: sealed}, s.setCredentials); err != nil {
		t.Fatal(err)
	}
	server := imapfixture.New(t, "plain", map[string]string{"login": "unique sensitive fixture password"})
	// Point this isolated owner fixture at its mutable TLS server.
	if err = s.DB.Exec("UPDATE accounts SET host=?,port=? WHERE acl_root_id=?", server.Host, server.Port, scope.RootID).Error; err != nil {
		t.Fatal(err)
	}
	probe, err := imapclient.New(imapclient.Config{Endpoints: []imapclient.Endpoint{{Host: server.Host, Port: server.Port, CIDRs: []string{"127.0.0.1/32"}}}, RootCAs: server.Roots})
	if err != nil {
		t.Fatal(err)
	}
	s.Probe = probe
	wire := base64.RawURLEncoding.EncodeToString([]byte("INBOX"))
	q := v1.RefreshMessages{MessageListQuery: v1.MessageListQuery{Scope: scope, Generation: 1, MessageQuery: imapclient.MessageQuery{WireName: wire, UIDWindow: 2}}}
	refresh := func(key string) v1.RefreshResult {
		t.Helper()
		out, err := command(t, s, v1.RefreshMessageIndex.ID, "mail.read", key, q, s.refreshIndex)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	listQ := v1.CachedListQuery{Scope: scope, Generation: 1, WireName: wire, Limit: 20}
	list := func() v1.CachedList {
		t.Helper()
		ctx := invocation(t, v1.ListCachedMessages.ID, "", "", listQ)
		out, err := s.listCached(ctx, listQ)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	first := refresh("initial")
	if first.Status != "ok" || first.Upserted != 2 || first.Folder == nil || first.Folder.LowUID != 101 || first.Folder.HighUID != 102 {
		t.Fatal(first)
	}
	messages := list().Messages
	if len(messages) != 2 {
		t.Fatal(messages)
	}
	old102, old101 := messages[0].ID, messages[1].ID
	server.SetMailbox(77, []uint32{102}, true)
	second := refresh("reconcile")
	messages = list().Messages
	if second.Removed != 1 || len(messages) != 1 || messages[0].ID != old102 || len(messages[0].Flags) != 2 {
		t.Fatal(second, messages)
	}
	get := func(id string) error {
		q := v1.CachedGetQuery{Scope: scope, Generation: 1, MessageID: id}
		_, err := s.getCached(invocation(t, v1.GetCachedMessage.ID, "", "", q), q)
		return err
	}
	if rpc.ErrorCode(get(old101)) != rpc.CodeNotFound {
		t.Fatal("expunged occurrence remained readable")
	}
	server.SetMailbox(78, []uint32{101, 102}, false)
	q.UIDValidity = 77
	reset := refresh("namespace-reset")
	if reset.Status != "uidvalidity_changed" || reset.Folder == nil || reset.Folder.UIDValidity != 78 || len(list().Messages) != 0 {
		t.Fatal("namespace invalidation", reset)
	}
	q.UIDValidity = 78
	refresh("rescan")
	messages = list().Messages
	if len(messages) != 2 || messages[0].ID == old102 || messages[1].ID == old101 || rpc.ErrorCode(get(old102)) != rpc.CodeNotFound {
		t.Fatal("UID reused an old local identity", messages)
	}
	// Reopen the owner database: folder identity and its last-window cursor are durable.
	persisted := list().Folder
	var files []struct {
		Name string
		File string
	}
	if err = s.DB.Raw("PRAGMA database_list").Scan(&files).Error; err != nil {
		t.Fatal(err)
	}
	path := ""
	for _, file := range files {
		if file.Name == "main" {
			path = file.File
		}
	}
	if path == "" {
		t.Fatal("owner database missing")
	}
	_ = database.Close(s.DB)
	s.DB, err = database.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(s.DB) })
	reopened := list().Folder
	if reopened.ID != persisted.ID || reopened.Revision != persisted.Revision || reopened.NextBeforeUID != persisted.NextBeforeUID {
		t.Fatal("reopen lost durable progress", reopened, persisted)
	}
	s.Probe, _ = imapclient.New(imapclient.Config{})
	if len(list().Messages) != 2 {
		t.Fatal("local read depended on IMAP")
	}
	q.UIDValidity = 0
	replay := refresh("initial")
	if replay.Folder == nil || replay.Folder.Revision != first.Folder.Revision {
		t.Fatal("completed refresh re-fetched", replay)
	}
	s.Probe = probe
	q.UIDValidity = 78
	ctx := invocation(t, v1.RefreshMessageIndex.ID, "", "stale", q)
	if err = s.Authorize(ctx, scope.RootID, "mail.read"); err != nil {
		t.Fatal(err)
	}
	before := list().Folder.Revision
	if err = s.DB.Exec("UPDATE accounts SET revision=revision+1 WHERE acl_root_id=?", scope.RootID).Error; err != nil {
		t.Fatal(err)
	}
	if _, err = events.Command(ctx, events.Store{DB: s.DB}, s.Contract, v1.RefreshMessageIndex.ID, q, s.refreshIndex); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatal("stale staged account snapshot accepted", err)
	}
	if list().Folder.Revision != before {
		t.Fatal("stale refresh advanced the cursor")
	}
	ctx = invocation(t, v1.RefreshMessageIndex.ID, "", "stale-folder", q)
	if err = s.Authorize(ctx, scope.RootID, "mail.read"); err != nil {
		t.Fatal(err)
	}
	if err = s.DB.Exec("UPDATE mail_folders SET revision=revision+1 WHERE id=?", reopened.ID).Error; err != nil {
		t.Fatal(err)
	}
	if _, err = events.Command(ctx, events.Store{DB: s.DB}, s.Contract, v1.RefreshMessageIndex.ID, q, s.refreshIndex); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatal("stale folder snapshot accepted", err)
	}
	// The durable stage stores no encrypted credential or invocation material.
	var staged refreshStage
	if err = s.DB.First(&staged).Error; err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	if json.Unmarshal(staged.Snapshot, &data) != nil {
		t.Fatal("stage JSON")
	}
	if _, ok := data["Ciphertext"]; ok {
		t.Fatal("credential in staging")
	}
}
