package calendar

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/calendar/api/v1"
	"github.com/pavlith/arc/services/calendar/models"
)

func syncQuery(t *testing.T, s *Module, q v1.SyncQuery) (v1.SyncResult, error) {
	t.Helper()
	op := v1.SyncCollection.ID
	if q.WorkspaceID == "" {
		op = v1.PersonalSyncCollection.ID
	}
	ctx := invocation(t, op, q.WorkspaceID, "", q)
	if err := s.Authorize(ctx, q.RootID, "calendar.read"); err != nil {
		return v1.SyncResult{}, err
	}
	return s.syncCollection(ctx, q)
}
func syncMust(t *testing.T, s *Module, q v1.SyncQuery) v1.SyncResult {
	t.Helper()
	page, err := syncQuery(t, s, q)
	if err != nil {
		t.Fatal(err)
	}
	return page
}
func rootHead(t *testing.T, s *Module) models.Root {
	t.Helper()
	var r models.Root
	if err := s.DB.Where("acl_root_id=?", root).Take(&r).Error; err != nil {
		t.Fatal(err)
	}
	return r
}
func TestSyncFrozenFullAndDeltaPagination(t *testing.T) {
	s := fixture(t)
	scope := v1.Scope{WorkspaceID: ws, RootID: root}
	empty := syncMust(t, s, v1.SyncQuery{Scope: scope, Limit: 1})
	if !empty.Complete || empty.Token == "" || len(empty.Items) != 0 {
		t.Fatal(empty)
	}
	create := func(suffix string) v1.ICalObject {
		id := "40000000-0000-4000-8000-0000000000" + suffix
		q := v1.ObjectCreate{EventRef: v1.EventRef{Scope: scope, EventID: id}, IfNoneMatch: true, Data: strings.Replace(sampleICal(), "external-uid@client.test", id+"@client.test", 1)}
		out, err := command(t, s, v1.CreateObject.ID, "calendar.create", "create-sync-"+suffix, q, s.createObject)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	a, b, c := create("10"), create("20"), create("30")
	first := syncMust(t, s, v1.SyncQuery{Scope: scope, Limit: 1})
	if first.Complete || first.Token != "" || first.Cursor == "" || len(first.Items) != 1 || first.Items[0].EventID != a.EventID {
		t.Fatal(first)
	}
	update := func(obj v1.ICalObject, key string) v1.ICalObject {
		q := v1.ObjectUpdate{EventRef: v1.EventRef{Scope: scope, EventID: obj.EventID}, IfMatch: obj.ETag, Data: strings.Replace(obj.Data, "opaque", "opaque-"+key, 1)}
		out, err := command(t, s, v1.UpdateObject.ID, "calendar.write", key, q, s.updateObject)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	remove := func(obj v1.ICalObject, key string) {
		_, err := command(t, s, v1.DeleteObject.ID, "calendar.delete", key, v1.ObjectDelete{EventRef: v1.EventRef{Scope: scope, EventID: obj.EventID}, IfMatch: obj.ETag}, s.deleteObject)
		if err != nil {
			t.Fatal(err)
		}
	}
	b2 := update(b, "b2")
	remove(c, "delete-c")
	d := create("25")
	remove(a, "delete-a")
	second := syncMust(t, s, v1.SyncQuery{Scope: scope, Cursor: first.Cursor, Limit: 1})
	if len(second.Items) != 1 || second.Items[0].EventID != b.EventID || second.Items[0].ETag != b.ETag || second.Items[0].Revision != 1 || second.Complete {
		t.Fatal("full page moved beyond frozen watermark", second)
	}
	third := syncMust(t, s, v1.SyncQuery{Scope: scope, Cursor: second.Cursor, Limit: 1})
	if !third.Complete || third.Token == "" || len(third.Items) != 1 || third.Items[0].EventID != c.EventID || third.Items[0].State != "active" {
		t.Fatal("full page lost a later-deleted object or included new resource", third)
	}
	delta1 := syncMust(t, s, v1.SyncQuery{Scope: scope, Token: third.Token, Limit: 2})
	if delta1.Complete || len(delta1.Items) != 2 || delta1.Items[0].EventID != b.EventID || delta1.Items[0].ETag != b2.ETag || delta1.Items[1].State != "deleted" {
		t.Fatal("delta snapshot mismatch", delta1)
	}
	b3 := update(b2, "b3")
	d2 := update(d, "d2")
	e := create("40")
	remove(d2, "delete-d")
	delta2 := syncMust(t, s, v1.SyncQuery{Scope: scope, Cursor: delta1.Cursor, Limit: 2})
	if !delta2.Complete || len(delta2.Items) != 2 || delta2.Items[0].EventID != d.EventID || delta2.Items[0].ETag != d.ETag || delta2.Items[1].EventID != a.EventID || delta2.Items[1].State != "deleted" {
		t.Fatal("delta cursor included later changes", delta2)
	}
	caught := syncMust(t, s, v1.SyncQuery{Scope: scope, Token: delta2.Token, Limit: 100})
	if !caught.Complete || len(caught.Items) != 3 || caught.Items[0].EventID != b3.EventID || caught.Items[0].ETag != b3.ETag || caught.Items[1].EventID != e.EventID || caught.Items[2].EventID != d.EventID || caught.Items[2].State != "deleted" {
		t.Fatal("delta failed to coalesce changes", caught)
	}
	idle := syncMust(t, s, v1.SyncQuery{Scope: scope, Token: caught.Token, Limit: 100})
	if !idle.Complete || idle.Token != caught.Token || len(idle.Items) != 0 {
		t.Fatal(idle)
	}
	fresh := syncMust(t, s, v1.SyncQuery{Scope: scope, Limit: 100})
	if len(fresh.Items) != 2 {
		t.Fatal("fresh sync included tombstones", fresh)
	}
}
func TestSyncReplayRollbackScopeExpiryAndReset(t *testing.T) {
	s := fixture(t)
	scope := v1.Scope{WorkspaceID: ws, RootID: root}
	empty := syncMust(t, s, v1.SyncQuery{Scope: scope, Limit: 10})
	q := v1.Create{Scope: scope, Input: sample()}
	event, err := command(t, s, v1.CreateEvent.ID, "calendar.create", "sync-create", q, s.create)
	if err != nil {
		t.Fatal(err)
	}
	head := rootHead(t, s)
	if _, err = command(t, s, v1.CreateEvent.ID, "calendar.create", "sync-create", q, s.create); err != nil || rootHead(t, s).SyncRevision != head.SyncRevision {
		t.Fatal("replay advanced sync", err)
	}
	baseline := syncMust(t, s, v1.SyncQuery{Scope: scope, Token: empty.Token, Limit: 10})
	if len(baseline.Items) != 1 || baseline.Items[0].EventID != event.ID {
		t.Fatal(baseline)
	}
	s.DB.Exec("CREATE TRIGGER deny_sync_outbox BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fixture'); END")
	update := v1.Update{EventRef: v1.EventRef{Scope: scope, EventID: event.ID}, Input: sample(), Revision: 1}
	update.Title = "Rollback"
	if _, err = command(t, s, v1.UpdateEvent.ID, "calendar.write", "sync-rollback", update, s.update); err == nil {
		t.Fatal("failed outbox committed")
	}
	if rootHead(t, s).SyncRevision != head.SyncRevision {
		t.Fatal("failed command advanced sync head")
	}
	unchanged := syncMust(t, s, v1.SyncQuery{Scope: scope, Token: baseline.Token, Limit: 10})
	if len(unchanged.Items) != 0 {
		t.Fatal("failed command leaked sync item", unchanged)
	}
	s.DB.Exec("DROP TRIGGER deny_sync_outbox")
	// Exercise retention without 10000 real renders/network commands.
	if err = s.DB.Exec(`WITH RECURSIVE seq(n) AS (SELECT 2 UNION ALL SELECT n+1 FROM seq WHERE n<10000)
 INSERT INTO sync_changes(workspace_id,acl_root_id,sequence,event_id,previous,entry)
 SELECT ?,?,n,?,i.entry,i.entry FROM seq CROSS JOIN sync_items i WHERE i.workspace_id=? AND i.acl_root_id=? AND i.event_id=?`, ws, root, event.ID, ws, root, event.ID).Error; err != nil {
		t.Fatal(err)
	}
	s.DB.Exec("UPDATE roots SET sync_revision=10000 WHERE acl_root_id=?", root)
	s.DB.Exec("UPDATE sync_items SET sequence=10000 WHERE event_id=?", event.ID)
	if _, err = command(t, s, v1.UpdateEvent.ID, "calendar.write", "sync-prune", update, s.update); err != nil {
		t.Fatal(err)
	}
	var n int64
	s.DB.Table("sync_changes").Where("acl_root_id=?", root).Count(&n)
	if n != syncHistoryLimit || rootHead(t, s).SyncFloor != 1 {
		t.Fatal("history not bounded", n)
	}
	if _, err = syncQuery(t, s, v1.SyncQuery{Scope: scope, Token: empty.Token, Limit: 10}); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatal("expired token accepted", err)
	}
	if _, err = syncQuery(t, s, v1.SyncQuery{Scope: scope, Token: baseline.Token, Limit: 10}); err != nil {
		t.Fatal("floor boundary token rejected", err)
	}
	h := rootHead(t, s)
	ref := syncRef(h)
	for _, mutate := range []func(*syncReference){func(r *syncReference) { r.RootID = newID() }, func(r *syncReference) { r.WorkspaceID = newID() }, func(r *syncReference) { r.Epoch = strings.Repeat("b", 32) }, func(r *syncReference) { r.Revision++ }} {
		bad := ref
		mutate(&bad)
		if _, err = syncQuery(t, s, v1.SyncQuery{Scope: scope, Token: syncEncode(syncTokenPrefix, bad), Limit: 10}); rpc.ErrorCode(err) != rpc.CodeConflict {
			t.Fatal("forged scope/future token accepted", err)
		}
	}
	incomplete := syncCursorPrefix + base64.RawURLEncoding.EncodeToString([]byte(`{"mode":"full","after_id":"`+event.ID+`"}`))
	if _, err = syncQuery(t, s, v1.SyncQuery{Scope: scope, Cursor: incomplete, Limit: 10}); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatal("cursor defaulted missing scope", err)
	}
	s.Check = func(_ context.Context, _ string, action string) error {
		if action == "calendar.free_busy" {
			return nil
		}
		return security.ErrDenied
	}
	if _, err = syncQuery(t, s, v1.SyncQuery{Scope: scope, Token: baseline.Token, Limit: 10}); !errors.Is(err, security.ErrDenied) {
		t.Fatal("free_busy read sync metadata", err)
	}
	s.Check = func(context.Context, string, string) error { return security.ErrUnavailable }
	if _, err = syncQuery(t, s, v1.SyncQuery{Scope: scope, Limit: 10}); !errors.Is(err, security.ErrUnavailable) {
		t.Fatal("authority outage did not fail closed", err)
	}
	s.Check = func(context.Context, string, string) error { return nil }
	old := syncMust(t, s, v1.SyncQuery{Scope: scope, Limit: 100})
	if err = s.DB.Exec("CREATE TRIGGER deny_bootstrap BEFORE INSERT ON sync_items BEGIN SELECT RAISE(ABORT,'fixture'); END").Error; err != nil {
		t.Fatal(err)
	}
	if err = s.RebuildSync(context.Background(), scope); err == nil {
		t.Fatal("failed reset committed")
	}
	if rootHead(t, s).SyncEpoch != h.SyncEpoch || !rootHead(t, s).SyncReady {
		t.Fatal("failed reset invalidated existing generation")
	}
	if _, err = syncQuery(t, s, v1.SyncQuery{Scope: scope, Token: old.Token, Limit: 100}); err != nil {
		t.Fatal("failed reset lost valid sync state", err)
	}
	if err = s.DB.Exec("DROP TRIGGER deny_bootstrap").Error; err != nil {
		t.Fatal(err)
	}
	if err = s.RebuildSync(context.Background(), scope); err != nil {
		t.Fatal("offline reset", err)
	}
	if _, err = syncQuery(t, s, v1.SyncQuery{Scope: scope, Token: old.Token, Limit: 100}); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatal("pre-reset token accepted", err)
	}
	after := syncMust(t, s, v1.SyncQuery{Scope: scope, Limit: 100})
	if len(after.Items) != 1 || after.Items[0].Revision != 2 {
		t.Fatal("reset lost current baseline", after)
	}
	if count, err := s.BootstrapSync(context.Background(), false); err != nil || count != 0 {
		t.Fatal("bootstrap not idempotent", count, err)
	}
}
func TestSyncUnsupportedObjectsAndOpaqueETag(t *testing.T) {
	s := fixture(t)
	scope := v1.Scope{WorkspaceID: ws, RootID: root}
	if err := s.DB.Exec("UPDATE roots SET sync_ready=0 WHERE acl_root_id=?", root).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := syncQuery(t, s, v1.SyncQuery{Scope: scope, Limit: 10}); rpc.ErrorCode(err) != rpc.CodeUnavailable {
		t.Fatal("unprepared legacy root issued a sync token", err)
	}
	input := sample()
	input.Start = "2026-11-12T09:00:00.1Z"
	unsupported, err := command(t, s, v1.CreateEvent.ID, "calendar.create", "subsecond-sync", v1.Create{Scope: scope, Input: input}, s.create)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := s.BootstrapSync(context.Background(), false); err != nil || count != 1 {
		t.Fatal("legacy root bootstrap", count, err)
	}
	page := syncMust(t, s, v1.SyncQuery{Scope: scope, Limit: 10})
	if len(page.Items) != 1 || page.Items[0].EventID != unsupported.ID || page.Items[0].State != "unsupported" || page.Items[0].ETag != "" {
		t.Fatal("non-exportable object hidden", page)
	}
	ref := v1.EventRef{Scope: scope, EventID: newID()}
	imported, err := command(t, s, v1.CreateObject.ID, "calendar.create", "sync-import", v1.ObjectCreate{EventRef: ref, IfNoneMatch: true, Data: sampleICal()}, s.createObject)
	if err != nil {
		t.Fatal(err)
	}
	start := syncMust(t, s, v1.SyncQuery{Scope: scope, Limit: 100})
	updated, err := command(t, s, v1.UpdateObject.ID, "calendar.write", "sync-opaque-update", v1.ObjectUpdate{EventRef: ref, IfMatch: imported.ETag, Data: strings.Replace(sampleICal(), "opaque", "changed-opaque", 1)}, s.updateObject)
	if err != nil {
		t.Fatal(err)
	}
	delta := syncMust(t, s, v1.SyncQuery{Scope: scope, Token: start.Token, Limit: 10})
	if len(delta.Items) != 1 || delta.Items[0].ETag != updated.ETag {
		t.Fatal("sync snapped stale opaque object data", delta)
	}
}
