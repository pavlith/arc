package calendar

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/calendar/api/v1"
)

func batchQuery(t *testing.T, s *Module, q v1.ObjectBatchQuery) (v1.ObjectBatchResult, error) {
	t.Helper()
	op := v1.MultigetObjects.ID
	if q.WorkspaceID == "" {
		op = v1.PersonalMultigetObjects.ID
	}
	ctx := invocation(t, op, q.WorkspaceID, "", q)
	if err := s.Authorize(ctx, q.RootID, "calendar.read"); err != nil {
		return v1.ObjectBatchResult{}, err
	}
	return s.multigetObjects(ctx, q)
}
func TestObjectMultigetOrderConditionsAndRootIsolation(t *testing.T) {
	s := fixture(t)
	scope := v1.Scope{WorkspaceID: ws, RootID: root}
	create := func() v1.ICalObject {
		id := newID()
		q := v1.ObjectCreate{EventRef: v1.EventRef{Scope: scope, EventID: id}, IfNoneMatch: true, Data: strings.Replace(sampleICal(), "external-uid@client.test", id+"@fixture", 1)}
		out, err := command(t, s, v1.CreateObject.ID, "calendar.create", id, q, s.createObject)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	a, b, deleted := create(), create(), create()
	if _, err := command(t, s, v1.DeleteObject.ID, "calendar.delete", "delete-batch", v1.ObjectDelete{EventRef: v1.EventRef{Scope: scope, EventID: deleted.EventID}, IfMatch: deleted.ETag}, s.deleteObject); err != nil {
		t.Fatal(err)
	}
	in := sample()
	in.Start = "2026-11-12T09:00:00.1Z"
	unsupported, err := command(t, s, v1.CreateEvent.ID, "calendar.create", "unsupported-batch", v1.Create{Scope: scope, Input: in}, s.create)
	if err != nil {
		t.Fatal(err)
	}
	missing := newID()
	q := v1.ObjectBatchQuery{Scope: scope, Objects: []v1.ObjectBatchTarget{{EventID: b.EventID, KnownETag: b.ETag}, {EventID: missing}, {EventID: a.EventID}, {EventID: deleted.EventID}, {EventID: unsupported.ID}}}
	out, err := batchQuery(t, s, q)
	if err != nil || !out.Complete || len(out.Items) != 5 {
		t.Fatalf("batch: %+v %v", out, err)
	}
	expected := []string{"not_modified", "not_found", "ok", "not_found", "unsupported"}
	for i, item := range out.Items {
		if item.EventID != q.Objects[i].EventID || item.Status != expected[i] {
			t.Fatal("batch changed request order/status", i, item)
		}
		if item.Status != "ok" && item.Data != "" {
			t.Fatal("non-content status leaked data", item.Status)
		}
		if item.Status == "not_found" && (item.UID != "" || item.Revision != 0 || item.ETag != "") {
			t.Fatal("hidden object metadata leaked")
		}
	}
	if out.Items[2].Data != a.Data || out.Items[2].ETag != a.ETag {
		t.Fatal("batch representation differs from object GET")
	}
	// A known event outside this permitted root is exactly a not_found result.
	otherRoot := newID()
	if err = s.DB.Exec("INSERT INTO roots(acl_root_id,workspace_id,owner_id,state,name,timezone,revision,sync_epoch,sync_ready) VALUES(?,?,'','active','Other','UTC',1,?,1)", otherRoot, ws, strings.Repeat("c", 32)).Error; err != nil {
		t.Fatal(err)
	}
	foreign := v1.ObjectBatchQuery{Scope: v1.Scope{WorkspaceID: ws, RootID: otherRoot}, Objects: []v1.ObjectBatchTarget{{EventID: a.EventID}, {EventID: missing}}}
	hidden, err := batchQuery(t, s, foreign)
	if err != nil || len(hidden.Items) != 2 || hidden.Items[0].Status != "not_found" || hidden.Items[0].UID != "" {
		t.Fatal("cross-root batch disclosed object", hidden, err)
	}
	s.Check = func(_ context.Context, _ string, action string) error {
		if action == "calendar.free_busy" {
			return nil
		}
		return security.ErrDenied
	}
	if _, err = batchQuery(t, s, q); !errors.Is(err, security.ErrDenied) {
		t.Fatal("cache hint bypassed current read permission", err)
	}
	s.Check = func(context.Context, string, string) error { return security.ErrUnavailable }
	if _, err = batchQuery(t, s, q); !errors.Is(err, security.ErrUnavailable) {
		t.Fatal("authority outage did not fail closed", err)
	}
}
func TestObjectMultigetBudgetContinuationAndValidation(t *testing.T) {
	s := fixture(t)
	scope := v1.Scope{WorkspaceID: ws, RootID: root}
	targets := []v1.ObjectBatchTarget{}
	for i := 0; i < 4; i++ {
		id := newID()
		raw := strings.Replace(sampleICal(), "external-uid@client.test", id+"@fixture", 1)
		raw = strings.Replace(raw, "X-CLIENT;", "X-PADDING:"+strings.Repeat("x", 60000)+"\r\nX-CLIENT;", 1)
		obj, err := command(t, s, v1.CreateObject.ID, "calendar.create", id, v1.ObjectCreate{EventRef: v1.EventRef{Scope: scope, EventID: id}, IfNoneMatch: true, Data: raw}, s.createObject)
		if err != nil {
			t.Fatal(err)
		}
		targets = append(targets, v1.ObjectBatchTarget{EventID: obj.EventID})
	}
	collected := []string{}
	offset := 0
	pages := 0
	for {
		page, err := batchQuery(t, s, v1.ObjectBatchQuery{Scope: scope, Objects: targets, Offset: offset})
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(page)
		if len(encoded) > maxObjectBatchBytes {
			t.Fatal("batch exceeded serialized budget", len(encoded))
		}
		for _, item := range page.Items {
			if item.Status != "ok" {
				t.Fatal(item.Status)
			}
			collected = append(collected, item.EventID)
		}
		pages++
		if page.Complete {
			break
		}
		if page.NextIndex <= offset || page.NextIndex >= len(targets) {
			t.Fatal("continuation did not progress", page.NextIndex)
		}
		offset = page.NextIndex
	}
	if pages < 2 || len(collected) != len(targets) {
		t.Fatal("budget did not split complete result", pages, len(collected))
	}
	for i, id := range collected {
		if id != targets[i].EventID {
			t.Fatal("continuation lost/repeated target")
		}
	}
	for _, q := range []v1.ObjectBatchQuery{
		{Scope: scope},
		{Scope: scope, Objects: targets, Offset: -1},
		{Scope: scope, Objects: targets, Offset: len(targets)},
		{Scope: scope, Objects: []v1.ObjectBatchTarget{targets[0], targets[0]}},
		{Scope: scope, Objects: []v1.ObjectBatchTarget{{EventID: targets[0].EventID, KnownETag: "*"}}},
		{Scope: scope, Objects: []v1.ObjectBatchTarget{{EventID: "not-a-uuid"}}},
	} {
		if _, err := batchQuery(t, s, q); rpc.ErrorCode(err) != rpc.CodeValidation {
			t.Fatal("invalid batch accepted", q, err)
		}
	}
}
