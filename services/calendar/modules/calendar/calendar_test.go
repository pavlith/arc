package calendar

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/calendar/api/v1"
	"github.com/pavlith/arc/services/calendar/migrations"
	"github.com/pavlith/arc/services/calendar/models"
	"gorm.io/gorm"
)

const ws = "40000000-0000-4000-8000-000000000001"
const root = "40000000-0000-4000-8000-000000000002"

func fixture(t *testing.T) *Module {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "calendar.sqlite")
	db, err := database.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err = database.Migrate(ctx, db, migrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	if err = database.Close(db); err != nil {
		t.Fatal(err)
	}
	db, err = database.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close(db) })
	if err = database.Migrate(ctx, db, migrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	if err = db.Create(&models.Root{RootID: root, WorkspaceID: ws, State: "active", SyncEpoch: strings.Repeat("a", 32), SyncReady: true, Name: "Work", Timezone: "Europe/Moscow", Revision: 1}).Error; err != nil {
		t.Fatal(err)
	}
	compiled, err := contract.Compile(v1.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	return &Module{DB: db, Contract: compiled, Check: func(context.Context, string, string) error { return nil }}
}
func invocation(t *testing.T, op, workspace, key string, q any) context.Context {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"operation": op, "proof": security.Proof{}, "auth": "fixture", "payload": q, "idempotency_key": key})
	auth := rpc.RemoteInvocationAuthorizer(func(context.Context, string, []byte) (security.Claims, error) {
		return security.Claims{Subject: "user:reader", SessionID: "session", Operation: op, WorkspaceID: workspace}, nil
	})
	ctx, err := auth(context.Background(), "fixture", raw)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}
func command[Q, R any](t *testing.T, s *Module, op, action, key string, q Q, fn func(context.Context, *gorm.DB, Q) (R, error)) (R, error) {
	t.Helper()
	var zero R
	raw, _ := json.Marshal(q)
	var scope v1.Scope
	json.Unmarshal(raw, &scope)
	ctx := invocation(t, op, scope.WorkspaceID, key, q)
	spec, err := s.Contract.Operation(op)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Contract.Validate(spec.RequestSchema, raw); err != nil {
		return zero, err
	}
	if err = s.Authorize(ctx, scope.RootID, action); err != nil {
		return zero, err
	}
	return events.Command(ctx, events.Store{DB: s.DB}, s.Contract, op, q, fn)
}
func sample() v1.Input {
	return v1.Input{Title: "Private appointment", Description: "Confidential", Timezone: "Europe/Moscow", Start: "2026-11-12T12:00:00+03:00", End: "2026-11-12T13:00:00+03:00", Busy: true}
}
func TestCalendarCRUDCASReplayRollbackAndScope(t *testing.T) {
	s := fixture(t)
	scope := v1.Scope{WorkspaceID: ws, RootID: root}
	q := v1.Create{Scope: scope, Input: sample()}
	created, err := command(t, s, v1.CreateEvent.ID, "calendar.create", "create", q, s.create)
	if err != nil {
		t.Fatal(err)
	}
	if created.Start != "2026-11-12T09:00:00Z" || created.Revision != 1 {
		t.Fatal(created)
	}
	replay, err := command(t, s, v1.CreateEvent.ID, "calendar.create", "create", q, s.create)
	if err != nil || replay.ID != created.ID {
		t.Fatalf("replay: %+v %v", replay, err)
	}
	mismatch := q
	mismatch.Title = "changed"
	if _, err = command(t, s, v1.CreateEvent.ID, "calendar.create", "create", mismatch, s.create); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatalf("payload replay: %v", err)
	}
	ref := v1.EventRef{Scope: scope, EventID: created.ID}
	update := v1.Update{EventRef: ref, Input: sample(), Revision: 1}
	update.Title = "Updated"
	saved, err := command(t, s, v1.UpdateEvent.ID, "calendar.write", "update", update, s.update)
	if err != nil || saved.Revision != 2 {
		t.Fatalf("update: %+v %v", saved, err)
	}
	if _, err = command(t, s, v1.UpdateEvent.ID, "calendar.write", "stale", update, s.update); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatalf("CAS: %v", err)
	}
	foreign := ref
	foreign.RootID = newID()
	if _, err = s.get(context.Background(), foreign); rpc.ErrorCode(err) != rpc.CodeNotFound {
		t.Fatalf("foreign root: %v", err)
	}
	// A failed outbox insert rolls back the event, audit and command reservation.
	if err = s.DB.Exec("CREATE TRIGGER deny_event BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fixture'); END").Error; err != nil {
		t.Fatal(err)
	}
	bad := v1.Update{EventRef: ref, Input: sample(), Revision: 2}
	if _, err = command(t, s, v1.UpdateEvent.ID, "calendar.write", "rollback", bad, s.update); err == nil {
		t.Fatal("outbox failure committed")
	}
	current, err := s.get(context.Background(), ref)
	if err != nil || current.Revision != 2 || current.Title != "Updated" {
		t.Fatalf("rollback: %+v %v", current, err)
	}
	var n int64
	s.DB.Table("command_results").Where("idempotency_key='rollback'").Count(&n)
	if n != 0 {
		t.Fatal("failed reservation retained")
	}
	s.DB.Exec("DROP TRIGGER deny_event")
	// Revocation is checked before returning a previously committed replay.
	s.Check = func(context.Context, string, string) error { return security.ErrDenied }
	if _, err = command(t, s, v1.CreateEvent.ID, "calendar.create", "create", q, s.create); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("revoked replay: %v", err)
	}
	s.Check = func(context.Context, string, string) error { return nil }
	deleted, err := command(t, s, v1.DeleteEvent.ID, "calendar.delete", "delete", v1.Delete{EventRef: ref, Revision: 2}, s.delete)
	if err != nil || !deleted.Deleted {
		t.Fatalf("delete: %+v %v", deleted, err)
	}
	if _, err = s.get(context.Background(), ref); rpc.ErrorCode(err) != rpc.CodeNotFound {
		t.Fatal("deleted event readable", err)
	}
	for _, table := range []string{"audit", "outbox", "command_results"} {
		s.DB.Table(table).Count(&n)
		if n != 3 {
			t.Fatalf("%s: %d", table, n)
		}
	}
}
func TestCalendarFreeBusyAndAllDayDST(t *testing.T) {
	s := fixture(t)
	scope := v1.Scope{WorkspaceID: ws, RootID: root}
	day := v1.Input{Title: "Secret", Description: "Do not disclose", Timezone: "America/New_York", AllDay: true, Start: "2026-03-08", End: "2026-03-09", Busy: true}
	_, start, end, err := validate(day)
	if err != nil || end.Sub(start) != 23*time.Hour {
		t.Fatalf("DST: %v %v", end.Sub(start), err)
	}
	for i, in := range []v1.Input{day, {Title: "Overlap", Timezone: day.Timezone, Start: "2026-03-08T12:00:00Z", End: "2026-03-08T14:00:00Z", Busy: true}, {Title: "Transparent", Timezone: "UTC", Start: "2026-03-09T12:00:00Z", End: "2026-03-09T14:00:00Z", Busy: false}} {
		if _, err := command(t, s, v1.CreateEvent.ID, "calendar.create", string(rune('a'+i)), v1.Create{Scope: scope, Input: in}, s.create); err != nil {
			t.Fatal(err)
		}
	}
	q := v1.Range{Scope: scope, From: start.Add(time.Hour), Until: end.Add(24 * time.Hour)}
	s.Check = func(_ context.Context, _ string, action string) error {
		if action != "calendar.free_busy" {
			return security.ErrDenied
		}
		return nil
	}
	ctx := invocation(t, v1.FreeBusy.ID, ws, "", q)
	if err = s.Authorize(ctx, root, "calendar.free_busy"); err != nil {
		t.Fatal(err)
	}
	busy, err := s.freeBusy(ctx, q)
	if err != nil || len(busy.Intervals) != 1 || !busy.Intervals[0].Start.Equal(q.From) || !busy.Intervals[0].End.Equal(end) {
		t.Fatalf("free/busy: %+v %v", busy, err)
	}
	raw, _ := json.Marshal(busy)
	var object map[string]json.RawMessage
	json.Unmarshal(raw, &object)
	if len(object) != 1 || object["intervals"] == nil {
		t.Fatal(string(raw))
	}
	if err = s.Authorize(ctx, root, "calendar.read"); !errors.Is(err, security.ErrDenied) {
		t.Fatal("free_busy gained read")
	}
	listed, err := s.list(ctx, v1.List{Range: q, Limit: 1})
	if err != nil || len(listed.Events) != 1 || listed.NextCursor == "" {
		t.Fatalf("list: %+v %v", listed, err)
	}
	next, err := s.list(ctx, v1.List{Range: q, Limit: 100, Cursor: listed.NextCursor})
	if err != nil || len(next.Events) != 2 {
		t.Fatalf("pagination: %+v %v", next, err)
	}
	for _, bad := range []v1.Input{{Title: "x", Timezone: "UTC", AllDay: true, Start: "2026-03-08T00:00:00Z", End: "2026-03-09"}, {Title: "x", Timezone: "Local", Start: day.Start, End: day.End}, {Title: "x", Timezone: "UTC", Start: "2026-03-08T12:00:00Z", End: "2026-03-08T11:00:00Z"}} {
		if _, _, _, err = validate(bad); err == nil {
			t.Fatal("invalid event accepted", bad)
		}
	}
}
func TestCalendarPersonalRootAndAuthorization(t *testing.T) {
	s := fixture(t)
	ctx := context.Background()
	scope := v1.Scope{RootID: newID()}
	owner := newID()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	in := v1.CalendarInput{Name: "Personal", Timezone: "UTC"}
	if _, err := s.PrepareRoot(ctx, scope, owner, in, key, "key", newID()); err != nil {
		t.Fatal(err)
	}
	payload := v1.Create{Scope: scope, Input: sample()}
	call := invocation(t, v1.PersonalCreateEvent.ID, "", "personal", payload)
	if err := s.Authorize(call, scope.RootID, "calendar.create"); err == nil {
		t.Fatal("prepared root accessible")
	}
	if err := s.ActivateRoot(ctx, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := command(t, s, v1.PersonalCreateEvent.ID, "calendar.create", "personal", payload, s.create); err != nil {
		t.Fatal(err)
	}
	if err := s.Authorize(invocation(t, v1.CreateEvent.ID, "", "wrong-route", payload), scope.RootID, "calendar.create"); err == nil {
		t.Fatal("personal scope on workspace route")
	}
	if err := s.Authorize(invocation(t, v1.PersonalCreateEvent.ID, ws, "wrong-workspace", payload), scope.RootID, "calendar.create"); err == nil {
		t.Fatal("claim workspace mismatch")
	}
	if err := s.Authorize(ctx, scope.RootID, "calendar.read"); err == nil {
		t.Fatal("unverified caller")
	}
	s.Check = nil
	if err := s.Authorize(call, scope.RootID, "calendar.create"); !errors.Is(err, security.ErrUnavailable) {
		t.Fatal("missing authority allowed", err)
	}
	if _, err := s.PrepareRoot(ctx, scope, newID(), in, key, "key", newID()); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatal("owner rebind accepted", err)
	}
}

func TestCalendarResponseBoundsAndMetadata(t *testing.T) {
	s := fixture(t)
	scope := v1.Scope{WorkspaceID: ws, RootID: root}
	q := v1.CalendarUpdate{Scope: scope, CalendarInput: v1.CalendarInput{Name: "Renamed", Timezone: "UTC"}, Revision: 1}
	updated, err := command(t, s, v1.UpdateCalendar.ID, "calendar.write", "rename", q, s.updateCalendar)
	if err != nil || updated.Revision != 2 || updated.Name != "Renamed" {
		t.Fatalf("metadata: %+v %v", updated, err)
	}
	if _, err = command(t, s, v1.UpdateCalendar.ID, "calendar.write", "stale-rename", q, s.updateCalendar); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatalf("metadata CAS: %v", err)
	}
	in := sample()
	in.Description = string(make([]byte, 8192))
	in.Busy = false
	if _, err = command(t, s, v1.CreateEvent.ID, "calendar.create", "description", v1.Create{Scope: scope, Input: in}, s.create); err != nil {
		t.Fatal(err)
	}
	from, _ := time.Parse(time.RFC3339, "2026-11-12T00:00:00Z")
	rangeQ := v1.Range{Scope: scope, From: from, Until: from.Add(24 * time.Hour)}
	listed, err := s.list(context.Background(), v1.List{Range: rangeQ, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(listed)
	var decoded struct {
		Events []map[string]json.RawMessage `json:"events"`
	}
	json.Unmarshal(raw, &decoded)
	if len(decoded.Events) != 1 || decoded.Events[0]["description"] != nil || len(raw) > 4096 {
		t.Fatal("list returned unbounded descriptions")
	}
	// More than 1000 disjoint intervals cannot fit the bounded response contract.
	now := time.Now().UTC()
	var rows []models.Event
	for i := 0; i < 1001; i++ {
		start := from.Add(time.Duration(i) * time.Minute)
		end := start.Add(20 * time.Second)
		rows = append(rows, models.Event{ID: newID(), WorkspaceID: ws, RootID: root, Title: "Busy", Timezone: "UTC", Start: start.Format(time.RFC3339), End: end.Format(time.RFC3339), StartAt: start, EndAt: end, Busy: true, Revision: 1, CreatedAt: now, UpdatedAt: now})
	}
	for i := range rows {
		rows[i].UID = rows[i].ID + "@arc"
	}
	if err = s.DB.CreateInBatches(rows, 100).Error; err != nil {
		t.Fatal(err)
	}
	var effective []models.Occurrence
	for _, row := range rows {
		effective = append(effective, models.Occurrence{EventID: row.ID, WorkspaceID: ws, RootID: root, RecurrenceID: row.Start, Start: row.Start, End: row.End, StartAt: row.StartAt, EndAt: row.EndAt, Busy: true})
	}
	if err = s.DB.CreateInBatches(effective, 100).Error; err != nil {
		t.Fatal(err)
	}
	out, err := s.freeBusy(context.Background(), rangeQ)
	if rpc.ErrorCode(err) != rpc.CodeValidation || len(out.Intervals) != 0 {
		t.Fatalf("partial or oversized free/busy: %d %v", len(out.Intervals), err)
	}
}
