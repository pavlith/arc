package contacts

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
	v1 "github.com/pavlith/arc/services/contacts/api/v1"
	"github.com/pavlith/arc/services/contacts/migrations"
	"github.com/pavlith/arc/services/contacts/models"
	"gorm.io/gorm"
)

const ws = "40000000-0000-4000-8000-000000000001"
const root = "40000000-0000-4000-8000-000000000002"

func fixture(t *testing.T) *Module {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "contacts.sqlite")
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
	if err = db.Create(&models.Root{RootID: root, WorkspaceID: ws, State: "active", Name: "Work", Revision: 1}).Error; err != nil {
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
	return v1.Input{DisplayName: "Иван Петров", Organization: "Arc", Role: "Engineer", Emails: []v1.LabelledValue{{Label: "work", Value: "ivan@example.test"}}, Phones: []v1.LabelledValue{{Value: "+7 123"}}, Addresses: []v1.Address{{Street: "Main street", Country: "RU"}}, Notes: "Confidential", CustomFields: map[string]string{"external_id": "abc"}}
}
func TestContactsCRUDCASReplayRollbackAndScope(t *testing.T) {
	s := fixture(t)
	scope := v1.Scope{WorkspaceID: ws, RootID: root}
	q := v1.Create{Scope: scope, Input: sample()}
	created, err := command(t, s, v1.CreateContact.ID, "contacts.create", "create", q, s.create)
	if err != nil {
		t.Fatal(err)
	}
	if created.UID != created.ID+"@arc" || created.Revision != 1 {
		t.Fatal(created)
	}
	replay, err := command(t, s, v1.CreateContact.ID, "contacts.create", "create", q, s.create)
	if err != nil || replay.ID != created.ID {
		t.Fatalf("replay: %+v %v", replay, err)
	}
	mismatch := q
	mismatch.DisplayName = "changed"
	if _, err = command(t, s, v1.CreateContact.ID, "contacts.create", "create", mismatch, s.create); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatalf("payload replay: %v", err)
	}
	ref := v1.ContactRef{Scope: scope, ContactID: created.ID}
	update := v1.Update{ContactRef: ref, Input: sample(), Revision: 1}
	update.DisplayName = "Updated"
	saved, err := command(t, s, v1.UpdateContact.ID, "contacts.write", "update", update, s.update)
	if err != nil || saved.Revision != 2 {
		t.Fatalf("update: %+v %v", saved, err)
	}
	if _, err = command(t, s, v1.UpdateContact.ID, "contacts.write", "stale", update, s.update); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatalf("CAS: %v", err)
	}
	foreign := ref
	foreign.RootID = newID()
	if _, err = s.get(context.Background(), foreign); rpc.ErrorCode(err) != rpc.CodeNotFound {
		t.Fatalf("foreign root: %v", err)
	}
	// A failed outbox insert rolls back the contact, audit and command reservation.
	if err = s.DB.Exec("CREATE TRIGGER deny_event BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fixture'); END").Error; err != nil {
		t.Fatal(err)
	}
	bad := v1.Update{ContactRef: ref, Input: sample(), Revision: 2}
	if _, err = command(t, s, v1.UpdateContact.ID, "contacts.write", "rollback", bad, s.update); err == nil {
		t.Fatal("outbox failure committed")
	}
	current, err := s.get(context.Background(), ref)
	if err != nil || current.Revision != 2 || current.DisplayName != "Updated" {
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
	if _, err = command(t, s, v1.CreateContact.ID, "contacts.create", "create", q, s.create); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("revoked replay: %v", err)
	}
	s.Check = func(context.Context, string, string) error { return nil }
	deleted, err := command(t, s, v1.DeleteContact.ID, "contacts.delete", "delete", v1.Delete{ContactRef: ref, Revision: 2}, s.delete)
	if err != nil || !deleted.Deleted {
		t.Fatalf("delete: %+v %v", deleted, err)
	}
	if _, err = s.get(context.Background(), ref); rpc.ErrorCode(err) != rpc.CodeNotFound {
		t.Fatal("deleted contact readable", err)
	}
	for _, table := range []string{"audit", "outbox", "command_results"} {
		s.DB.Table(table).Count(&n)
		if n != 3 {
			t.Fatalf("%s: %d", table, n)
		}
	}
}
func TestBookPersonalRootAndAuthorization(t *testing.T) {
	s := fixture(t)
	ctx := context.Background()
	scope := v1.Scope{RootID: newID()}
	owner := newID()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	in := v1.BookInput{Name: "Personal"}
	if _, err := s.PrepareRoot(ctx, scope, owner, in, key, "key", newID()); err != nil {
		t.Fatal(err)
	}
	payload := v1.Create{Scope: scope, Input: sample()}
	call := invocation(t, v1.PersonalCreateContact.ID, "", "personal", payload)
	if err := s.Authorize(call, scope.RootID, "contacts.create"); err == nil {
		t.Fatal("prepared root accessible")
	}
	if err := s.ActivateRoot(ctx, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := command(t, s, v1.PersonalCreateContact.ID, "contacts.create", "personal", payload, s.create); err != nil {
		t.Fatal(err)
	}
	if err := s.Authorize(invocation(t, v1.CreateContact.ID, "", "wrong-route", payload), scope.RootID, "contacts.create"); err == nil {
		t.Fatal("personal scope on workspace route")
	}
	if err := s.Authorize(invocation(t, v1.PersonalCreateContact.ID, ws, "wrong-workspace", payload), scope.RootID, "contacts.create"); err == nil {
		t.Fatal("claim workspace mismatch")
	}
	if err := s.Authorize(ctx, scope.RootID, "contacts.read"); err == nil {
		t.Fatal("unverified caller")
	}
	s.Check = nil
	if err := s.Authorize(call, scope.RootID, "contacts.create"); !errors.Is(err, security.ErrUnavailable) {
		t.Fatal("missing authority allowed", err)
	}
	if _, err := s.PrepareRoot(ctx, scope, newID(), in, key, "key", newID()); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatal("owner rebind accepted", err)
	}
}

func TestInputBoundsCopiesAndSearch(t *testing.T) {
	in := sample()
	in.DisplayName = "  Иван Петров  "
	in.Emails[0].Value = " ivan@example.test "
	in.CustomFields[" padded "] = " value "
	normalized, raw, err := validate(in)
	if err != nil || normalized.DisplayName != "Иван Петров" || normalized.CustomFields["padded"] != "value" {
		t.Fatalf("normalization: %+v %v", normalized, err)
	}
	if in.Emails[0].Value != " ivan@example.test " || in.CustomFields[" padded "] != " value " {
		t.Fatal("caller data mutated")
	}
	if len(raw) > 48*1024 {
		t.Fatal("unbounded contact")
	}
	for _, change := range []func(*v1.Input){
		func(v *v1.Input) { v.DisplayName = " " },
		func(v *v1.Input) { v.DisplayName = "bad\nname" },
		func(v *v1.Input) { v.Notes = "bad\x00" },
		func(v *v1.Input) { v.Emails = []v1.LabelledValue{{Value: "Name <x@example.test>"}} },
		func(v *v1.Input) { v.Emails = []v1.LabelledValue{{Value: "bad"}} },
		func(v *v1.Input) { v.Phones = make([]v1.LabelledValue, 33) },
		func(v *v1.Input) { v.Addresses = []v1.Address{{Label: "empty"}} },
		func(v *v1.Input) { v.CustomFields = map[string]string{"x": "1", " x ": "2"} },
		func(v *v1.Input) { v.DisplayName = string([]byte{255}) },
		func(v *v1.Input) { v.DisplayName = strings.Repeat("я", 257) },
		func(v *v1.Input) {
			v.Notes = strings.Repeat("<", 8192)
			v.CustomFields = map[string]string{"extra": strings.Repeat("x", 512)}
		},
	} {
		v := sample()
		change(&v)
		if _, _, err := validate(v); err == nil {
			t.Fatal("invalid contact accepted")
		}
	}
	s := fixture(t)
	scope := v1.Scope{WorkspaceID: ws, RootID: root}
	created, err := command(t, s, v1.CreateContact.ID, "contacts.create", "search", v1.Create{Scope: scope, Input: sample()}, s.create)
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"ПЕТРОВ", "ENGINEER", "MAIN STREET", "ABC", "IVAN@EXAMPLE.TEST", "+7 123"} {
		got, err := s.list(context.Background(), v1.List{Scope: scope, Query: query, Limit: 100})
		if err != nil || len(got.Contacts) != 1 || got.Contacts[0].ID != created.ID {
			t.Fatalf("search %q: %+v %v", query, got, err)
		}
	}
	for _, query := range []string{"external_id", "display_name", "%", "_"} {
		got, err := s.list(context.Background(), v1.List{Scope: scope, Query: query, Limit: 100})
		if err != nil || len(got.Contacts) != 0 {
			t.Fatal("matched metadata/wildcard", query, err)
		}
	}
}
func TestListWireBudgetAndBookCAS(t *testing.T) {
	s := fixture(t)
	scope := v1.Scope{WorkspaceID: ws, RootID: root}
	q := v1.BookUpdate{Scope: scope, BookInput: v1.BookInput{Name: "Renamed"}, Revision: 1}
	book, err := command(t, s, v1.UpdateBook.ID, "contacts.write", "rename", q, s.updateBook)
	if err != nil || book.Revision != 2 || book.Name != "Renamed" {
		t.Fatal(book, err)
	}
	if _, err := command(t, s, v1.UpdateBook.ID, "contacts.write", "stale-rename", q, s.updateBook); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatal("book CAS", err)
	}
	in := sample()
	in.DisplayName = strings.Repeat("<", 256)
	in.Organization = strings.Repeat("<", 256)
	in.Role = strings.Repeat("<", 128)
	_, fields, err := validate(in)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	rows := make([]models.Contact, 100)
	for i := range rows {
		id := newID()
		rows[i] = models.Contact{ID: id, UID: id + "@arc", WorkspaceID: ws, RootID: root, DisplayName: in.DisplayName, Organization: in.Organization, Role: in.Role, Fields: fields, SearchText: searchText(in), Revision: 1, CreatedAt: now, UpdatedAt: now}
	}
	if err := s.DB.CreateInBatches(rows, 50).Error; err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		got, err := s.list(context.Background(), v1.List{Scope: scope, Cursor: cursor, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(got)
		if len(raw) > 200*1024 || strings.Contains(string(raw), "notes") || strings.Contains(string(raw), "emails") {
			t.Fatal("unbounded list")
		}
		for _, c := range got.Contacts {
			if seen[c.ID] {
				t.Fatal("duplicate cursor result")
			}
			seen[c.ID] = true
		}
		pages++
		if got.NextCursor == "" {
			break
		}
		cursor = got.NextCursor
		if pages > 3 {
			t.Fatal("pagination stalled")
		}
	}
	if len(seen) != 100 || pages < 2 {
		t.Fatal("wire-budget continuation lost items", len(seen), pages)
	}
}
