// Package calendar owns calendar roots, events and collection state.
package calendar

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	_ "time/tzdata"
	"unicode/utf8"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/module"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/calendar/api/v1"
	"github.com/pavlith/arc/services/calendar/models"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/identity"
	"github.com/pavlith/arc/services/resources"
	"gorm.io/gorm"
)

type Module struct {
	DB       *gorm.DB
	Contract *contract.Compiled
	Identity identity.Client
	Check    func(context.Context, string, string) error
}

func (*Module) ID() string { return "calendar" }
func (s *Module) db(ctx context.Context) *gorm.DB {
	return database.FromContext(ctx, s.DB).WithContext(ctx)
}
func invalid() error { return &rpc.Error{Code: rpc.CodeValidation, Message: "invalid Calendar input"} }
func conflict() error {
	return &rpc.Error{Code: rpc.CodeConflict, Message: "Calendar revision conflict"}
}
func dbError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return &rpc.Error{Code: rpc.CodeNotFound, Message: "calendar item unavailable"}
	}
	return security.ErrUnavailable
}

var idPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validScope(q v1.Scope) bool {
	return idPattern.MatchString(q.RootID) && (q.WorkspaceID == "" || idPattern.MatchString(q.WorkspaceID))
}
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func (s *Module) root(ctx context.Context, q v1.Scope) (models.Root, error) {
	var row models.Root
	err := s.db(ctx).Where("acl_root_id=? AND workspace_id=? AND state='active'", q.RootID, q.WorkspaceID).Take(&row).Error
	return row, dbError(err)
}
func (s *Module) Authorize(ctx context.Context, root, action string) error {
	cl, ok := rpc.VerifiedClaims(ctx)
	meta, has := rpc.Metadata(ctx)
	if !ok || !has || cl.SessionID == "" || !strings.HasPrefix(cl.Subject, "user:") {
		return security.ErrUnauthenticated
	}
	var q v1.Scope
	if json.Unmarshal(meta.Payload, &q) != nil || !validScope(q) || q.RootID != root || cl.WorkspaceID != q.WorkspaceID || strings.HasPrefix(cl.Operation, "calendar.personal.") != (q.WorkspaceID == "") {
		return security.ErrDenied
	}
	if _, err := s.root(ctx, q); err != nil {
		return err
	}
	if s.Check == nil {
		return security.ErrUnavailable
	}
	return s.Check(ctx, root, action)
}
func calendarInput(in v1.CalendarInput) (v1.CalendarInput, error) {
	in.Name = strings.TrimSpace(in.Name)
	if !utf8.ValidString(in.Name) || in.Name == "" || utf8.RuneCountInString(in.Name) > 256 {
		return in, invalid()
	}
	if _, err := location(in.Timezone); err != nil {
		return in, err
	}
	return in, nil
}
func location(name string) (*time.Location, error) {
	// Local is host-dependent and is never a stored timezone.
	if name == "" || name == "Local" || len(name) > 128 {
		return nil, invalid()
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, invalid()
	}
	return loc, nil
}

// PrepareRoot is an operator-side lifecycle hook, never a public root-creation RPC.
// Access must reserve this exact provider/owner binding before the receipt is used.
func (s *Module) PrepareRoot(ctx context.Context, q v1.Scope, owner string, in v1.CalendarInput, key ed25519.PrivateKey, kid, provider string) (string, error) {
	if !validScope(q) || (q.WorkspaceID == "") != (owner != "") || owner != "" && !idPattern.MatchString(owner) {
		return "", invalid()
	}
	in, err := calendarInput(in)
	if err != nil {
		return "", err
	}
	receipt, err := access.SignDomainReceipt(key, access.DomainReceipt{Provider: provider, Root: q.RootID, Operation: "activate", Kid: kid, ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		return "", err
	}
	if err := s.DB.WithContext(ctx).Exec("INSERT INTO roots(acl_root_id,workspace_id,owner_id,state,name,timezone,revision,sync_epoch,sync_ready) VALUES(?,?,?,'prepared',?,?,1,lower(hex(randomblob(16))),1) ON CONFLICT DO NOTHING", q.RootID, q.WorkspaceID, owner, in.Name, in.Timezone).Error; err != nil {
		return "", dbError(err)
	}
	var row models.Root
	if err := s.DB.WithContext(ctx).Where("acl_root_id=?", q.RootID).Take(&row).Error; err != nil {
		return "", dbError(err)
	}
	if row.WorkspaceID != q.WorkspaceID || row.OwnerID != owner || row.State == "prepared" && (row.Name != in.Name || row.Timezone != in.Timezone) {
		return "", conflict()
	}
	return receipt, nil
}
func (s *Module) ActivateRoot(ctx context.Context, q v1.Scope) error {
	if !validScope(q) {
		return invalid()
	}
	res := s.DB.WithContext(ctx).Exec("UPDATE roots SET state='active' WHERE acl_root_id=? AND workspace_id=?", q.RootID, q.WorkspaceID)
	if res.Error != nil {
		return dbError(res.Error)
	}
	if res.RowsAffected != 1 {
		return dbError(gorm.ErrRecordNotFound)
	}
	return nil
}
func (s *Module) getCalendar(ctx context.Context, q v1.Scope) (v1.Calendar, error) {
	row, err := s.root(ctx, q)
	return v1.Calendar{Scope: q, CalendarInput: v1.CalendarInput{Name: row.Name, Timezone: row.Timezone}, Revision: row.Revision}, err
}
func (s *Module) updateCalendar(ctx context.Context, tx *gorm.DB, q v1.CalendarUpdate) (v1.Calendar, error) {
	in, err := calendarInput(q.CalendarInput)
	if err != nil {
		return v1.Calendar{}, err
	}
	if q.Revision < 1 {
		return v1.Calendar{}, invalid()
	}
	res := tx.Model(&models.Root{}).Where("acl_root_id=? AND workspace_id=? AND state='active' AND revision=?", q.RootID, q.WorkspaceID, q.Revision).Updates(map[string]any{"name": in.Name, "timezone": in.Timezone, "revision": q.Revision + 1})
	if res.Error != nil {
		return v1.Calendar{}, dbError(res.Error)
	}
	if res.RowsAffected != 1 {
		return v1.Calendar{}, conflict()
	}
	return v1.Calendar{Scope: q.Scope, CalendarInput: in, Revision: q.Revision + 1}, s.changed(ctx, tx, q.Scope, q.RootID, q.Revision+1, "calendar.updated")
}
func (s *Module) changed(ctx context.Context, tx *gorm.DB, scope v1.Scope, id string, revision int64, action string) error {
	cl, ok := rpc.VerifiedClaims(ctx)
	if !ok {
		return security.ErrUnauthenticated
	}
	now := time.Now().UTC()
	if err := tx.Exec("INSERT INTO audit(workspace_id,acl_root_id,entity_id,actor,operation,revision,created_at) VALUES(?,?,?,?,?,?,?)", scope.WorkspaceID, scope.RootID, id, cl.Subject, cl.Operation, revision, now).Error; err != nil {
		return dbError(err)
	}
	payload, err := json.Marshal(v1.Changed{Scope: scope, EntityID: id, Revision: revision, Action: action})
	if err != nil {
		return invalid()
	}
	if action != "calendar.updated" {
		if err := s.recordSync(ctx, tx, scope, id); err != nil {
			return err
		}
	}
	return (events.Store{DB: s.DB}).Enqueue(ctx, tx, s.Contract, v1.ChangedSubject, events.Envelope{ID: newID(), Type: v1.ChangedName, Version: 1, AggregateID: id, OccurredAt: now, Payload: payload})
}
func (s *Module) grants(ctx context.Context, _ *gorm.DB, q v1.Grant) (v1.GrantResult, error) {
	if q.GrantID != "" {
		if !idPattern.MatchString(q.GrantID) || q.PrincipalID != "" || q.PrincipalKind != "" || q.Action != "" {
			return v1.GrantResult{}, invalid()
		}
	} else if !idPattern.MatchString(q.PrincipalID) || (q.PrincipalKind != "user" && q.PrincipalKind != "group") || q.WorkspaceID == "" && q.PrincipalKind != "user" || q.Action == "" {
		return v1.GrantResult{}, invalid()
	}
	client := s.Identity
	meta, _ := rpc.Metadata(ctx)
	cl, _ := rpc.VerifiedClaims(ctx)
	sum := sha256.Sum256([]byte(cl.Subject + ":" + cl.Operation + ":" + meta.IdempotencyKey))
	client.IdempotencyKey = "calendar-grants:" + hex.EncodeToString(sum[:])
	op := "access.v1.grants.add"
	if q.GrantID != "" {
		op = "access.v1.grants.revoke"
	}
	next, err := resources.Invocation(ctx, client, "access/v1", op)
	if err != nil {
		return v1.GrantResult{}, err
	}
	ac := &access.Client{RPC: client.RPC}
	var r access.MutationResult
	if q.GrantID != "" {
		r, err = ac.RevokeGrant(next, access.RevokeRequest{GrantID: q.GrantID, ResourceID: q.RootID})
	} else {
		r, err = ac.AddGrant(next, access.GrantRequest{ResourceID: q.RootID, PrincipalKind: q.PrincipalKind, PrincipalID: q.PrincipalID, Action: q.Action})
	}
	return v1.GrantResult{ResourceID: r.ResourceID, GrantID: r.GrantID, State: r.State, Revision: r.Revision}, err
}

func (s *Module) Register(r *module.Registry) error {
	if s.DB == nil || s.Contract == nil || s.Check == nil {
		return security.ErrUnavailable
	}
	p := module.Policy{Resource: s.Authorize}
	store := events.Store{DB: s.DB}
	for _, op := range []module.Query[v1.Scope, v1.Calendar]{v1.GetCalendar, v1.PersonalGetCalendar} {
		if err := module.BindQuery(r, op, p, s.getCalendar); err != nil {
			return err
		}
	}
	for _, op := range []module.Command[v1.CalendarUpdate, v1.Calendar]{v1.UpdateCalendar, v1.PersonalUpdateCalendar} {
		if err := module.BindCommand(r, op, p, store, s.updateCalendar); err != nil {
			return err
		}
	}
	for _, op := range []module.Command[v1.Create, v1.Event]{v1.CreateEvent, v1.PersonalCreateEvent} {
		if err := module.BindCommand(r, op, p, store, s.create); err != nil {
			return err
		}
	}
	for _, op := range []module.Query[v1.EventRef, v1.Event]{v1.GetEvent, v1.PersonalGetEvent} {
		if err := module.BindQuery(r, op, p, s.get); err != nil {
			return err
		}
	}
	for _, op := range []module.Command[v1.Update, v1.Event]{v1.UpdateEvent, v1.PersonalUpdateEvent} {
		if err := module.BindCommand(r, op, p, store, s.update); err != nil {
			return err
		}
	}
	for _, op := range []module.Command[v1.Delete, v1.Mutation]{v1.DeleteEvent, v1.PersonalDeleteEvent} {
		if err := module.BindCommand(r, op, p, store, s.delete); err != nil {
			return err
		}
	}
	for _, op := range []module.Query[v1.List, v1.EventList]{v1.ListEvents, v1.PersonalListEvents} {
		if err := module.BindQuery(r, op, p, s.list); err != nil {
			return err
		}
	}
	for _, op := range []module.Query[v1.Range, v1.BusyResult]{v1.FreeBusy, v1.PersonalFreeBusy} {
		if err := module.BindQuery(r, op, p, s.freeBusy); err != nil {
			return err
		}
	}
	for _, op := range []module.Command[v1.Grant, v1.GrantResult]{v1.RootGrants, v1.PersonalRootGrants} {
		if err := module.BindCommand(r, op, p, store, s.grants); err != nil {
			return err
		}
	}
	for _, op := range []module.Query[v1.OccurrenceQuery, v1.OccurrenceList]{v1.ListOccurrences, v1.PersonalListOccurrences} {
		if err := module.BindQuery(r, op, p, s.occurrences); err != nil {
			return err
		}
	}
	for _, op := range []module.Query[v1.EventRef, v1.ICalObject]{v1.GetObject, v1.PersonalGetObject} {
		if err := module.BindQuery(r, op, p, s.getObject); err != nil {
			return err
		}
	}
	for _, op := range []module.Command[v1.ObjectCreate, v1.ICalObject]{v1.CreateObject, v1.PersonalCreateObject} {
		if err := module.BindCommand(r, op, p, store, s.createObject); err != nil {
			return err
		}
	}
	for _, op := range []module.Command[v1.ObjectUpdate, v1.ICalObject]{v1.UpdateObject, v1.PersonalUpdateObject} {
		if err := module.BindCommand(r, op, p, store, s.updateObject); err != nil {
			return err
		}
	}
	for _, op := range []module.Command[v1.ObjectDelete, v1.Mutation]{v1.DeleteObject, v1.PersonalDeleteObject} {
		if err := module.BindCommand(r, op, p, store, s.deleteObject); err != nil {
			return err
		}
	}
	for _, op := range []module.Query[v1.SyncQuery, v1.SyncResult]{v1.SyncCollection, v1.PersonalSyncCollection} {
		if err := module.BindQuery(r, op, p, s.syncCollection); err != nil {
			return err
		}
	}
	for _, op := range []module.Query[v1.ObjectBatchQuery, v1.ObjectBatchResult]{v1.MultigetObjects, v1.PersonalMultigetObjects} {
		if err := module.BindQuery(r, op, p, s.multigetObjects); err != nil {
			return err
		}
	}
	return nil
}
