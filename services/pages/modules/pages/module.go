package pages

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/module"
	"github.com/pavlith/arc/sdk/resource"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/identity"
	v1 "github.com/pavlith/arc/services/pages/api/v1"
	"github.com/pavlith/arc/services/pages/models"
	"github.com/pavlith/arc/services/resources"
	"gorm.io/gorm"
)

type Module struct {
	DB       *gorm.DB
	Contract *contract.Compiled
	Identity identity.Client
	Check    func(context.Context, string, string) error
	Resolve  func(context.Context, resource.Ref) (resource.Summary, error)
}

func (*Module) ID() string { return "pages" }
func (s *Module) db(ctx context.Context) *gorm.DB {
	return database.FromContext(ctx, s.DB).WithContext(ctx)
}
func invalid() error  { return &rpc.Error{Code: rpc.CodeValidation, Message: "invalid Pages input"} }
func conflict() error { return &rpc.Error{Code: rpc.CodeConflict, Message: "Pages revision conflict"} }
func missing() error  { return &rpc.Error{Code: rpc.CodeNotFound, Message: "page unavailable"} }
func dbError(err error) error {
	if err == nil {
		return nil
	}
	if err == gorm.ErrRecordNotFound {
		return missing()
	}
	return rpc.SecurityError(security.ErrUnavailable)
}
func pointer(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
func str(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
func (s *Module) root(ctx context.Context, scope v1.Scope) error {
	var active bool
	if err := s.db(ctx).Raw("SELECT EXISTS(SELECT 1 FROM roots WHERE acl_root_id=? AND workspace_id=? AND state='active')", scope.RootID, scope.WorkspaceID).Row().Scan(&active); err != nil {
		return dbError(err)
	}
	if !active {
		return security.ErrDenied
	}
	return nil
}
func (s *Module) Authorize(ctx context.Context, root, action string) error {
	cl, ok := rpc.VerifiedClaims(ctx)
	meta, has := rpc.Metadata(ctx)
	if !ok || !has || cl.SessionID == "" || !strings.HasPrefix(cl.Subject, "user:") {
		return security.ErrUnauthenticated
	}
	var scope v1.Scope
	if json.Unmarshal(meta.Payload, &scope) != nil || scope.RootID != root || cl.WorkspaceID != scope.WorkspaceID || strings.HasPrefix(cl.Operation, "pages.personal.") != (scope.WorkspaceID == "") {
		return security.ErrDenied
	}
	if err := s.root(ctx, scope); err != nil {
		return err
	}
	if s.Check == nil {
		return security.ErrUnavailable
	}
	if err := s.Check(ctx, root, action); err != nil {
		return err
	}
	if action != "pages.read" && (strings.HasSuffix(cl.Operation, ".templates.use") || strings.HasSuffix(cl.Operation, ".pages.restore")) {
		return s.Check(ctx, root, "pages.read")
	}
	return nil
}
func (s *Module) PrepareRoot(ctx context.Context, scope v1.Scope, owner string, key ed25519.PrivateKey, kid, provider string) (string, error) {
	if !(resource.Ref{Kind: "page", RootID: scope.RootID, ID: scope.RootID, WorkspaceID: scope.WorkspaceID}).Valid() || (owner != "" && !(resource.Ref{Kind: "page", RootID: owner, ID: owner}).Valid()) || (scope.WorkspaceID == "") != (owner != "") {
		return "", invalid()
	}
	if err := s.DB.WithContext(ctx).Exec("INSERT INTO roots(acl_root_id,workspace_id,owner_id,state) VALUES(?,?,?,'prepared') ON CONFLICT DO NOTHING", scope.RootID, scope.WorkspaceID, owner).Error; err != nil {
		return "", dbError(err)
	}
	var row models.Root
	if err := s.DB.WithContext(ctx).Where("acl_root_id=?", scope.RootID).Take(&row).Error; err != nil {
		return "", dbError(err)
	}
	if row.WorkspaceID != scope.WorkspaceID || row.OwnerID != owner {
		return "", conflict()
	}
	return access.SignDomainReceipt(key, access.DomainReceipt{Provider: provider, Root: scope.RootID, Operation: "activate", Kid: kid, ExpiresAt: time.Now().Add(time.Minute)})
}
func (s *Module) ActivateRoot(ctx context.Context, scope v1.Scope) error {
	r := s.DB.WithContext(ctx).Exec("UPDATE roots SET state='active' WHERE acl_root_id=? AND workspace_id=?", scope.RootID, scope.WorkspaceID)
	if r.Error != nil {
		return dbError(r.Error)
	}
	if r.RowsAffected != 1 {
		return missing()
	}
	return nil
}
func (s *Module) Lookup(ctx context.Context, ref resource.Ref) (resource.Summary, error) {
	cl, ok := rpc.VerifiedClaims(ctx)
	if !ok || !ref.Valid() || cl.WorkspaceID != ref.WorkspaceID {
		return resource.Summary{}, security.ErrDenied
	}
	if ref.Kind != "page" {
		if s.Resolve == nil {
			return resource.Summary{}, security.ErrUnavailable
		}
		return s.Resolve(ctx, ref)
	}
	scope := v1.Scope{RootID: ref.RootID, WorkspaceID: ref.WorkspaceID}
	if err := s.root(ctx, scope); err != nil {
		return resource.Summary{}, err
	}
	if s.Check == nil {
		return resource.Summary{}, security.ErrUnavailable
	}
	if err := s.Check(ctx, ref.RootID, "pages.read"); err != nil {
		return resource.Summary{}, err
	}
	row, err := s.row(ctx, s.db(ctx), v1.PageRef{Scope: scope, PageID: ref.ID})
	if err != nil {
		return resource.Summary{}, err
	}
	return resource.Summary{Ref: ref, Title: row.Title, Revision: row.Revision}, nil
}
func (s *Module) preview(ctx context.Context, q v1.Preview) (resource.Summary, error) {
	if _, err := s.row(ctx, s.db(ctx), q.PageRef); err != nil {
		return resource.Summary{}, err
	}
	return s.Lookup(ctx, q.Target)
}
func (s *Module) changed(ctx context.Context, tx *gorm.DB, row models.Page, action string) error {
	cl, _ := rpc.VerifiedClaims(ctx)
	now := time.Now().UTC()
	if err := tx.Exec("INSERT INTO audit(workspace_id,acl_root_id,entity_id,actor,operation,revision,created_at) VALUES(?,?,?,?,?,?,?)", row.WorkspaceID, row.RootID, row.ID, cl.Subject, cl.Operation, row.Revision, now).Error; err != nil {
		return dbError(err)
	}
	payload, _ := json.Marshal(v1.Changed{Scope: v1.Scope{WorkspaceID: row.WorkspaceID, RootID: row.RootID}, EntityID: row.ID, Revision: row.Revision, Action: action})
	return (events.Store{DB: s.DB}).Enqueue(ctx, tx, s.Contract, v1.ChangedSubject, events.Envelope{ID: newID(), Type: v1.ChangedName, Version: 1, AggregateID: row.ID, OccurredAt: now, Payload: payload})
}
func (s *Module) grants(ctx context.Context, _ *gorm.DB, q v1.Grant) (v1.GrantResult, error) {
	client := s.Identity
	meta, _ := rpc.Metadata(ctx)
	cl, _ := rpc.VerifiedClaims(ctx)
	sum := sha256.Sum256([]byte(cl.Subject + ":" + cl.Operation + ":" + meta.IdempotencyKey))
	client.IdempotencyKey = "pages-grants:" + hex.EncodeToString(sum[:])
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
		r, err = ac.AddGrant(next, access.GrantRequest{ResourceID: q.RootID, PrincipalKind: "user", PrincipalID: q.PrincipalID, Action: q.Action})
	}
	return v1.GrantResult{ResourceID: r.ResourceID, GrantID: r.GrantID, State: r.State, Revision: r.Revision}, err
}
func (s *Module) Register(r *module.Registry) error {
	if s.DB == nil || s.Contract == nil || s.Check == nil {
		return security.ErrUnavailable
	}
	p := module.Policy{Resource: s.Authorize}
	store := events.Store{DB: s.DB}
	for _, op := range []module.Command[v1.Create, v1.Page]{v1.CreatePage, v1.PersonalCreatePage} {
		if err := module.BindCommand(r, op, p, store, s.create); err != nil {
			return err
		}
	}
	for _, op := range []module.Command[v1.TemplateUse, v1.Page]{v1.UseTemplate, v1.PersonalUseTemplate} {
		if err := module.BindCommand(r, op, p, store, s.useTemplate); err != nil {
			return err
		}
	}
	for _, op := range []module.Query[v1.PageRef, v1.Page]{v1.GetPage, v1.PersonalGetPage} {
		if err := module.BindQuery(r, op, p, s.get); err != nil {
			return err
		}
	}
	for _, op := range []module.Command[v1.Update, v1.Page]{v1.UpdatePage, v1.PersonalUpdatePage} {
		if err := module.BindCommand(r, op, p, store, s.update); err != nil {
			return err
		}
	}
	for _, op := range []module.Command[v1.Move, v1.Mutation]{v1.MovePage, v1.PersonalMovePage} {
		if err := module.BindCommand(r, op, p, store, s.move); err != nil {
			return err
		}
	}
	for _, op := range []module.Command[v1.Archive, v1.Mutation]{v1.ArchivePage, v1.PersonalArchivePage} {
		if err := module.BindCommand(r, op, p, store, s.archive); err != nil {
			return err
		}
	}
	for _, op := range []module.Query[v1.List, v1.PageList]{v1.ListPages, v1.PersonalListPages} {
		if err := module.BindQuery(r, op, p, s.list); err != nil {
			return err
		}
	}
	for _, op := range []module.Query[v1.VersionList, v1.Versions]{v1.ListVersions, v1.PersonalListVersions} {
		if err := module.BindQuery(r, op, p, s.versions); err != nil {
			return err
		}
	}
	for _, op := range []module.Command[v1.Restore, v1.Page]{v1.RestorePage, v1.PersonalRestorePage} {
		if err := module.BindCommand(r, op, p, store, s.restore); err != nil {
			return err
		}
	}
	for _, op := range []module.Query[v1.Preview, resource.Summary]{v1.PreviewReference, v1.PersonalPreviewReference} {
		if err := module.BindQuery(r, op, p, s.preview); err != nil {
			return err
		}
	}
	for _, op := range []module.Command[v1.TemplateCreate, v1.Template]{v1.CreateTemplate, v1.PersonalCreateTemplate} {
		if err := module.BindCommand(r, op, p, store, s.createTemplate); err != nil {
			return err
		}
	}
	for _, op := range []module.Command[v1.TemplateUpdate, v1.Template]{v1.UpdateTemplate, v1.PersonalUpdateTemplate} {
		if err := module.BindCommand(r, op, p, store, s.updateTemplate); err != nil {
			return err
		}
	}
	for _, op := range []module.Query[v1.TemplateRef, v1.Template]{v1.GetTemplate, v1.PersonalGetTemplate} {
		if err := module.BindQuery(r, op, p, s.getTemplate); err != nil {
			return err
		}
	}
	for _, op := range []module.Query[v1.List, v1.TemplateList]{v1.ListTemplates, v1.PersonalListTemplates} {
		if err := module.BindQuery(r, op, p, s.listTemplates); err != nil {
			return err
		}
	}
	for _, op := range []module.Command[v1.TemplateArchive, v1.Mutation]{v1.ArchiveTemplate, v1.PersonalArchiveTemplate} {
		if err := module.BindCommand(r, op, p, store, s.archiveTemplate); err != nil {
			return err
		}
	}
	for _, op := range []module.Command[v1.Grant, v1.GrantResult]{v1.RootGrants, v1.PersonalRootGrants} {
		if err := module.BindCommand(r, op, p, store, s.grants); err != nil {
			return err
		}
	}
	return nil
}
