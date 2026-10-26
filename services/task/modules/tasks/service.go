// Package tasks implements only the M0 workspace Tasks proof service.
package tasks

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/module"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/identity"
	"gorm.io/gorm"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
	"strings"
	"time"
)

type Service struct {
	DB       *sql.DB
	GormDB   *gorm.DB
	Identity identity.Client
	Contract *contract.Compiled
	Check    func(context.Context, string, string) error
}

func NewID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func unavailable(e error) error {
	if e == nil {
		return nil
	}
	return rpc.SecurityError(security.ErrUnavailable)
}
func (s *Service) ID() string { return "task" }

// Register binds every approved Tasks v1 operation; protected resource checks
// happen before command replay, including on idempotent retries.
func (s *Service) Register(r *module.Registry) error {
	if s == nil || (s.DB == nil && s.GormDB == nil) || s.Contract == nil || s.Check == nil {
		return security.ErrUnavailable
	}
	policy := module.Policy{Resource: s.Authorize}
	if s.GormDB != nil {
		store := events.GormStore{DB: s.GormDB}
		if err := module.BindGORMCommand(r, taskv1.Create, policy, store, s.createGORM); err != nil {
			return err
		}
		if err := module.BindGORMCommand(r, taskv1.Admin, policy, store, s.grantsGORM); err != nil {
			return err
		}
	} else {
		store := events.Store{DB: s.DB, Schema: "task"}
		if err := module.BindCommand(r, taskv1.Create, policy, store, s.create); err != nil {
			return err
		}
		if err := module.BindCommand(r, taskv1.Admin, policy, store, s.grants); err != nil {
			return err
		}
	}
	if err := module.BindQuery(r, taskv1.Get, policy, s.get); err != nil {
		return err
	}
	return module.BindQuery(r, taskv1.List, policy, s.list)
}

// Authorize verifies the actual task/root/workspace relation before Access.Check.
// This runs before Command replay, so revocation also denies cached results.
func (s *Service) Authorize(ctx context.Context, root, action string) error {
	if s.GormDB != nil {
		return s.authorizeGORM(ctx, root, action)
	}
	meta, ok := rpc.Metadata(ctx)
	cl, verified := rpc.VerifiedClaims(ctx)
	if !ok || !verified || !strings.HasPrefix(cl.Subject, "user:") {
		return security.ErrUnauthenticated
	}
	var q struct {
		Scope
		TaskID string `json:"task_id"`
	}
	if json.Unmarshal(meta.Payload, &q) != nil || root != q.RootID || q.WorkspaceID == "" || cl.WorkspaceID != q.WorkspaceID {
		return security.ErrDenied
	}
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM task.roots WHERE acl_root_id=$1 AND workspace_id=$2 AND state='active')`
	args := []any{root, q.WorkspaceID}
	if cl.Operation == Get {
		query = `SELECT EXISTS(SELECT 1 FROM task.tasks t JOIN task.roots r USING(acl_root_id,workspace_id) WHERE t.acl_root_id=$1 AND t.workspace_id=$2 AND t.id=$3 AND r.state='active')`
		args = append(args, q.TaskID)
	}
	if e := s.DB.QueryRowContext(ctx, query, args...).Scan(&exists); e != nil {
		return security.ErrUnavailable
	}
	if !exists {
		return security.ErrDenied
	}
	return s.Check(ctx, root, action)
}
func (s *Service) create(ctx context.Context, tx *sql.Tx, q CreateRequest) (Task, error) {
	cl, _ := rpc.VerifiedClaims(ctx)
	meta, _ := rpc.Metadata(ctx)
	if strings.TrimSpace(q.Title) == "" {
		return Task{}, &rpc.Error{Code: rpc.CodeValidation, Message: "title is required"}
	}
	now := time.Now().UTC()
	v := Task{ID: NewID(), WorkspaceID: q.WorkspaceID, RootID: q.RootID, Title: q.Title, Status: "open", CreatedBy: strings.TrimPrefix(cl.Subject, "user:"), CreatedAt: now, UpdatedAt: now}
	_, e := tx.ExecContext(ctx, `INSERT INTO task.tasks(id,workspace_id,acl_root_id,title,status,created_by,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, v.ID, v.WorkspaceID, v.RootID, v.Title, v.Status, v.CreatedBy, v.CreatedAt, v.UpdatedAt)
	if e != nil {
		return Task{}, unavailable(e)
	}
	payload, _ := json.Marshal(CreatedEvent{Scope: q.Scope, TaskID: v.ID})
	e = (events.Store{DB: s.DB, Schema: "task"}).Enqueue(ctx, tx, s.Contract, Created, events.Envelope{ID: NewID(), Type: "task.task.created", Version: 1, AggregateID: v.ID, OccurredAt: now, Traceparent: meta.Traceparent, Payload: payload})
	if e != nil {
		return Task{}, unavailable(e)
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO task.audit(task_id,actor,operation,request_id,traceparent) VALUES($1,$2,$3,$4,$5)`, v.ID, v.CreatedBy, Create, meta.RequestID, meta.Traceparent)
	return v, unavailable(e)
}

const columns = `id,workspace_id,acl_root_id,title,status,created_by,created_at,updated_at`

func scan(row interface{ Scan(...any) error }) (Task, error) {
	var v Task
	e := row.Scan(&v.ID, &v.WorkspaceID, &v.RootID, &v.Title, &v.Status, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt)
	return v, e
}
func (s *Service) get(ctx context.Context, q GetRequest) (Task, error) {
	if s.GormDB != nil {
		return s.getGORM(ctx, q)
	}
	v, e := scan(s.DB.QueryRowContext(ctx, `SELECT `+columns+` FROM task.tasks WHERE id=$1 AND workspace_id=$2 AND acl_root_id=$3`, q.TaskID, q.WorkspaceID, q.RootID))
	if e == sql.ErrNoRows {
		return Task{}, &rpc.Error{Code: rpc.CodeNotFound, Message: "task not found"}
	}
	return v, unavailable(e)
}
func (s *Service) list(ctx context.Context, q ListRequest) (ListResponse, error) {
	if s.GormDB != nil {
		return s.listGORM(ctx, q)
	}
	cl, _ := rpc.VerifiedClaims(ctx)
	rows, e := s.DB.QueryContext(ctx, `SELECT `+columns+` FROM task.tasks WHERE workspace_id=$1 AND acl_root_id=$2 AND created_by=$3 ORDER BY created_at,id LIMIT $4`, q.WorkspaceID, q.RootID, strings.TrimPrefix(cl.Subject, "user:"), q.Limit)
	if e != nil {
		return ListResponse{}, unavailable(e)
	}
	defer rows.Close()
	out := ListResponse{Tasks: []Task{}}
	for rows.Next() {
		v, e := scan(rows)
		if e != nil {
			return ListResponse{}, unavailable(e)
		}
		out.Tasks = append(out.Tasks, v)
	}
	return out, unavailable(rows.Err())
}

// PrepareRoot commits the domain binding before issuing its activation receipt.
// Caller must first reserve the root through the approved Access lifecycle.
func (s *Service) PrepareRoot(ctx context.Context, q Scope, key ed25519.PrivateKey, kid, provider string) (string, error) {
	if s.GormDB != nil {
		return s.prepareRootGORM(ctx, q, key, kid, provider)
	}
	_, e := s.DB.ExecContext(ctx, `INSERT INTO task.roots(acl_root_id,workspace_id,state) VALUES($1,$2,'prepared') ON CONFLICT(acl_root_id) DO NOTHING`, q.RootID, q.WorkspaceID)
	if e != nil {
		return "", e
	}
	var workspace string
	if e = s.DB.QueryRowContext(ctx, `SELECT workspace_id FROM task.roots WHERE acl_root_id=$1`, q.RootID).Scan(&workspace); e != nil {
		return "", e
	}
	if workspace != q.WorkspaceID {
		return "", security.ErrDenied
	}
	return access.SignDomainReceipt(key, access.DomainReceipt{Provider: provider, Root: q.RootID, Operation: "activate", Kid: kid, ExpiresAt: time.Now().Add(time.Minute)})
}
func (s *Service) ActivateRoot(ctx context.Context, q Scope) error {
	if s.GormDB != nil {
		return s.activateRootGORM(ctx, q)
	}
	r, e := s.DB.ExecContext(ctx, `UPDATE task.roots SET state='active' WHERE acl_root_id=$1 AND workspace_id=$2`, q.RootID, q.WorkspaceID)
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return security.ErrDenied
	}
	return nil
}

// GrantCommand is an internal provisioning operation; HTTP exposure is disabled.
func (s *Service) grants(ctx context.Context, tx *sql.Tx, q GrantCommand) (taskv1.GrantResult, error) {
	result, err := s.grantsAccess(ctx, tx, q)
	return taskv1.GrantResult{
		ResourceID: result.ResourceID, GrantID: result.GrantID,
		State: result.State, Revision: result.Revision,
	}, err
}
func (s *Service) grantsAccess(ctx context.Context, tx *sql.Tx, q GrantCommand) (access.MutationResult, error) {
	op := "grants.add"
	if q.GrantID != "" {
		op = "grants.revoke"
	}
	client := s.Identity
	meta, _ := rpc.Metadata(ctx)
	client.IdempotencyKey = "task.grants:" + meta.IdempotencyKey
	ctx, e := InvocationContext(ctx, client, identity.Target{Audience: "access/v1", Operation: "access.v1." + op})
	if e != nil {
		return access.MutationResult{}, e
	}
	ac := &access.Client{RPC: client.RPC}
	if q.GrantID != "" {
		return ac.RevokeGrant(ctx, access.RevokeRequest{GrantID: q.GrantID})
	}
	return ac.AddGrant(ctx, access.GrantRequest{ResourceID: q.RootID, PrincipalKind: q.PrincipalKind, PrincipalID: q.PrincipalID, Action: q.Action})
}
