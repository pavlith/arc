package tasks

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/access"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
	"github.com/pavlith/arc/services/task/models"
	"gorm.io/gorm"
)

func toTask(v models.Task) Task {
	return Task{
		ID: v.ID, WorkspaceID: v.WorkspaceID, RootID: v.RootID,
		Title: v.Title, Status: v.Status, CreatedBy: v.CreatedBy,
		CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt,
	}
}

// createGORM executes only inside Command's replay transaction.
func (s *Service) createGORM(ctx context.Context, tx *gorm.DB, q CreateRequest) (Task, error) {
	cl, _ := rpc.VerifiedClaims(ctx)
	meta, _ := rpc.Metadata(ctx)
	if strings.TrimSpace(q.Title) == "" {
		return Task{}, &rpc.Error{Code: rpc.CodeValidation, Message: "title is required"}
	}
	now := time.Now().UTC()
	row := models.Task{
		ID: NewID(), WorkspaceID: q.WorkspaceID, RootID: q.RootID,
		Title: q.Title, Status: "open", CreatedBy: strings.TrimPrefix(cl.Subject, "user:"),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := tx.WithContext(ctx).Create(&row).Error; err != nil {
		return Task{}, unavailable(err)
	}
	payload, _ := json.Marshal(CreatedEvent{Scope: q.Scope, TaskID: row.ID})
	if err := (events.Store{DB: s.GormDB}).Enqueue(ctx, tx, s.Contract, Created,
		events.Envelope{
			ID: NewID(), Type: taskv1.CreatedName, Version: 1, AggregateID: row.ID,
			OccurredAt: now, Traceparent: meta.Traceparent, Payload: payload,
		}); err != nil {
		return Task{}, unavailable(err)
	}
	if err := tx.WithContext(ctx).Create(&models.Audit{
		TaskID: row.ID, Actor: row.CreatedBy, Operation: Create,
		RequestID: meta.RequestID, Traceparent: meta.Traceparent,
		CreatedAt: now,
	}).Error; err != nil {
		return Task{}, unavailable(err)
	}
	return toTask(row), nil
}

// Access mutation is done through its independently authorized Core RPC;
// the local command_result is only marked complete after the RPC succeeds.
func (s *Service) grantsGORM(ctx context.Context, tx *gorm.DB, q GrantCommand) (taskv1.GrantResult, error) {
	result, err := s.grantsAccess(ctx, q)
	return taskv1.GrantResult{
		ResourceID: result.ResourceID, GrantID: result.GrantID,
		State: result.State, Revision: result.Revision,
	}, err
}

func (s *Service) getGORM(ctx context.Context, q GetRequest) (Task, error) {
	var row models.Task
	result := s.GormDB.WithContext(ctx).
		Where("id=? AND workspace_id=? AND acl_root_id=?", q.TaskID, q.WorkspaceID, q.RootID).
		Take(&row)
	if result.Error == gorm.ErrRecordNotFound {
		return Task{}, &rpc.Error{Code: rpc.CodeNotFound, Message: "task not found"}
	}
	if result.Error != nil {
		return Task{}, unavailable(result.Error)
	}
	return toTask(row), nil
}

func (s *Service) listGORM(ctx context.Context, q ListRequest) (ListResponse, error) {
	cl, _ := rpc.VerifiedClaims(ctx)
	var rows []models.Task
	result := s.GormDB.WithContext(ctx).
		Where("workspace_id=? AND acl_root_id=? AND created_by=?", q.WorkspaceID, q.RootID, strings.TrimPrefix(cl.Subject, "user:")).
		Order("created_at, id").Limit(q.Limit).Find(&rows)
	if result.Error != nil {
		return ListResponse{}, unavailable(result.Error)
	}
	out := ListResponse{Tasks: make([]Task, 0, len(rows))}
	for _, row := range rows {
		out.Tasks = append(out.Tasks, toTask(row))
	}
	return out, nil
}

func (s *Service) authorizeGORM(ctx context.Context, root, action string) error {
	meta, ok := rpc.Metadata(ctx)
	cl, verified := rpc.VerifiedClaims(ctx)
	if !ok || !verified || !strings.HasPrefix(cl.Subject, "user:") {
		return security.ErrUnauthenticated
	}
	var q struct {
		Scope
		TaskID string `json:"task_id"`
	}
	if json.Unmarshal(meta.Payload, &q) != nil || root != q.RootID ||
		q.WorkspaceID == "" || cl.WorkspaceID != q.WorkspaceID {
		return security.ErrDenied
	}
	query := "SELECT EXISTS(SELECT 1 FROM roots WHERE acl_root_id=? AND workspace_id=? AND state='active')"
	args := []any{root, q.WorkspaceID}
	if cl.Operation == Get {
		query = `SELECT EXISTS(SELECT 1 FROM tasks t JOIN roots r USING(acl_root_id,workspace_id)
			WHERE t.acl_root_id=? AND t.workspace_id=? AND t.id=? AND r.state='active')`
		args = append(args, q.TaskID)
	}
	var exists bool
	if err := s.GormDB.WithContext(ctx).Raw(query, args...).Row().Scan(&exists); err != nil {
		return security.ErrUnavailable
	}
	if !exists {
		return security.ErrDenied
	}
	return s.Check(ctx, root, action)
}

func (s *Service) prepareRootGORM(ctx context.Context, q Scope, key ed25519.PrivateKey, kid, provider string) (string, error) {
	if err := s.GormDB.WithContext(ctx).
		Exec("INSERT INTO roots(acl_root_id,workspace_id,state) VALUES(?,?,'prepared') ON CONFLICT(acl_root_id) DO NOTHING",
			q.RootID, q.WorkspaceID).Error; err != nil {
		return "", err
	}
	var workspace string
	if err := s.GormDB.WithContext(ctx).Raw("SELECT workspace_id FROM roots WHERE acl_root_id=?", q.RootID).
		Row().Scan(&workspace); err != nil {
		return "", err
	}
	if workspace != q.WorkspaceID {
		return "", security.ErrDenied
	}
	return access.SignDomainReceipt(key, access.DomainReceipt{
		Provider: provider, Root: q.RootID, Operation: "activate",
		Kid: kid, ExpiresAt: time.Now().Add(time.Minute),
	})
}

func (s *Service) activateRootGORM(ctx context.Context, q Scope) error {
	result := s.GormDB.WithContext(ctx).
		Exec("UPDATE roots SET state='active' WHERE acl_root_id=? AND workspace_id=?", q.RootID, q.WorkspaceID)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return security.ErrDenied
	}
	return nil
}
