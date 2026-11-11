package tasks

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pavlith/arc/sdk/resource"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/task/api/v1"
	"github.com/pavlith/arc/services/task/models"
	"gorm.io/gorm"
)

func (s *Service) attachmentPolicy(ctx context.Context) error {
	cl, ok := rpc.VerifiedClaims(ctx)
	if !ok {
		return security.ErrUnauthenticated
	}
	if cl.Operation != v1.AttachmentChangeOp.ID {
		return nil
	}
	meta, _ := rpc.Metadata(ctx)
	var q v1.AttachmentChange
	if json.Unmarshal(meta.Payload, &q) != nil || q.File.Kind != "file" || !q.File.Valid() || q.File.WorkspaceID != q.WorkspaceID {
		return invalidWork()
	}
	if q.Remove {
		return nil
	}
	if s.Resolve == nil {
		return security.ErrUnavailable
	}
	_, err := s.Resolve(ctx, q.File)
	return err
}
func (s *Service) changeAttachment(ctx context.Context, tx *gorm.DB, q v1.AttachmentChange) (v1.AttachmentResult, error) {
	var empty v1.AttachmentResult
	if !q.File.Valid() || q.File.Kind != "file" || q.File.WorkspaceID != q.WorkspaceID || q.Revision < 1 || q.ExpectedUpdatedAt.IsZero() {
		return empty, invalidWork()
	}
	item, err := workItem(ctx, tx, q.GetRequest)
	if err != nil {
		return empty, err
	}
	if item.TeamID == "" || item.Revision != q.Revision || !item.UpdatedAt.Equal(q.ExpectedUpdatedAt) {
		return empty, catalogConflict()
	}
	if q.Remove {
		if err := tx.Exec("DELETE FROM task_attachments WHERE task_id=? AND workspace_id=? AND acl_root_id=? AND file_root_id=? AND file_id=?", q.TaskID, q.WorkspaceID, q.RootID, q.File.RootID, q.File.ID).Error; err != nil {
			return empty, catalogError(err)
		}
	} else {
		var count int64
		if err := tx.Table("task_attachments").Where("task_id=?", q.TaskID).Count(&count).Error; err != nil {
			return empty, catalogError(err)
		}
		if count >= 100 {
			return empty, invalidWork()
		}
		if err := tx.Exec("INSERT INTO task_attachments(task_id,workspace_id,acl_root_id,file_root_id,file_id) VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING", q.TaskID, q.WorkspaceID, q.RootID, q.File.RootID, q.File.ID).Error; err != nil {
			return empty, catalogError(err)
		}
	}
	now := time.Now().UTC()
	if !now.After(item.UpdatedAt) {
		now = item.UpdatedAt.Add(time.Nanosecond)
	}
	res := tx.Model(&models.TaskDetails{}).Where("task_id=? AND revision=?", q.TaskID, q.Revision).Update("revision", q.Revision+1)
	if res.Error != nil {
		return empty, catalogError(res.Error)
	}
	if res.RowsAffected != 1 {
		return empty, catalogConflict()
	}
	if err := tx.Model(&models.Task{}).Where("id=?", q.TaskID).Update("updated_at", now).Error; err != nil {
		return empty, catalogError(err)
	}
	if err := s.catalogChanged(ctx, tx, q.Scope, "work", q.TaskID, q.Revision+1, "attachments"); err != nil {
		return empty, err
	}
	return v1.AttachmentResult{GetRequest: q.GetRequest, Revision: q.Revision + 1, UpdatedAt: now}, nil
}
func (s *Service) listAttachments(ctx context.Context, q v1.GetRequest) (v1.AttachmentList, error) {
	out := v1.AttachmentList{Files: []resource.Ref{}}
	if _, err := workItem(ctx, s.GormDB, q); err != nil {
		return out, err
	}
	var rows []struct {
		FileRootID string
		FileID     string
	}
	if err := s.GormDB.WithContext(ctx).Table("task_attachments").Where("task_id=? AND workspace_id=? AND acl_root_id=?", q.TaskID, q.WorkspaceID, q.RootID).Order("file_root_id,file_id").Limit(100).Scan(&rows).Error; err != nil {
		return out, catalogError(err)
	}
	for _, r := range rows {
		out.Files = append(out.Files, resource.Ref{Kind: "file", WorkspaceID: q.WorkspaceID, RootID: r.FileRootID, ID: r.FileID})
	}
	return out, nil
}
func (s *Service) previewReference(ctx context.Context, q v1.ReferencePreview) (resource.Summary, error) {
	if _, err := workItem(ctx, s.GormDB, q.GetRequest); err != nil {
		return resource.Summary{}, err
	}
	if s.Resolve == nil {
		return resource.Summary{}, security.ErrUnavailable
	}
	return s.Resolve(ctx, q.Target)
}
