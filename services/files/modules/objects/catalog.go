package objects

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/rpc"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/models"
	"github.com/pavlith/arc/services/files/modules/folders"
	"gorm.io/gorm"
)

func readyFile(ctx context.Context, tx *gorm.DB, ref filesv1.FileRef, revision int64) (models.File, error) {
	var row models.File
	if revision < 1 {
		return row, invalid()
	}
	if err := tx.WithContext(ctx).Where("id=? AND workspace_id=? AND acl_root_id=? AND state='ready'",
		ref.FileID, ref.WorkspaceID, ref.RootID).Take(&row).Error; err != nil {
		return row, normalizeFileError(err)
	}
	if row.Revision != revision {
		return row, conflict()
	}
	return row, nil
}

func (s *Module) renameFile(ctx context.Context, tx *gorm.DB, q filesv1.FileRenameRequest) (filesv1.File, error) {
	name, err := validFilename(q.Filename)
	if err != nil {
		return filesv1.File{}, err
	}
	row, err := readyFile(ctx, tx, q.FileRef, q.Revision)
	if err != nil {
		return filesv1.File{}, err
	}
	row.Filename = name
	return s.updateFile(ctx, tx, row, "renamed")
}

func (s *Module) moveFile(ctx context.Context, tx *gorm.DB, q filesv1.FileMoveRequest) (filesv1.File, error) {
	row, err := readyFile(ctx, tx, q.FileRef, q.Revision)
	if err != nil {
		return filesv1.File{}, err
	}
	if err := s.folder(ctx, tx, q.Scope, q.FolderID); err != nil {
		return filesv1.File{}, err
	}
	row.FolderID = pointer(q.FolderID)
	return s.updateFile(ctx, tx, row, "moved")
}

func (s *Module) archiveFile(ctx context.Context, tx *gorm.DB, q filesv1.FileArchiveRequest) (filesv1.File, error) {
	row, err := readyFile(ctx, tx, q.FileRef, q.Revision)
	if err != nil {
		return filesv1.File{}, err
	}
	now := time.Now().UTC()
	row.State, row.ArchivedAt = "archived", &now
	return s.updateFile(ctx, tx, row, "archived")
}

func (s *Module) updateFile(ctx context.Context, tx *gorm.DB, row models.File, action string) (filesv1.File, error) {
	now := time.Now().UTC()
	res := tx.WithContext(ctx).Model(&models.File{}).
		Where("id=? AND workspace_id=? AND acl_root_id=? AND revision=? AND state='ready'",
			row.ID, row.WorkspaceID, row.RootID, row.Revision).
		Updates(map[string]any{"filename": row.Filename, "folder_id": row.FolderID,
			"state": row.State, "archived_at": row.ArchivedAt, "revision": row.Revision + 1, "updated_at": now})
	if res.Error != nil {
		return filesv1.File{}, unavailable(res.Error)
	}
	if res.RowsAffected != 1 {
		return filesv1.File{}, conflict()
	}
	row.Revision++
	row.UpdatedAt = now
	cl, _ := rpc.VerifiedClaims(ctx)
	meta, _ := rpc.Metadata(ctx)
	if err := tx.WithContext(ctx).Create(&models.Audit{
		WorkspaceID: row.WorkspaceID, RootID: row.RootID, FolderID: row.ID,
		Actor: cl.Subject, Operation: cl.Operation, Revision: row.Revision,
		RequestID: meta.RequestID, Traceparent: meta.Traceparent, CreatedAt: now,
	}).Error; err != nil {
		return filesv1.File{}, unavailable(err)
	}
	payload, err := json.Marshal(filesv1.CatalogChanged{
		Scope:      filesv1.Scope{WorkspaceID: row.WorkspaceID, RootID: row.RootID},
		EntityKind: "file", EntityID: row.ID, Revision: row.Revision, Action: action,
	})
	if err != nil {
		return filesv1.File{}, unavailable(err)
	}
	if err := (events.Store{DB: s.DB}).Enqueue(ctx, tx, s.Contract, filesv1.CatalogChangedSubject,
		events.Envelope{ID: folders.NewID(), Type: filesv1.CatalogChangedName, Version: 1,
			AggregateID: row.ID, OccurredAt: now, Traceparent: meta.Traceparent, Payload: payload}); err != nil {
		return filesv1.File{}, unavailable(err)
	}
	return fileDTO(row), nil
}
