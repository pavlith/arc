package folders

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mattn/go-sqlite3"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/services/core/modules/access"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/models"
	"gorm.io/gorm"
)

func normalizeName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "." || name == ".." || name == "" ||
		utf8.RuneCountInString(name) > 256 || strings.ContainsAny(name, "/\\") {
		return "", invalid()
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", invalid()
		}
	}
	return name, nil
}
func dbError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return notFound()
	}
	var sq sqlite3.Error
	if errors.As(err, &sq) && (sq.ExtendedCode == sqlite3.ErrConstraintUnique || sq.ExtendedCode == sqlite3.ErrConstraintPrimaryKey) {
		return conflict()
	}
	return unavailable(err)
}
func toFolder(v models.Folder) filesv1.Folder {
	out := filesv1.Folder{
		Scope: filesv1.Scope{WorkspaceID: v.WorkspaceID, RootID: v.RootID},
		ID: v.ID, Name: v.Name, Revision: v.Revision, Archived: v.ArchivedAt != nil,
		CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt,
	}
	if v.ParentID != nil {
		out.ParentID = *v.ParentID
	}
	return out
}
func getFolder(ctx context.Context, db *gorm.DB, q filesv1.FolderRef) (models.Folder, error) {
	var row models.Folder
	err := db.WithContext(ctx).Where(
		"id=? AND workspace_id=? AND acl_root_id=? AND archived_at IS NULL",
		q.FolderID, q.WorkspaceID, q.RootID).Take(&row).Error
	return row, dbError(err)
}
func parentPointer(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
func (s *Service) create(ctx context.Context, tx *gorm.DB, q filesv1.FolderCreateRequest) (filesv1.Folder, error) {
	name, err := normalizeName(q.Name)
	if err != nil {
		return filesv1.Folder{}, err
	}
	if q.ParentID != "" {
		if _, err := getFolder(ctx, tx, filesv1.FolderRef{Scope: q.Scope, FolderID: q.ParentID}); err != nil {
			return filesv1.Folder{}, err
		}
	}
	now := time.Now().UTC()
	row := models.Folder{
		ID: NewID(), WorkspaceID: q.WorkspaceID, RootID: q.RootID,
		ParentID: parentPointer(q.ParentID), Name: name, Revision: 1,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := tx.WithContext(ctx).Create(&row).Error; err != nil {
		return filesv1.Folder{}, dbError(err)
	}
	if err := s.changed(ctx, tx, q.Scope, row, "created"); err != nil {
		return filesv1.Folder{}, err
	}
	return toFolder(row), nil
}
func (s *Service) get(ctx context.Context, q filesv1.FolderRef) (filesv1.Folder, error) {
	row, err := getFolder(ctx, s.GormDB, q)
	if err != nil {
		return filesv1.Folder{}, err
	}
	return toFolder(row), nil
}
func (s *Service) list(ctx context.Context, q filesv1.FolderListRequest) (filesv1.FoldersResult, error) {
	result := filesv1.FoldersResult{Folders: []filesv1.Folder{}}
	if q.Limit < 1 || q.Limit > 100 {
		return result, invalid()
	}
	if q.ParentID != "" {
		if _, err := getFolder(ctx, s.GormDB, filesv1.FolderRef{Scope: q.Scope, FolderID: q.ParentID}); err != nil {
			return result, err
		}
	}
	query := s.GormDB.WithContext(ctx).Where(
		"workspace_id=? AND acl_root_id=? AND archived_at IS NULL AND id>?",
		q.WorkspaceID, q.RootID, q.Cursor)
	if q.ParentID == "" {
		query = query.Where("parent_id IS NULL")
	} else {
		query = query.Where("parent_id=?", q.ParentID)
	}
	var rows []models.Folder
	if err := query.Order("id").Limit(q.Limit+1).Find(&rows).Error; err != nil {
		return result, unavailable(err)
	}
	if len(rows) > q.Limit {
		rows = rows[:q.Limit]
		result.NextCursor = rows[len(rows)-1].ID
	}
	for _, row := range rows {
		result.Folders = append(result.Folders, toFolder(row))
	}
	return result, nil
}

func (s *Service) rename(ctx context.Context, tx *gorm.DB, q filesv1.FolderRenameRequest) (filesv1.Folder, error) {
	name, err := normalizeName(q.Name)
	if err != nil || q.Revision < 1 {
		return filesv1.Folder{}, invalid()
	}
	row, err := getFolder(ctx, tx, q.FolderRef)
	if err != nil {
		return filesv1.Folder{}, err
	}
	if row.Revision != q.Revision {
		return filesv1.Folder{}, conflict()
	}
	now := time.Now().UTC()
	res := tx.WithContext(ctx).Model(&models.Folder{}).
		Where("id=? AND workspace_id=? AND acl_root_id=? AND revision=? AND archived_at IS NULL",
			row.ID, q.WorkspaceID, q.RootID, q.Revision).
		Updates(map[string]any{"name": name, "revision": q.Revision+1, "updated_at": now})
	if err := dbError(res.Error); err != nil {
		return filesv1.Folder{}, err
	}
	if res.RowsAffected != 1 {
		return filesv1.Folder{}, conflict()
	}
	row.Name, row.Revision, row.UpdatedAt = name, row.Revision+1, now
	return toFolder(row), s.changed(ctx, tx, q.Scope, row, "renamed")
}

// A descendant cannot become the parent of its ancestor. Walk the SAME root
// under the command transaction and bound depth to prevent malicious cycles.
func checkMove(ctx context.Context, tx *gorm.DB, q filesv1.FolderMoveRequest) error {
	next := q.ParentID
	for depth := 0; next != ""; depth++ {
		if depth >= 128 || next == q.FolderID {
			return conflict()
		}
		p, err := getFolder(ctx, tx, filesv1.FolderRef{Scope: q.Scope, FolderID: next})
		if err != nil {
			return err
		}
		if p.ParentID == nil {
			break
		}
		next = *p.ParentID
	}
	return nil
}
func (s *Service) move(ctx context.Context, tx *gorm.DB, q filesv1.FolderMoveRequest) (filesv1.Folder, error) {
	if q.Revision < 1 {
		return filesv1.Folder{}, invalid()
	}
	row, err := getFolder(ctx, tx, q.FolderRef)
	if err != nil {
		return filesv1.Folder{}, err
	}
	if row.Revision != q.Revision {
		return filesv1.Folder{}, conflict()
	}
	if err := checkMove(ctx, tx, q); err != nil {
		return filesv1.Folder{}, err
	}
	now := time.Now().UTC()
	res := tx.WithContext(ctx).Model(&models.Folder{}).
		Where("id=? AND workspace_id=? AND acl_root_id=? AND revision=? AND archived_at IS NULL",
			row.ID, q.WorkspaceID, q.RootID, q.Revision).
		Updates(map[string]any{"parent_id": parentPointer(q.ParentID), "revision": q.Revision+1, "updated_at": now})
	if err := dbError(res.Error); err != nil {
		return filesv1.Folder{}, err
	}
	if res.RowsAffected != 1 {
		return filesv1.Folder{}, conflict()
	}
	row.ParentID, row.Revision, row.UpdatedAt = parentPointer(q.ParentID), row.Revision+1, now
	return toFolder(row), s.changed(ctx, tx, q.Scope, row, "moved")
}
func (s *Service) archive(ctx context.Context, tx *gorm.DB, q filesv1.FolderArchiveRequest) (filesv1.Folder, error) {
	if q.Revision < 1 {
		return filesv1.Folder{}, invalid()
	}
	row, err := getFolder(ctx, tx, q.FolderRef)
	if err != nil {
		return filesv1.Folder{}, err
	}
	if row.Revision != q.Revision {
		return filesv1.Folder{}, conflict()
	}
	var children, files int64
	if err := tx.WithContext(ctx).Model(&models.Folder{}).
		Where("parent_id=? AND workspace_id=? AND acl_root_id=? AND archived_at IS NULL",
			row.ID, q.WorkspaceID, q.RootID).Count(&children).Error; err != nil {
		return filesv1.Folder{}, unavailable(err)
	}
	if err := tx.WithContext(ctx).Table("files").Where(
		"folder_id=? AND workspace_id=? AND acl_root_id=? AND state='ready'",
		row.ID, q.WorkspaceID, q.RootID).Count(&files).Error; err != nil {
		return filesv1.Folder{}, unavailable(err)
	}
	if children != 0 || files != 0 {
		return filesv1.Folder{}, conflict()
	}
	now := time.Now().UTC()
	res := tx.WithContext(ctx).Model(&models.Folder{}).
		Where("id=? AND workspace_id=? AND acl_root_id=? AND revision=? AND archived_at IS NULL",
			row.ID, q.WorkspaceID, q.RootID, q.Revision).
		Updates(map[string]any{"archived_at": now, "revision": q.Revision+1, "updated_at": now})
	if err := dbError(res.Error); err != nil {
		return filesv1.Folder{}, err
	}
	if res.RowsAffected != 1 {
		return filesv1.Folder{}, conflict()
	}
	row.ArchivedAt, row.Revision, row.UpdatedAt = &now, row.Revision+1, now
	return toFolder(row), s.changed(ctx, tx, q.Scope, row, "archived")
}
func (s *Service) changed(ctx context.Context, tx *gorm.DB, scope filesv1.Scope, row models.Folder, action string) error {
	cl, _ := rpc.VerifiedClaims(ctx)
	meta, _ := rpc.Metadata(ctx)
	if err := tx.WithContext(ctx).Create(&models.Audit{
		WorkspaceID: scope.WorkspaceID, RootID: scope.RootID, FolderID: row.ID,
		Actor: cl.Subject, Operation: cl.Operation, Revision: row.Revision,
		RequestID: meta.RequestID, Traceparent: meta.Traceparent, CreatedAt: row.UpdatedAt,
	}).Error; err != nil {
		return unavailable(err)
	}
	payload, err := json.Marshal(filesv1.CatalogChanged{
		Scope: scope, EntityKind: "folder", EntityID: row.ID,
		Revision: row.Revision, Action: action,
	})
	if err != nil {
		return unavailable(err)
	}
	return (events.Store{DB: s.GormDB}).Enqueue(ctx, tx, s.Contract, filesv1.CatalogChangedSubject,
		events.Envelope{ID: NewID(), Type: filesv1.CatalogChangedName,
			Version: 1, AggregateID: row.ID, OccurredAt: row.UpdatedAt,
			Traceparent: meta.Traceparent, Payload: payload})
}

// ProvisionRoot is an internal domain lifecycle, not a browser mutation.
func (s *Service) PrepareRoot(ctx context.Context, scope filesv1.Scope,
	key ed25519.PrivateKey, kid, provider string) (string, error) {
	if err := s.GormDB.WithContext(ctx).Exec(
		"INSERT INTO roots(acl_root_id,workspace_id,state) VALUES(?,?,'prepared') ON CONFLICT(acl_root_id) DO NOTHING",
		scope.RootID, scope.WorkspaceID).Error; err != nil {
		return "", unavailable(err)
	}
	var workspace string
	if err := s.GormDB.WithContext(ctx).Raw(
		"SELECT workspace_id FROM roots WHERE acl_root_id=?", scope.RootID).Row().Scan(&workspace); err != nil {
		return "", unavailable(err)
	}
	if workspace != scope.WorkspaceID {
		return "", conflict()
	}
	return access.SignDomainReceipt(key, access.DomainReceipt{
		Provider: provider, Root: scope.RootID, Operation: "activate",
		Kid: kid, ExpiresAt: time.Now().Add(time.Minute),
	})
}
func (s *Service) ActivateRoot(ctx context.Context, scope filesv1.Scope) error {
	res := s.GormDB.WithContext(ctx).Exec(
		"UPDATE roots SET state='active' WHERE acl_root_id=? AND workspace_id=?",
		scope.RootID, scope.WorkspaceID)
	if res.Error != nil {
		return unavailable(res.Error)
	}
	if res.RowsAffected != 1 {
		return conflict()
	}
	return nil
}
