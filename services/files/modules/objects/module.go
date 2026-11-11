// Package objects owns Files upload metadata and ready-file catalog.
// Its private byte store never accepts untrusted RPC payload bytes.
package objects

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mattn/go-sqlite3"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/module"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/models"
	"github.com/pavlith/arc/services/files/modules/folders"
	"github.com/pavlith/arc/services/files/storage"
	"gorm.io/gorm"
)

var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Module struct {
	DB        *gorm.DB
	Contract  *contract.Compiled
	Storage   *storage.Local
	Authorize func(context.Context, string, string) error
	chunkMu   sync.Mutex
}

func (*Module) ID() string { return "objects" }

func (s *Module) Register(r *module.Registry) error {
	if s == nil || s.DB == nil || s.Storage == nil || s.Contract == nil || s.Authorize == nil {
		return module.ErrInvalid
	}
	policy := module.Policy{Resource: s.Authorize}
	store := events.Store{DB: s.DB}
	if err := module.BindCommand(r, filesv1.UploadInitiate, policy, store, s.initiate); err != nil {
		return err
	}
	if err := module.BindQuery(r, filesv1.UploadGet, policy, s.getUpload); err != nil {
		return err
	}
	if err := module.BindCommand(r, filesv1.UploadAbort, policy, store, s.abort); err != nil {
		return err
	}
	if err := module.BindCommand(r, filesv1.UploadComplete, policy, store, s.complete); err != nil {
		return err
	}
	if err := module.BindQuery(r, filesv1.FileGet, policy, s.getFile); err != nil {
		return err
	}
	if err := module.BindQuery(r, filesv1.FileList, policy, s.listFiles); err != nil {
		return err
	}
	return r.AddWorker(module.Worker{ID: "files-upload-cleanup", Run: s.RunCleanup})
}

func invalid() error {
	return &rpc.Error{Code: rpc.CodeValidation, Message: "invalid Files upload metadata"}
}
func conflict() error {
	return &rpc.Error{Code: rpc.CodeConflict, Message: "Files upload state or revision conflict"}
}
func missing() error { return &rpc.Error{Code: rpc.CodeNotFound, Message: "Files entry unavailable"} }
func unavailable(err error) error {
	if err == nil {
		return nil
	}
	var typed *rpc.Error
	if errors.As(err, &typed) {
		return err
	}
	var sqlite sqlite3.Error
	if errors.As(err, &sqlite) && (sqlite.ExtendedCode == sqlite3.ErrConstraintUnique || sqlite.ExtendedCode == sqlite3.ErrConstraintPrimaryKey) {
		return conflict()
	}
	return rpc.SecurityError(security.ErrUnavailable)
}
func validFilename(name string) (string, error) {
	name = strings.TrimSpace(name)
	if !utf8.ValidString(name) || name == "" || name == "." || name == ".." ||
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
func pointer(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
func fromPointer(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
func uploadDTO(v models.Upload) filesv1.Upload {
	return filesv1.Upload{
		Scope: filesv1.Scope{WorkspaceID: v.WorkspaceID, RootID: v.RootID},
		ID:    v.ID, FolderID: fromPointer(v.FolderID), Filename: v.Filename,
		MIME: v.DeclaredMIME, ExpectedSize: v.ExpectedSize, ExpectedSHA256: v.ExpectedSHA256,
		Offset: v.Offset, ExpiresAt: v.ExpiresAt, State: v.State,
	}
}
func fileDTO(v models.File) filesv1.File {
	return filesv1.File{
		Scope: filesv1.Scope{WorkspaceID: v.WorkspaceID, RootID: v.RootID},
		ID:    v.ID, FolderID: fromPointer(v.FolderID), Filename: v.Filename,
		MIME: v.MIME, Size: v.Size, SHA256: v.SHA256, ETag: "\"" + v.SHA256 + "\"",
		Revision: v.Revision, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt,
	}
}

func (s *Module) folder(ctx context.Context, tx *gorm.DB, scope filesv1.Scope, id string) error {
	if id == "" {
		return nil
	}
	var ok bool
	if err := tx.WithContext(ctx).Raw(
		"SELECT EXISTS(SELECT 1 FROM folders WHERE id=? AND workspace_id=? AND acl_root_id=? AND archived_at IS NULL)",
		id, scope.WorkspaceID, scope.RootID).Row().Scan(&ok); err != nil {
		return unavailable(err)
	}
	if !ok {
		return missing()
	}
	return nil
}

func actor(ctx context.Context) (string, string, error) {
	cl, ok := rpc.VerifiedClaims(ctx)
	if !ok || !strings.HasPrefix(cl.Subject, "user:") || cl.SessionID == "" {
		return "", "", security.ErrUnauthenticated
	}
	return cl.Subject, cl.SessionID, nil
}

func (s *Module) initiate(ctx context.Context, tx *gorm.DB, q filesv1.UploadInitiateRequest) (filesv1.Upload, error) {
	name, err := validFilename(q.Filename)
	if err != nil || q.ExpectedSize < 0 || q.ExpectedSize > storage.MaxObjectSize ||
		q.MIME != "application/octet-stream" || q.ExpectedSHA256 != "" && !hashPattern.MatchString(q.ExpectedSHA256) {
		return filesv1.Upload{}, invalid()
	}
	subject, session, err := actor(ctx)
	if err != nil {
		return filesv1.Upload{}, err
	}
	if err := s.folder(ctx, tx, q.Scope, q.FolderID); err != nil {
		return filesv1.Upload{}, err
	}
	meta, ok := rpc.Metadata(ctx)
	if !ok || meta.IdempotencyKey == "" {
		return filesv1.Upload{}, security.ErrUnauthenticated
	}
	now := time.Now().UTC()
	// Bound outstanding reservations until the tenant quota backend is
	// available. This is actor-scoped and counts only unexpired pending rows.
	var reservation struct {
		Count int64
		Bytes int64
	}
	if err := tx.WithContext(ctx).Model(&models.Upload{}).
		Select("count(*) AS count, coalesce(sum(expected_size),0) AS bytes").
		Where("actor_id=? AND state='pending' AND expires_at>?", subject, now).
		Scan(&reservation).Error; err != nil {
		return filesv1.Upload{}, unavailable(err)
	}
	if reservation.Count >= 10 || q.ExpectedSize > 2*storage.MaxObjectSize-reservation.Bytes {
		return filesv1.Upload{}, conflict()
	}
	id := folders.NewID()
	v := models.Upload{
		ID: id, WorkspaceID: q.WorkspaceID, RootID: q.RootID,
		FolderID: pointer(q.FolderID), ActorID: subject, SessionID: session,
		Filename: name, DeclaredMIME: q.MIME, ExpectedSize: q.ExpectedSize,
		ExpectedSHA256: q.ExpectedSHA256, TempKey: id, Offset: 0,
		State: "pending", IdempotencyKey: meta.IdempotencyKey, ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := tx.WithContext(ctx).Create(&v).Error; err != nil {
		return filesv1.Upload{}, unavailable(err)
	}
	if err := s.Storage.Prepare(ctx, id); err != nil {
		return filesv1.Upload{}, unavailable(err)
	}
	return uploadDTO(v), nil
}

func (s *Module) ownUpload(ctx context.Context, db *gorm.DB, ref filesv1.UploadRef) (models.Upload, error) {
	var v models.Upload
	subject, session, err := actor(ctx)
	if err != nil {
		return v, err
	}
	err = db.WithContext(ctx).Where("id=? AND workspace_id=? AND acl_root_id=? AND actor_id=? AND session_id=?",
		ref.UploadID, ref.WorkspaceID, ref.RootID, subject, session).Take(&v).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return v, missing()
	}
	return v, unavailable(err)
}
func (s *Module) getUpload(ctx context.Context, q filesv1.UploadRef) (filesv1.Upload, error) {
	v, err := s.ownUpload(ctx, s.DB, q)
	if err != nil {
		return filesv1.Upload{}, err
	}
	return uploadDTO(v), nil
}
func (s *Module) abort(ctx context.Context, tx *gorm.DB, q filesv1.UploadRef) (filesv1.Upload, error) {
	v, err := s.ownUpload(ctx, tx, q)
	if err != nil {
		return filesv1.Upload{}, err
	}
	if v.State == "aborted" {
		return uploadDTO(v), nil
	}
	if v.State != "pending" {
		return filesv1.Upload{}, conflict()
	}
	now := time.Now().UTC()
	res := tx.WithContext(ctx).Model(&models.Upload{}).
		Where("id=? AND workspace_id=? AND acl_root_id=? AND state='pending'", v.ID, v.WorkspaceID, v.RootID).
		Updates(map[string]any{"state": "aborted", "updated_at": now})
	if err := res.Error; err != nil {
		return filesv1.Upload{}, unavailable(err)
	}
	if res.RowsAffected != 1 {
		return filesv1.Upload{}, conflict()
	}
	// Never delete bytes inside this SQL transaction: a failed commit must
	// leave an intact pending upload. The Files cleanup worker removes bytes
	// only after the aborted state has been committed.
	v.State, v.UpdatedAt = "aborted", now
	return uploadDTO(v), nil
}

func (s *Module) complete(ctx context.Context, tx *gorm.DB, q filesv1.UploadRef) (filesv1.File, error) {
	v, err := s.ownUpload(ctx, tx, q)
	if err != nil {
		return filesv1.File{}, err
	}
	if v.State != "pending" || !v.ExpiresAt.After(time.Now()) {
		return filesv1.File{}, conflict()
	}
	if err := s.folder(ctx, tx, q.Scope, fromPointer(v.FolderID)); err != nil {
		return filesv1.File{}, err
	}
	offset, err := s.Storage.Offset(ctx, v.TempKey)
	if err != nil {
		return filesv1.File{}, unavailable(err)
	}
	if offset != v.Offset || offset != v.ExpectedSize {
		return filesv1.File{}, conflict()
	}
	// The first version accepts binary-only uploads. Content is always
	// downloaded as an attachment; no user-supplied active MIME executes.
	fileID := folders.NewID()
	obj, err := s.Storage.Promote(ctx, v.TempKey, fileID, v.ExpectedSize, v.ExpectedSHA256)
	if err != nil {
		return filesv1.File{}, unavailable(err)
	}
	now := time.Now().UTC()
	row := models.File{
		ID: fileID, WorkspaceID: v.WorkspaceID, RootID: v.RootID, FolderID: v.FolderID,
		Filename: v.Filename, MIME: v.DeclaredMIME, Size: obj.Size, SHA256: obj.SHA256,
		BlobKey: obj.Key, Revision: 1, State: "ready", CreatedAt: now, UpdatedAt: now,
	}
	if err := tx.WithContext(ctx).Create(&row).Error; err != nil {
		return filesv1.File{}, unavailable(err)
	}
	res := tx.WithContext(ctx).Model(&models.Upload{}).
		Where("id=? AND workspace_id=? AND acl_root_id=? AND state='pending'", v.ID, v.WorkspaceID, v.RootID).
		Updates(map[string]any{"state": "completed", "updated_at": now})
	if err := res.Error; err != nil {
		return filesv1.File{}, unavailable(err)
	}
	if res.RowsAffected != 1 {
		return filesv1.File{}, conflict()
	}
	meta, _ := rpc.Metadata(ctx)
	cl, _ := rpc.VerifiedClaims(ctx)
	if err := tx.WithContext(ctx).Create(&models.Audit{
		WorkspaceID: q.WorkspaceID, RootID: q.RootID, FolderID: fileID,
		Actor: cl.Subject, Operation: cl.Operation, Revision: 1,
		RequestID: meta.RequestID, Traceparent: meta.Traceparent, CreatedAt: now,
	}).Error; err != nil {
		return filesv1.File{}, unavailable(err)
	}
	payload, err := json.Marshal(filesv1.CatalogChanged{
		Scope: q.Scope, EntityKind: "file", EntityID: fileID, Revision: 1, Action: "uploaded",
	})
	if err != nil {
		return filesv1.File{}, unavailable(err)
	}
	err = (events.Store{DB: s.DB}).Enqueue(ctx, tx, s.Contract, filesv1.CatalogChangedSubject,
		events.Envelope{ID: folders.NewID(), Type: filesv1.CatalogChangedName,
			Version: 1, AggregateID: fileID, OccurredAt: now,
			Traceparent: meta.Traceparent, Payload: payload})
	if err != nil {
		return filesv1.File{}, unavailable(err)
	}
	return fileDTO(row), nil
}

func normalizeFileError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return missing()
	}
	return unavailable(err)
}

func (s *Module) getFile(ctx context.Context, q filesv1.FileRef) (filesv1.File, error) {
	var v models.File
	err := s.DB.WithContext(ctx).Where(
		"id=? AND workspace_id=? AND acl_root_id=? AND state='ready'",
		q.FileID, q.WorkspaceID, q.RootID).Take(&v).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return filesv1.File{}, missing()
	}
	if err != nil {
		return filesv1.File{}, unavailable(err)
	}
	return fileDTO(v), nil
}
func (s *Module) listFiles(ctx context.Context, q filesv1.FileListRequest) (filesv1.FilesResult, error) {
	out := filesv1.FilesResult{Files: []filesv1.File{}}
	if q.Limit < 1 || q.Limit > 100 {
		return out, invalid()
	}
	if err := s.folder(ctx, s.DB, q.Scope, q.FolderID); err != nil {
		return out, err
	}
	db := s.DB.WithContext(ctx).Model(&models.File{}).
		Where("workspace_id=? AND acl_root_id=? AND state='ready' AND id>?",
			q.WorkspaceID, q.RootID, q.Cursor)
	if q.FolderID == "" {
		db = db.Where("folder_id IS NULL")
	} else {
		db = db.Where("folder_id=?", q.FolderID)
	}
	var rows []models.File
	if err := db.Order("id").Limit(q.Limit + 1).Find(&rows).Error; err != nil {
		return out, unavailable(err)
	}
	if len(rows) > q.Limit {
		rows = rows[:q.Limit]
		out.NextCursor = rows[len(rows)-1].ID
	}
	for _, row := range rows {
		out.Files = append(out.Files, fileDTO(row))
	}
	return out, nil
}
