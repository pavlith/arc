package pages

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pavlith/arc/sdk/database"
	v1 "github.com/pavlith/arc/services/pages/api/v1"
	"github.com/pavlith/arc/services/pages/document"
	"github.com/pavlith/arc/services/pages/models"
	"gorm.io/gorm"
)

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func metadata(row models.Page) v1.Metadata {
	return v1.Metadata{Scope: v1.Scope{WorkspaceID: row.WorkspaceID, RootID: row.RootID}, ID: row.ID, ParentID: str(row.ParentID), Title: row.Title, Revision: row.Revision, Archived: row.ArchivedAt != nil, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
}
func page(row models.Page) v1.Page {
	return v1.Page{Metadata: metadata(row), Document: json.RawMessage(row.Document)}
}
func mutation(row models.Page) v1.Mutation {
	return v1.Mutation{ID: row.ID, Revision: row.Revision, Archived: row.ArchivedAt != nil, UpdatedAt: row.UpdatedAt}
}
func (s *Module) row(ctx context.Context, db *gorm.DB, q v1.PageRef) (models.Page, error) {
	var row models.Page
	err := db.WithContext(ctx).Where("id=? AND workspace_id=? AND acl_root_id=? AND archived_at IS NULL", q.PageID, q.WorkspaceID, q.RootID).Take(&row).Error
	return row, dbError(err)
}
func (s *Module) validate(ctx context.Context, in v1.Input) (v1.Input, error) {
	in.Title = strings.TrimSpace(in.Title)
	if !utf8.ValidString(in.Title) || in.Title == "" || utf8.RuneCountInString(in.Title) > 256 {
		return in, invalid()
	}
	refs, err := document.Validate(in.Document)
	if err != nil {
		return in, invalid()
	}
	for _, ref := range refs {
		if _, err := s.Lookup(ctx, ref); err != nil {
			return in, err
		}
	}
	return in, nil
}
func (s *Module) parent(ctx context.Context, tx *gorm.DB, scope v1.Scope, parent, moving string) (int, error) {
	depth := 0
	for parent != "" {
		if parent == moving || depth >= 32 {
			return 0, invalid()
		}
		row, err := s.row(ctx, tx, v1.PageRef{Scope: scope, PageID: parent})
		if err != nil {
			return 0, err
		}
		parent = str(row.ParentID)
		depth++
	}
	return depth, nil
}
func (s *Module) create(ctx context.Context, tx *gorm.DB, q v1.Create) (v1.Page, error) {
	if q.TemplateID != "" {
		return v1.Page{}, invalid()
	}
	in, err := s.validate(database.TransactionContext(ctx, s.DB, tx), q.Input)
	if err != nil {
		return v1.Page{}, err
	}
	depth, err := s.parent(ctx, tx, q.Scope, q.ParentID, "")
	if err != nil {
		return v1.Page{}, err
	}
	if depth >= 32 {
		return v1.Page{}, invalid()
	}
	var count int64
	if err := tx.Model(&models.Page{}).Where("workspace_id=? AND acl_root_id=?", q.WorkspaceID, q.RootID).Count(&count).Error; err != nil {
		return v1.Page{}, dbError(err)
	}
	if count >= 10000 {
		return v1.Page{}, invalid()
	}
	now := time.Now().UTC()
	row := models.Page{ID: newID(), WorkspaceID: q.WorkspaceID, RootID: q.RootID, ParentID: pointer(q.ParentID), Title: in.Title, Document: string(in.Document), Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := tx.Create(&row).Error; err != nil {
		return v1.Page{}, dbError(err)
	}
	if err := s.record(ctx, tx, row, "created"); err != nil {
		return v1.Page{}, err
	}
	return page(row), nil
}
func (s *Module) get(ctx context.Context, q v1.PageRef) (v1.Page, error) {
	row, err := s.row(ctx, s.db(ctx), q)
	if err != nil {
		return v1.Page{}, err
	}
	return page(row), nil
}
func (s *Module) record(ctx context.Context, tx *gorm.DB, row models.Page, action string) error {
	if err := tx.Exec("INSERT INTO versions(page_id,revision,title,document,created_at) VALUES(?,?,?,?,?)", row.ID, row.Revision, row.Title, row.Document, row.UpdatedAt).Error; err != nil {
		return dbError(err)
	}
	if err := tx.Exec("DELETE FROM versions WHERE page_id=? AND revision<=?", row.ID, row.Revision-100).Error; err != nil {
		return dbError(err)
	}
	return s.changed(ctx, tx, row, action)
}
func (s *Module) save(ctx context.Context, tx *gorm.DB, row models.Page, revision int64, action string) (models.Page, error) {
	now := time.Now().UTC()
	if !now.After(row.UpdatedAt) {
		now = row.UpdatedAt.Add(time.Nanosecond)
	}
	row.UpdatedAt = now
	row.Revision = revision + 1
	res := tx.Model(&models.Page{}).Where("id=? AND workspace_id=? AND acl_root_id=? AND revision=? AND archived_at IS NULL", row.ID, row.WorkspaceID, row.RootID, revision).Updates(map[string]any{"title": row.Title, "document": row.Document, "parent_id": row.ParentID, "revision": row.Revision, "updated_at": row.UpdatedAt, "archived_at": row.ArchivedAt})
	if res.Error != nil {
		return row, dbError(res.Error)
	}
	if res.RowsAffected != 1 {
		return row, conflict()
	}
	return row, s.record(ctx, tx, row, action)
}
func (s *Module) update(ctx context.Context, tx *gorm.DB, q v1.Update) (v1.Page, error) {
	row, err := s.row(ctx, tx, q.PageRef)
	if err != nil {
		return v1.Page{}, err
	}
	if q.Revision < 1 || q.Revision != row.Revision {
		return v1.Page{}, conflict()
	}
	in, err := s.validate(database.TransactionContext(ctx, s.DB, tx), q.Input)
	if err != nil {
		return v1.Page{}, err
	}
	row.Title, row.Document = in.Title, string(in.Document)
	row, err = s.save(ctx, tx, row, q.Revision, "updated")
	return page(row), err
}
func (s *Module) move(ctx context.Context, tx *gorm.DB, q v1.Move) (v1.Mutation, error) {
	row, err := s.row(ctx, tx, q.PageRef)
	if err != nil {
		return v1.Mutation{}, err
	}
	if q.Revision != row.Revision || q.Revision < 1 {
		return v1.Mutation{}, conflict()
	}
	depth, err := s.parent(ctx, tx, q.Scope, q.ParentID, row.ID)
	if err != nil {
		return v1.Mutation{}, err
	}
	var height int
	if err := tx.Raw(`WITH RECURSIVE tree(id,depth) AS (SELECT ?,1 UNION ALL SELECT p.id,t.depth+1 FROM pages p JOIN tree t ON p.parent_id=t.id WHERE p.workspace_id=? AND p.acl_root_id=? AND p.archived_at IS NULL AND t.depth<33) SELECT max(depth) FROM tree`, row.ID, row.WorkspaceID, row.RootID).Row().Scan(&height); err != nil {
		return v1.Mutation{}, dbError(err)
	}
	if depth+height > 32 {
		return v1.Mutation{}, invalid()
	}
	row.ParentID = pointer(q.ParentID)
	row, err = s.save(ctx, tx, row, q.Revision, "moved")
	return mutation(row), err
}
func (s *Module) archive(ctx context.Context, tx *gorm.DB, q v1.Archive) (v1.Mutation, error) {
	row, err := s.row(ctx, tx, q.PageRef)
	if err != nil {
		return v1.Mutation{}, err
	}
	if q.Revision != row.Revision || q.Revision < 1 {
		return v1.Mutation{}, conflict()
	}
	var children int64
	if err := tx.Model(&models.Page{}).Where("parent_id=? AND workspace_id=? AND acl_root_id=? AND archived_at IS NULL", row.ID, q.WorkspaceID, q.RootID).Count(&children).Error; err != nil {
		return v1.Mutation{}, dbError(err)
	}
	if children != 0 {
		return v1.Mutation{}, conflict()
	}
	now := time.Now().UTC()
	row.ArchivedAt = &now
	row, err = s.save(ctx, tx, row, q.Revision, "archived")
	return mutation(row), err
}
func (s *Module) list(ctx context.Context, q v1.List) (v1.PageList, error) {
	out := v1.PageList{Pages: []v1.Metadata{}}
	if q.Limit < 1 || q.Limit > 100 || utf8.RuneCountInString(q.Query) > 256 {
		return out, invalid()
	}
	db := s.db(ctx).Model(&models.Page{}).Where("workspace_id=? AND acl_root_id=? AND archived_at IS NULL AND id>?", q.WorkspaceID, q.RootID, q.Cursor)
	if q.ParentID != "" {
		if _, err := s.row(ctx, s.db(ctx), v1.PageRef{Scope: q.Scope, PageID: q.ParentID}); err != nil {
			return out, err
		}
		db = db.Where("parent_id=?", q.ParentID)
	} else if q.Query == "" {
		db = db.Where("parent_id IS NULL")
	}
	if q.Query != "" {
		db = db.Where("instr(title,?)>0", q.Query)
	}
	var rows []models.Page
	if err := db.Order("id").Limit(q.Limit + 1).Find(&rows).Error; err != nil {
		return out, dbError(err)
	}
	if len(rows) > q.Limit {
		rows = rows[:q.Limit]
		out.NextCursor = rows[len(rows)-1].ID
	}
	for _, row := range rows {
		out.Pages = append(out.Pages, metadata(row))
	}
	return out, nil
}
func (s *Module) versions(ctx context.Context, q v1.VersionList) (v1.Versions, error) {
	out := v1.Versions{Versions: []v1.Version{}}
	if q.Limit < 1 || q.Limit > 100 || q.Before < 0 {
		return out, invalid()
	}
	if _, err := s.row(ctx, s.db(ctx), q.PageRef); err != nil {
		return out, err
	}
	db := s.db(ctx).Table("versions").Where("page_id=?", q.PageID)
	if q.Before > 0 {
		db = db.Where("revision<?", q.Before)
	}
	var rows []v1.Version
	if err := db.Order("revision DESC").Limit(q.Limit + 1).Find(&rows).Error; err != nil {
		return out, dbError(err)
	}
	if len(rows) > q.Limit {
		rows = rows[:q.Limit]
		out.NextBefore = rows[len(rows)-1].Revision
	}
	out.Versions = append(out.Versions, rows...)
	return out, nil
}
func (s *Module) restore(ctx context.Context, tx *gorm.DB, q v1.Restore) (v1.Page, error) {
	if q.Version < 1 {
		return v1.Page{}, invalid()
	}
	row, err := s.row(ctx, tx, q.PageRef)
	if err != nil {
		return v1.Page{}, err
	}
	if row.Revision != q.Revision || q.Revision < 1 {
		return v1.Page{}, conflict()
	}
	var stored struct {
		Title    string
		Document string
	}
	if err := tx.Table("versions").Select("title,document").Where("page_id=? AND revision=?", q.PageID, q.Version).Take(&stored).Error; err != nil {
		return v1.Page{}, dbError(err)
	}
	in, err := s.validate(database.TransactionContext(ctx, s.DB, tx), v1.Input{Title: stored.Title, Document: json.RawMessage(stored.Document)})
	if err != nil {
		return v1.Page{}, err
	}
	row.Title, row.Document = in.Title, string(in.Document)
	row, err = s.save(ctx, tx, row, q.Revision, "restored")
	return page(row), err
}
