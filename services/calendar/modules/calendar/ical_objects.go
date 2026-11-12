package calendar

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"

	v1 "github.com/pavlith/arc/services/calendar/api/v1"
	"github.com/pavlith/arc/services/calendar/models"
	"gorm.io/gorm"
)

var strongETag = regexp.MustCompile(`^"[0-9a-f]{64}"$`)

func object(row models.Event) (v1.ICalObject, error) {
	in := dto(row).Input
	data, err := renderICal(in, row.UID, row.Revision, row.UpdatedAt, row.ICalRaw)
	if err != nil {
		return v1.ICalObject{}, err
	}
	// A strong object validator also changes on same-second writes with identical
	// projections. UID alone or a client SEQUENCE never bypasses owner CAS.
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d\n%s", row.Revision, data)))
	return v1.ICalObject{Scope: v1.Scope{WorkspaceID: row.WorkspaceID, RootID: row.RootID}, EventID: row.ID, UID: row.UID, ETag: `"` + hex.EncodeToString(sum[:]) + `"`, Revision: row.Revision, Data: data}, nil
}
func (s *Module) getObject(ctx context.Context, q v1.EventRef) (v1.ICalObject, error) {
	row, err := s.row(ctx, s.db(ctx), q)
	if err != nil {
		return v1.ICalObject{}, err
	}
	return object(row)
}
func (s *Module) createObject(ctx context.Context, tx *gorm.DB, q v1.ObjectCreate) (v1.ICalObject, error) {
	if !idPattern.MatchString(q.EventID) || !q.IfNoneMatch {
		return v1.ICalObject{}, invalid()
	}
	uid, in, err := parseICal(ctx, q.Data)
	if err != nil {
		return v1.ICalObject{}, err
	}
	// Retain tombstone UID reservations; stale clients cannot resurrect deleted
	// content by reusing a different event URL or an old UID.
	var count int64
	if err = tx.Model(&models.Event{}).Where("id=? OR (workspace_id=? AND acl_root_id=? AND uid=?)", q.EventID, q.WorkspaceID, q.RootID, uid).Count(&count).Error; err != nil {
		return v1.ICalObject{}, dbError(err)
	}
	if count != 0 {
		return v1.ICalObject{}, conflict()
	}
	_, err = s.createStored(ctx, tx, v1.Create{Scope: q.Scope, Input: in}, q.EventID, uid, q.Data)
	if err != nil {
		return v1.ICalObject{}, err
	}
	row, err := s.row(ctx, tx, q.EventRef)
	if err != nil {
		return v1.ICalObject{}, err
	}
	return object(row)
}
func (s *Module) updateObject(ctx context.Context, tx *gorm.DB, q v1.ObjectUpdate) (v1.ICalObject, error) {
	if !strongETag.MatchString(q.IfMatch) {
		return v1.ICalObject{}, invalid()
	}
	row, err := s.row(ctx, tx, q.EventRef)
	if err != nil {
		return v1.ICalObject{}, err
	}
	old, err := object(row)
	if err != nil {
		return v1.ICalObject{}, err
	}
	if old.ETag != q.IfMatch {
		return v1.ICalObject{}, conflict()
	}
	uid, in, err := parseICal(ctx, q.Data)
	if err != nil {
		return v1.ICalObject{}, err
	}
	if uid != row.UID {
		return v1.ICalObject{}, conflict()
	}
	// Store opaque data before the common audit/outbox/sync hook snapshots it.
	_, err = s.updateStored(ctx, tx, v1.Update{EventRef: q.EventRef, Input: in, Revision: row.Revision}, &q.Data)
	if err != nil {
		return v1.ICalObject{}, err
	}
	row, err = s.row(ctx, tx, q.EventRef)
	if err != nil {
		return v1.ICalObject{}, err
	}
	return object(row)
}
func (s *Module) deleteObject(ctx context.Context, tx *gorm.DB, q v1.ObjectDelete) (v1.Mutation, error) {
	if !strongETag.MatchString(q.IfMatch) {
		return v1.Mutation{}, invalid()
	}
	row, err := s.row(ctx, tx, q.EventRef)
	if err != nil {
		return v1.Mutation{}, err
	}
	old, err := object(row)
	if err != nil {
		return v1.Mutation{}, err
	}
	if old.ETag != q.IfMatch {
		return v1.Mutation{}, conflict()
	}
	return s.delete(ctx, tx, v1.Delete{EventRef: q.EventRef, Revision: row.Revision})
}
