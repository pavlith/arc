package contacts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"

	v1 "github.com/pavlith/arc/services/contacts/api/v1"
	"github.com/pavlith/arc/services/contacts/models"
	"gorm.io/gorm"
)

var strongETag = regexp.MustCompile(`^"[0-9a-f]{64}"$`)

func object(row models.Contact) (v1.VCardObject, error) {
	in, err := dto(row)
	if err != nil {
		return v1.VCardObject{}, err
	}
	data := row.VCardRaw
	if data == "" {
		data, err = renderVCard(in.Input, row.UID, "")
		if err != nil {
			return v1.VCardObject{}, err
		}
	}

	// A strong object validator also changes on same-second writes with identical
	// projections. UID alone or an imported REV never bypasses owner CAS.
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d\n%s", row.Revision, data)))
	return v1.VCardObject{Scope: v1.Scope{WorkspaceID: row.WorkspaceID, RootID: row.RootID}, ContactID: row.ID, UID: row.UID, ETag: `"` + hex.EncodeToString(sum[:]) + `"`, Revision: row.Revision, Data: data}, nil
}
func (s *Module) getObject(ctx context.Context, q v1.ContactRef) (v1.VCardObject, error) {
	row, err := s.row(ctx, s.db(ctx), q)
	if err != nil {
		return v1.VCardObject{}, err
	}
	return object(row)
}
func (s *Module) createObject(ctx context.Context, tx *gorm.DB, q v1.ObjectCreate) (v1.VCardObject, error) {
	if !idPattern.MatchString(q.ContactID) || !q.IfNoneMatch {
		return v1.VCardObject{}, invalid()
	}
	uid, in, data, err := parseVCard(q.Data)
	if err != nil {
		return v1.VCardObject{}, err
	}
	// Retain tombstone UID reservations; stale clients cannot resurrect deleted
	// content by reusing a different contact URL or an old UID.
	var count int64
	if err = tx.Model(&models.Contact{}).Where("id=? OR (workspace_id=? AND acl_root_id=? AND uid=?)", q.ContactID, q.WorkspaceID, q.RootID, uid).Count(&count).Error; err != nil {
		return v1.VCardObject{}, dbError(err)
	}
	if count != 0 {
		return v1.VCardObject{}, conflict()
	}
	_, err = s.createStored(ctx, tx, v1.Create{Scope: q.Scope, Input: in}, q.ContactID, uid, data)
	if err != nil {
		return v1.VCardObject{}, err
	}
	row, err := s.row(ctx, tx, q.ContactRef)
	if err != nil {
		return v1.VCardObject{}, err
	}
	return object(row)
}
func (s *Module) updateObject(ctx context.Context, tx *gorm.DB, q v1.ObjectUpdate) (v1.VCardObject, error) {
	if !strongETag.MatchString(q.IfMatch) {
		return v1.VCardObject{}, invalid()
	}
	row, err := s.row(ctx, tx, q.ContactRef)
	if err != nil {
		return v1.VCardObject{}, err
	}
	old, err := object(row)
	if err != nil {
		return v1.VCardObject{}, err
	}
	if old.ETag != q.IfMatch {
		return v1.VCardObject{}, conflict()
	}
	uid, in, data, err := parseVCard(q.Data)
	if err != nil {
		return v1.VCardObject{}, err
	}
	if uid != row.UID {
		return v1.VCardObject{}, conflict()
	}
	// Store opaque data before the common audit/outbox hook records the mutation.
	_, err = s.updateStored(ctx, tx, v1.Update{ContactRef: q.ContactRef, Input: in, Revision: row.Revision}, &data)
	if err != nil {
		return v1.VCardObject{}, err
	}
	row, err = s.row(ctx, tx, q.ContactRef)
	if err != nil {
		return v1.VCardObject{}, err
	}
	return object(row)
}
func (s *Module) deleteObject(ctx context.Context, tx *gorm.DB, q v1.ObjectDelete) (v1.Mutation, error) {
	if !strongETag.MatchString(q.IfMatch) {
		return v1.Mutation{}, invalid()
	}
	row, err := s.row(ctx, tx, q.ContactRef)
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
	return s.delete(ctx, tx, v1.Delete{ContactRef: q.ContactRef, Revision: row.Revision})
}
