package calendar

import (
	"context"
	"encoding/json"

	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/calendar/api/v1"
	"github.com/pavlith/arc/services/calendar/models"
	"gorm.io/gorm"
)

const maxObjectBatchBytes = 200 << 10

func (s *Module) multigetObjects(ctx context.Context, q v1.ObjectBatchQuery) (v1.ObjectBatchResult, error) {
	out := v1.ObjectBatchResult{Scope: q.Scope, Items: []v1.ObjectBatchItem{}}
	if len(q.Objects) < 1 || len(q.Objects) > 100 || q.Offset < 0 || q.Offset >= len(q.Objects) {
		return out, invalid()
	}
	ids := make([]string, 0, len(q.Objects))
	seen := map[string]bool{}
	for _, target := range q.Objects {
		if !idPattern.MatchString(target.EventID) || seen[target.EventID] || target.KnownETag != "" && !strongETag.MatchString(target.KnownETag) {
			return out, invalid()
		}
		seen[target.EventID] = true
		ids = append(ids, target.EventID)
	}
	// All lookups are owner-local and bind the actual workspace/root. A known ID
	// outside the collection is indistinguishable from an unknown/deleted ID.
	err := s.db(ctx).Transaction(func(tx *gorm.DB) error {
		var rows []models.Event
		if err := tx.Where("workspace_id=? AND acl_root_id=? AND deleted_at IS NULL AND id IN ?", q.WorkspaceID, q.RootID, ids[q.Offset:]).Find(&rows).Error; err != nil {
			return dbError(err)
		}
		found := make(map[string]models.Event, len(rows))
		for _, row := range rows {
			found[row.ID] = row
		}
		for i := q.Offset; i < len(q.Objects); i++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			target := q.Objects[i]
			item := v1.ObjectBatchItem{EventID: target.EventID, Status: "not_found"}
			if row, exists := found[target.EventID]; exists {
				item.UID = row.UID
				item.Revision = row.Revision
				current, err := object(row)
				if err != nil {
					if rpc.ErrorCode(err) != rpc.CodeValidation {
						return err
					}
					item.Status = "unsupported"
				} else {
					item.ETag = current.ETag
					if target.KnownETag == current.ETag {
						item.Status = "not_modified"
					} else {
						item.Status = "ok"
						item.Data = current.Data
					}
				}
			}
			candidate := out
			candidate.Items = append(append([]v1.ObjectBatchItem(nil), out.Items...), item)
			// Include pessimistic continuation overhead while measuring actual encoded
			// JSON (including escaping), leaving room for the ordinary RPC envelope.
			candidate.NextIndex = i + 1
			raw, err := json.Marshal(candidate)
			if err != nil {
				return security.ErrUnavailable
			}
			if len(raw) > maxObjectBatchBytes {
				if len(out.Items) == 0 {
					return security.ErrUnavailable
				}
				out.NextIndex = i
				return nil
			}
			out.Items = candidate.Items
		}
		out.Complete = true
		return nil
	})
	if err != nil {
		return v1.ObjectBatchResult{Scope: q.Scope, Items: []v1.ObjectBatchItem{}}, err
	}
	return out, nil
}
