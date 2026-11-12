package calendar

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/calendar/api/v1"
	"github.com/pavlith/arc/services/calendar/models"
	"gorm.io/gorm"
)

const syncHistoryLimit int64 = 10000
const syncTokenPrefix = "urn:arc:calendar:sync:v1:"
const syncCursorPrefix = "arc-calendar-page-v1:"

var epochPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type syncReference struct {
	WorkspaceID string `json:"workspace_id"`
	RootID      string `json:"root_id"`
	Epoch       string `json:"epoch"`
	Revision    int64  `json:"revision"`
}
type syncPage struct {
	syncReference
	Mode          string `json:"mode"`
	Since         int64  `json:"since"`
	AfterID       string `json:"after_id,omitempty"`
	AfterSequence int64  `json:"after_sequence,omitempty"`
}

func syncInvalid() error {
	return &rpc.Error{Code: rpc.CodeConflict, Message: "Calendar sync token invalid; restart full sync"}
}
func syncEncode(prefix string, value any) string {
	raw, _ := json.Marshal(value)
	return prefix + base64.RawURLEncoding.EncodeToString(raw)
}
func syncDecode(value, prefix string, dst any, max int) error {
	if len(value) > max || !strings.HasPrefix(value, prefix) {
		return syncInvalid()
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil || contract.Strict(raw, dst) != nil {
		return syncInvalid()
	}
	return nil
}
func syncRef(root models.Root) syncReference {
	return syncReference{WorkspaceID: root.WorkspaceID, RootID: root.RootID, Epoch: root.SyncEpoch, Revision: root.SyncRevision}
}
func (r syncReference) valid(root models.Root) bool {
	return r.RootID == root.RootID && r.WorkspaceID == root.WorkspaceID && r.Epoch == root.SyncEpoch && r.Revision >= root.SyncFloor && r.Revision <= root.SyncRevision
}
func syncMetadata(row models.Event) (v1.SyncItem, error) {
	item := v1.SyncItem{EventID: row.ID, UID: row.UID, Revision: row.Revision, State: "deleted"}
	if row.DeletedAt != nil {
		return item, nil
	}
	current, err := object(row)
	if err != nil {
		if rpc.ErrorCode(err) != rpc.CodeValidation {
			return item, err
		}
		item.State = "unsupported"
	} else {
		item.State = "active"
		item.ETag = current.ETag
	}
	return item, nil
}
func (s *Module) recordSync(ctx context.Context, tx *gorm.DB, scope v1.Scope, id string) error {
	var root models.Root
	if err := tx.WithContext(ctx).Where("acl_root_id=? AND workspace_id=?", scope.RootID, scope.WorkspaceID).Take(&root).Error; err != nil {
		return dbError(err)
	}
	// Pre-upgrade roots remain usable through existing APIs, but cannot issue a
	// sync token until the explicit owner bootstrap has populated their baseline.
	if !root.SyncReady {
		return nil
	}
	if !epochPattern.MatchString(root.SyncEpoch) {
		return security.ErrUnavailable
	}
	var row models.Event
	if err := tx.WithContext(ctx).Where("id=? AND workspace_id=? AND acl_root_id=?", id, scope.WorkspaceID, scope.RootID).Take(&row).Error; err != nil {
		return dbError(err)
	}
	item, err := syncMetadata(row)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(item)
	if err != nil {
		return security.ErrUnavailable
	}
	var previous string
	err = tx.Raw("SELECT entry FROM sync_items WHERE workspace_id=? AND acl_root_id=? AND event_id=?", scope.WorkspaceID, scope.RootID, id).Row().Scan(&previous)
	var before any
	if err == nil {
		before = previous
	} else if !errors.Is(err, sql.ErrNoRows) {
		return dbError(err)
	}
	var sequence int64
	if err = tx.Raw("UPDATE roots SET sync_revision=sync_revision+1 WHERE acl_root_id=? AND workspace_id=? AND sync_revision<9223372036854775807 RETURNING sync_revision", scope.RootID, scope.WorkspaceID).Row().Scan(&sequence); err != nil {
		return dbError(err)
	}
	if err = tx.Exec("INSERT INTO sync_changes(workspace_id,acl_root_id,sequence,event_id,previous,entry) VALUES(?,?,?,?,?,?)", scope.WorkspaceID, scope.RootID, sequence, id, before, string(raw)).Error; err != nil {
		return dbError(err)
	}
	if err = tx.Exec("INSERT INTO sync_items(workspace_id,acl_root_id,event_id,sequence,entry) VALUES(?,?,?,?,?) ON CONFLICT(workspace_id,acl_root_id,event_id) DO UPDATE SET sequence=excluded.sequence,entry=excluded.entry", scope.WorkspaceID, scope.RootID, id, sequence, string(raw)).Error; err != nil {
		return dbError(err)
	}
	floor := sequence - syncHistoryLimit
	if floor > 0 {
		if err = tx.Exec("DELETE FROM sync_changes WHERE workspace_id=? AND acl_root_id=? AND sequence<=?", scope.WorkspaceID, scope.RootID, floor).Error; err != nil {
			return dbError(err)
		}
		if err = tx.Exec("UPDATE roots SET sync_floor=? WHERE workspace_id=? AND acl_root_id=?", floor, scope.WorkspaceID, scope.RootID).Error; err != nil {
			return dbError(err)
		}
	}
	return nil
}
func (s *Module) syncCollection(ctx context.Context, q v1.SyncQuery) (v1.SyncResult, error) {
	out := v1.SyncResult{Scope: q.Scope, Items: []v1.SyncItem{}}
	if q.Limit < 1 || q.Limit > 100 || q.Token != "" && q.Cursor != "" {
		return out, invalid()
	}
	err := s.db(ctx).Transaction(func(tx *gorm.DB) error {
		// Head/floor and all page rows come from one SQLite WAL read snapshot.
		var root models.Root
		if err := tx.Where("acl_root_id=? AND workspace_id=? AND state='active'", q.RootID, q.WorkspaceID).Take(&root).Error; err != nil {
			return dbError(err)
		}
		if !root.SyncReady || !epochPattern.MatchString(root.SyncEpoch) {
			return &rpc.Error{Code: rpc.CodeUnavailable, Message: "Calendar sync needs owner bootstrap"}
		}
		page := syncPage{syncReference: syncRef(root), Mode: "full"}
		if q.Cursor != "" {
			var supplied syncPage
			if err := syncDecode(q.Cursor, syncCursorPrefix, &supplied, 1024); err != nil {
				return err
			}
			page = supplied
			if !page.syncReference.valid(root) {
				return syncInvalid()
			}
			switch page.Mode {
			case "full":
				if page.Since != 0 || page.AfterSequence != 0 || !idPattern.MatchString(page.AfterID) {
					return syncInvalid()
				}
			case "delta":
				if page.AfterID != "" || page.Since < root.SyncFloor || page.Since > page.Revision || page.AfterSequence <= page.Since || page.AfterSequence > page.Revision {
					return syncInvalid()
				}
			default:
				return syncInvalid()
			}
		} else if q.Token != "" {
			var since syncReference
			if err := syncDecode(q.Token, syncTokenPrefix, &since, 512); err != nil {
				return err
			}
			if !since.valid(root) {
				return syncInvalid()
			}
			page.Mode = "delta"
			page.Since = since.Revision
			page.AfterSequence = since.Revision
		}
		var rows []struct {
			EventID  string
			Sequence int64
			Entry    string
		}
		var err error
		if page.Mode == "full" {
			// For a resource changed after the frozen watermark, the first later
			// change contains its exact prior state. Retention validation above
			// guarantees that this before-image still exists.
			err = tx.Raw(`WITH snapshots AS (
    SELECT i.event_id,CASE WHEN i.sequence<=? THEN i.entry ELSE
     (SELECT c.previous FROM sync_changes c WHERE c.workspace_id=i.workspace_id AND c.acl_root_id=i.acl_root_id AND c.event_id=i.event_id AND c.sequence>? ORDER BY c.sequence LIMIT 1)
     END AS entry
    FROM sync_items i WHERE i.workspace_id=? AND i.acl_root_id=? AND i.event_id>?
   ) SELECT event_id,entry FROM snapshots WHERE entry IS NOT NULL AND json_extract(entry,'$.state')<>'deleted' ORDER BY event_id LIMIT ?`, page.Revision, page.Revision, q.WorkspaceID, q.RootID, page.AfterID, q.Limit+1).Scan(&rows).Error
		} else {
			err = tx.Raw(`SELECT event_id,sequence,entry FROM sync_changes
    WHERE workspace_id=? AND acl_root_id=? AND sequence>? AND sequence IN (
     SELECT max(sequence) FROM sync_changes WHERE workspace_id=? AND acl_root_id=? AND sequence>? AND sequence<=? GROUP BY event_id
    ) ORDER BY sequence LIMIT ?`, q.WorkspaceID, q.RootID, page.AfterSequence, q.WorkspaceID, q.RootID, page.Since, page.Revision, q.Limit+1).Scan(&rows).Error
		}
		if err != nil {
			return dbError(err)
		}
		out.Complete = len(rows) <= q.Limit
		if !out.Complete {
			rows = rows[:q.Limit]
			if page.Mode == "full" {
				page.AfterID = rows[len(rows)-1].EventID
			} else {
				page.AfterSequence = rows[len(rows)-1].Sequence
			}
			out.Cursor = syncEncode(syncCursorPrefix, page)
		} else {
			out.Token = syncEncode(syncTokenPrefix, page.syncReference)
		}
		for _, row := range rows {
			var item v1.SyncItem
			if contract.Strict([]byte(row.Entry), &item) != nil || item.EventID != row.EventID || item.Revision < 1 || !validUID(item.UID) {
				return security.ErrUnavailable
			}
			switch item.State {
			case "active":
				if !strongETag.MatchString(item.ETag) {
					return security.ErrUnavailable
				}
			case "deleted", "unsupported":
				if item.ETag != "" {
					return security.ErrUnavailable
				}
			default:
				return security.ErrUnavailable
			}
			out.Items = append(out.Items, item)
		}
		return nil
	})
	if err != nil {
		return v1.SyncResult{Scope: q.Scope, Items: []v1.SyncItem{}}, err
	}
	return out, nil
}
