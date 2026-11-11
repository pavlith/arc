package objects

import (
	"context"
	"time"

	"github.com/pavlith/arc/services/files/storage"
	"gorm.io/gorm"
)

// Quota is operator configuration, shared by all roots/users in a workspace.
// It is not a client-selectable upload option. Zero fields use safe defaults.
type Quota struct {
	WorkspaceBytes int64 `json:"workspace_bytes"`
	WorkspaceFiles int64 `json:"workspace_files"`
}

func (q Quota) Effective() (Quota, error) {
	if q.WorkspaceBytes < 0 || q.WorkspaceFiles < 0 || q.WorkspaceBytes > 1<<50 || q.WorkspaceFiles > 1000000 {
		return Quota{}, invalid()
	}
	if q.WorkspaceBytes == 0 {
		q.WorkspaceBytes = 10 * storage.MaxObjectSize
	}
	if q.WorkspaceFiles == 0 {
		q.WorkspaceFiles = 10000
	}
	return q, nil
}

// checkWorkspaceQuota runs inside the command replay transaction, after its
// write reservation. Concurrent users cannot oversubscribe the same capacity.
// Archived bytes still exist and therefore continue to consume capacity.
func (s *Module) checkWorkspaceQuota(ctx context.Context, tx *gorm.DB, workspace string, size int64, now time.Time) error {
	quota, err := s.Quota.Effective()
	if err != nil {
		return unavailable(err)
	}
	var usage struct {
		Count int64
		Bytes int64
	}
	if err := tx.WithContext(ctx).Raw(`SELECT count(*) AS count, coalesce(sum(bytes),0) AS bytes FROM (
 SELECT size AS bytes FROM files WHERE workspace_id=?
 UNION ALL
 SELECT expected_size AS bytes FROM uploads WHERE workspace_id=? AND state='pending' AND expires_at>?
 )`, workspace, workspace, now).Scan(&usage).Error; err != nil {
		return unavailable(err)
	}
	if usage.Count >= quota.WorkspaceFiles || usage.Bytes > quota.WorkspaceBytes || size > quota.WorkspaceBytes-usage.Bytes {
		return conflict()
	}
	return nil
}
