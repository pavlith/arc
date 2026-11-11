package objects

import (
	"context"
	"time"

	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/storage"
	"gorm.io/gorm"
)

// Quota is operator configuration, shared by all roots/users in a workspace.
// It is not a client-selectable upload option. Zero fields use safe defaults.
type Quota struct {
	PersonalBytes  int64 `json:"personal_bytes"`
	PersonalFiles  int64 `json:"personal_files"`
	WorkspaceBytes int64 `json:"workspace_bytes"`
	WorkspaceFiles int64 `json:"workspace_files"`
}

func (q Quota) Effective() (Quota, error) {
	if q.PersonalBytes < 0 || q.PersonalFiles < 0 || q.PersonalBytes > 1<<50 || q.PersonalFiles > 1000000 || q.WorkspaceBytes < 0 || q.WorkspaceFiles < 0 || q.WorkspaceBytes > 1<<50 || q.WorkspaceFiles > 1000000 {
		return Quota{}, invalid()
	}
	if q.WorkspaceBytes == 0 {
		q.WorkspaceBytes = 10 * storage.MaxObjectSize
	}
	if q.WorkspaceFiles == 0 {
		q.WorkspaceFiles = 10000
	}
	if q.PersonalBytes == 0 {
		q.PersonalBytes = 10 * storage.MaxObjectSize
	}
	if q.PersonalFiles == 0 {
		q.PersonalFiles = 10000
	}
	return q, nil
}

// checkUploadQuota runs inside the command replay transaction, after its
// write reservation. Concurrent users cannot oversubscribe the same capacity.
// Archived bytes still exist and therefore continue to consume capacity.
func (s *Module) checkUploadQuota(ctx context.Context, tx *gorm.DB, scope filesv1.Scope, size int64, now time.Time) error {
	quota, err := s.Quota.Effective()
	if err != nil {
		return unavailable(err)
	}
	owner := ""
	if scope.WorkspaceID == "" {
		if err := tx.WithContext(ctx).Raw("SELECT owner_id FROM roots WHERE acl_root_id=? AND workspace_id='' AND state='active'", scope.RootID).Row().Scan(&owner); err != nil || owner == "" {
			return unavailable(gorm.ErrInvalidData)
		}
		quota.WorkspaceBytes, quota.WorkspaceFiles = quota.PersonalBytes, quota.PersonalFiles
	}
	var usage struct {
		Count int64
		Bytes int64
	}
	if err := tx.WithContext(ctx).Raw(`SELECT count(*) AS count, coalesce(sum(bytes),0) AS bytes FROM (
 SELECT size AS bytes FROM files WHERE workspace_id=? AND (?<>'' OR acl_root_id IN (SELECT acl_root_id FROM roots WHERE owner_id=? AND workspace_id=''))
 UNION ALL
 SELECT expected_size AS bytes FROM uploads WHERE workspace_id=? AND (?<>'' OR acl_root_id IN (SELECT acl_root_id FROM roots WHERE owner_id=? AND workspace_id='')) AND state='pending' AND expires_at>?
 )`, scope.WorkspaceID, scope.WorkspaceID, owner, scope.WorkspaceID, scope.WorkspaceID, owner, now).Scan(&usage).Error; err != nil {
		return unavailable(err)
	}
	if usage.Count >= quota.WorkspaceFiles || usage.Bytes > quota.WorkspaceBytes || size > quota.WorkspaceBytes-usage.Bytes {
		return conflict()
	}
	return nil
}
