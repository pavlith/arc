package mail

import (
	"context"
	"time"

	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/mail/api/v1"
	"github.com/pavlith/arc/services/mail/models"
	"gorm.io/gorm"
)

const (
	indexFolders        = 64
	indexMessages       = 10000
	indexTotalBytes     = 32 << 20
	indexMessageBytes   = 64 << 10
	indexPendingBatches = 10
	indexStageBytes     = 160 << 10
	indexPendingSeconds = 900
)

func cacheLimits() v1.CacheLimits {
	return v1.CacheLimits{FolderBindings: indexFolders, Messages: indexMessages, SummaryBytes: indexTotalBytes, SummaryPerMessageBytes: indexMessageBytes, PendingBatches: indexPendingBatches, PendingSnapshotBytes: indexStageBytes, PendingTTLSeconds: indexPendingSeconds}
}
func (s *Module) ownerCacheAccount(ctx context.Context, db *gorm.DB, scope v1.Scope) (models.Account, error) {
	row, err := account(ctx, db, scope)
	if err != nil {
		return row, err
	}
	claims, ok := rpc.VerifiedClaims(ctx)
	if !ok || claims.Subject != "user:"+row.OwnerID || claims.SessionID == "" || claims.WorkspaceID != "" || claims.DelegationID != "" || claims.OnBehalfOf != "" {
		return row, rpc.SecurityError(security.ErrDenied)
	}
	return row, nil
}
func cacheUsage(ctx context.Context, db *gorm.DB, row models.Account) (v1.CacheUsage, error) {
	var count struct{ Messages, ActiveMessages, SummaryBytes int64 }
	err := db.WithContext(ctx).Raw(`SELECT count(*) AS messages,COALESCE(sum(length(m.summary)),0) AS summary_bytes,COALESCE(sum(CASE WHEN f.generation=? AND m.uid_validity=f.uid_validity AND m.present=1 THEN 1 ELSE 0 END),0) AS active_messages FROM mail_messages m JOIN mail_folders f ON f.id=m.folder_id WHERE f.acl_root_id=?`, row.Generation, row.RootID).Scan(&count).Error
	if err != nil {
		return v1.CacheUsage{}, dbError(err)
	}
	var folders int64
	if err = db.WithContext(ctx).Model(&indexFolder{}).Where("acl_root_id=?", row.RootID).Count(&folders).Error; err != nil {
		return v1.CacheUsage{}, dbError(err)
	}
	var pending struct{ PendingBatches, PendingBytes int64 }
	if err = db.WithContext(ctx).Raw("SELECT count(*) AS pending_batches,COALESCE(sum(length(snapshot)),0) AS pending_bytes FROM mail_refresh_staging WHERE acl_root_id=?", row.RootID).Scan(&pending).Error; err != nil {
		return v1.CacheUsage{}, dbError(err)
	}
	return v1.CacheUsage{FolderBindings: folders, Messages: count.Messages, ActiveMessages: count.ActiveMessages, ObsoleteMessages: count.Messages - count.ActiveMessages, SummaryBytes: count.SummaryBytes, PendingBatches: pending.PendingBatches, PendingBytes: pending.PendingBytes, Limits: cacheLimits()}, nil
}
func (s *Module) cacheStatus(ctx context.Context, q v1.Scope) (v1.CacheStatus, error) {
	var out v1.CacheStatus
	err := s.db(ctx).Transaction(func(tx *gorm.DB) error {
		row, err := s.ownerCacheAccount(ctx, tx, q)
		if err != nil {
			return err
		}
		usage, err := cacheUsage(ctx, tx, row)
		if err != nil {
			return err
		}
		out = v1.CacheStatus{Scope: q, Revision: row.Revision, Generation: row.Generation, Usage: usage}
		return nil
	})
	if err != nil {
		return v1.CacheStatus{}, err
	}
	if err = s.Check(ctx, q.RootID, "mail.connection.manage"); err != nil {
		return v1.CacheStatus{}, rpc.SecurityError(err)
	}
	row, err := s.ownerCacheAccount(ctx, s.db(ctx), q)
	if err != nil {
		return v1.CacheStatus{}, err
	}
	if row.Revision != out.Revision || row.Generation != out.Generation {
		return v1.CacheStatus{}, conflict()
	}
	return out, nil
}
func (s *Module) pruneCache(ctx context.Context, tx *gorm.DB, q v1.CachePrune) (v1.CachePruned, error) {
	empty := v1.CachePruned{}
	if q.Revision < 1 || q.Generation < 1 || q.Limit < 1 || q.Limit > 500 || q.Mode != "obsolete" && q.Mode != "all" {
		return empty, invalid()
	}
	row, err := s.ownerCacheAccount(ctx, tx, q.Scope)
	if err != nil {
		return empty, err
	}
	if row.Revision != q.Revision || row.Generation != q.Generation {
		return empty, conflict()
	}
	var candidates []struct {
		ID           string
		FolderID     string
		SummaryBytes int64
	}
	query := tx.Table("mail_messages AS m").Select("m.id,m.folder_id,length(m.summary) AS summary_bytes").Joins("JOIN mail_folders f ON f.id=m.folder_id").Where("f.acl_root_id=?", q.RootID)
	if q.Mode == "obsolete" {
		query = query.Where("(f.generation<>? OR m.uid_validity<>f.uid_validity OR m.present=0)", row.Generation)
	}
	if err = query.Order("m.id").Limit(q.Limit).Scan(&candidates).Error; err != nil {
		return empty, dbError(err)
	}
	out := v1.CachePruned{Mode: q.Mode}
	if len(candidates) > 0 {
		ids := make([]string, 0, len(candidates))
		folders := []string{}
		seen := map[string]bool{}
		for _, candidate := range candidates {
			ids = append(ids, candidate.ID)
			out.ReclaimedSummaryBytes += candidate.SummaryBytes
			if !seen[candidate.FolderID] {
				folders = append(folders, candidate.FolderID)
				seen[candidate.FolderID] = true
			}
		}
		removed := tx.Where("id IN ? AND folder_id IN (SELECT id FROM mail_folders WHERE acl_root_id=?)", ids, q.RootID).Delete(&indexMessage{})
		if removed.Error != nil {
			return empty, dbError(removed.Error)
		}
		if removed.RowsAffected != int64(len(ids)) {
			return empty, conflict()
		}
		out.RemovedMessages = len(ids)
		changes := map[string]any{"revision": gorm.Expr("revision+1"), "updated_at": time.Now().UTC()}
		if q.Mode == "all" {
			changes["next_before_uid"] = 0
			changes["low_uid"] = 0
			changes["high_uid"] = 0
		}
		if err = tx.Model(&indexFolder{}).Where("acl_root_id=? AND id IN ?", q.RootID, folders).Updates(changes).Error; err != nil {
			return empty, dbError(err)
		}
	}
	emptyFolders := tx.Where("acl_root_id=? AND NOT EXISTS (SELECT 1 FROM mail_messages m WHERE m.folder_id=mail_folders.id)", q.RootID)
	if q.Mode == "obsolete" {
		emptyFolders = emptyFolders.Where("generation<>?", row.Generation)
	}
	removedFolders := emptyFolders.Delete(&indexFolder{})
	if removedFolders.Error != nil {
		return empty, dbError(removedFolders.Error)
	}
	out.RemovedFolders = int(removedFolders.RowsAffected)
	var pending struct {
		Count int64
		Size  int64
	}
	if err = tx.Raw("SELECT count(*) AS count,COALESCE(sum(length(snapshot)),0) AS size FROM mail_refresh_staging WHERE acl_root_id=?", q.RootID).Scan(&pending).Error; err != nil {
		return empty, dbError(err)
	}
	removedStages := tx.Where("acl_root_id=?", q.RootID).Delete(&refreshStage{})
	if removedStages.Error != nil {
		return empty, dbError(removedStages.Error)
	}
	out.RemovedBatches = int(removedStages.RowsAffected)
	out.ReclaimedPendingBytes = pending.Size
	// The account revision fences all in-flight/staged refreshes. Existing save
	// commits the owner audit and one account.cache.pruned outbox hint atomically.
	saved, err := s.save(ctx, tx, row, q.Revision, "account.cache.pruned")
	if err != nil {
		return empty, err
	}
	usage, err := cacheUsage(ctx, tx, row)
	if err != nil {
		return empty, err
	}
	out.CacheStatus = v1.CacheStatus{Scope: q.Scope, Revision: saved.Revision, Generation: row.Generation, Usage: usage}
	if q.Mode == "all" {
		out.More = usage.Messages > 0 || usage.FolderBindings > 0
	} else {
		out.More = usage.ObsoleteMessages > 0
	}
	return out, nil
}
