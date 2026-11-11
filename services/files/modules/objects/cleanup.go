package objects

import (
	"context"
	"time"

	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/files/models"
)

// Cleanup removes bytes only AFTER the upload state is durably aborted or
// expired. Failed disk cleanup is retried on the next pass; no pending upload
// that might still be committed is removed.
func (s *Module) Cleanup(ctx context.Context, limit int) (int, error) {
	if ctx == nil || s == nil || s.DB == nil || s.Storage == nil {
		return 0, security.ErrUnavailable
	}
	if limit < 1 || limit > 100 {
		return 0, invalid()
	}
	s.chunkMu.Lock()
	defer s.chunkMu.Unlock()
	now := time.Now().UTC()
	var queue []models.Upload
	err := s.DB.WithContext(ctx).
		Where("cleaned_at IS NULL AND (state IN ('aborted','expired') OR (state='pending' AND expires_at<=?))", now).
		Order("id").Limit(limit).Find(&queue).Error
	if err != nil {
		return 0, unavailable(err)
	}
	count := 0
	for _, item := range queue {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		if item.State == "pending" {
			res := s.DB.WithContext(ctx).Model(&models.Upload{}).
				Where("id=? AND state='pending' AND cleaned_at IS NULL AND expires_at<=?", item.ID, now).
				Updates(map[string]any{"state": "expired", "updated_at": now})
			if res.Error != nil {
				return count, unavailable(res.Error)
			}
			if res.RowsAffected != 1 {
				continue
			}
		}
		if err := s.Storage.Abort(ctx, item.TempKey); err != nil {
			return count, unavailable(err)
		}
		res := s.DB.WithContext(ctx).Model(&models.Upload{}).
			Where("id=? AND state IN ('expired','aborted') AND cleaned_at IS NULL", item.ID).
			Update("cleaned_at", time.Now().UTC())
		if res.Error != nil {
			return count, unavailable(res.Error)
		}
		if res.RowsAffected != 1 {
			return count, security.ErrUnavailable
		}
		count++
	}
	return count, nil
}

// RunCleanup is the owner-local bounded sweeper; it never touches another
// service's database or authorizations. A database/storage outage is terminal
// for the worker, not silently treated as a successful cleanup.
func (s *Module) RunCleanup(ctx context.Context) error {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		for i := 0; i < 10; i++ {
			n, err := s.Cleanup(ctx, 100)
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
			if n < 100 {
				break
			}
		}
		// A failed initiation can leave a temp inode without a committed
		// SQL upload row. Never delete a recent or referenced temp inode.
		if _, err := s.PruneOrphanPending(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// PruneOrphanPending reclaims only unreferenced temp files older than the
// 24-hour upload lifetime plus a two-hour crash-recovery grace period.
// It cannot delete an active upload or an upload awaiting durable cleanup.
func (s *Module) PruneOrphanPending(ctx context.Context) (int, error) {
	if ctx == nil || s == nil || s.DB == nil || s.Storage == nil {
		return 0, security.ErrUnavailable
	}
	s.chunkMu.Lock()
	defer s.chunkMu.Unlock()
	var removed int
	cutoff := time.Now().Add(-26 * time.Hour)
	err := s.Storage.ScanOldPending(ctx, cutoff, func(id string) error {
		var protected bool
		if err := s.DB.WithContext(ctx).Raw(
			"SELECT EXISTS(SELECT 1 FROM uploads WHERE id=? AND cleaned_at IS NULL AND state IN ('pending','aborted','expired'))",
			id,
		).Row().Scan(&protected); err != nil {
			return unavailable(err)
		}
		if protected {
			return nil
		}
		if err := s.Storage.Abort(ctx, id); err != nil {
			return unavailable(err)
		}
		removed++
		return nil
	})
	return removed, err
}
