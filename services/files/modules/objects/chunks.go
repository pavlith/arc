package objects

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/models"
	"github.com/pavlith/arc/services/files/storage"
	"gorm.io/gorm"
)

// AppendChunk is a Files-internal byte operation for a future private transport.
// The caller must supply a cryptographically verified RPC identity context,
// not headers provided by the browser. It rechecks live root Access on EVERY
// attempt, and cannot run if that check is unavailable.
func (s *Module) AppendChunk(ctx context.Context, ref filesv1.UploadRef, offset, length int64, body io.Reader) (filesv1.Upload, error) {
	var empty filesv1.Upload
	if s == nil || s.DB == nil || s.Storage == nil || s.Authorize == nil || ctx == nil {
		return empty, security.ErrUnavailable
	}
	if body == nil || length < 1 || length > storage.MaxChunkSize || offset < 0 ||
		offset > storage.MaxObjectSize || length > storage.MaxObjectSize-offset {
		return empty, invalid()
	}
	claims, ok := rpc.VerifiedClaims(ctx)
	meta, hasMeta := rpc.Metadata(ctx)
	if !ok || !hasMeta || claims.SessionID == "" || claims.WorkspaceID != ref.WorkspaceID ||
		ref.WorkspaceID == "" || ref.RootID == "" {
		return empty, security.ErrUnauthenticated
	}
	var scope filesv1.Scope
	if json.Unmarshal(meta.Payload, &scope) != nil || scope != ref.Scope {
		return empty, security.ErrDenied
	}
	if err := s.Authorize(ctx, ref.RootID, "files.create"); err != nil {
		return empty, err
	}
	// This process is the exclusive Files owner of its DB and local byte root.
	// The lock covers the entire SQL commit and any compensating disk truncate.
	s.chunkMu.Lock()
	defer s.chunkMu.Unlock()
	physicalChanged := false
	var committedOffset int64
	var result filesv1.Upload
	err := s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		v, err := s.ownUpload(ctx, tx, ref)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		if v.State != "pending" || !v.ExpiresAt.After(now) ||
			offset != v.Offset || length > v.ExpectedSize-offset {
			return conflict()
		}
		committedOffset = v.Offset
		if err := s.Storage.RewindPending(ctx, v.TempKey, v.Offset); err != nil {
			return unavailable(err)
		}
		next, err := s.Storage.Append(ctx, v.TempKey, offset, length,
			&authorizedReader{source: body, ctx: ctx, authorize: func() error { return s.Authorize(ctx, ref.RootID, "files.create") }})
		if err != nil {
			return unavailable(err)
		}
		physicalChanged = true
		update := tx.WithContext(ctx).Model(&models.Upload{}).
			Where("id=? AND workspace_id=? AND acl_root_id=? AND actor_id=? AND session_id=? AND state='pending' AND offset=? AND expires_at>?",
				v.ID, v.WorkspaceID, v.RootID, v.ActorID, v.SessionID, offset, now).
			Updates(map[string]any{"offset": next, "updated_at": now})
		if update.Error != nil {
			return unavailable(update.Error)
		}
		if update.RowsAffected != 1 {
			return conflict()
		}
		v.Offset, v.UpdatedAt = next, now
		result = uploadDTO(v)
		return nil
	})
	if err == nil {
		return result, nil
	}
	if physicalChanged {
		// Rollback runs after the failed SQL transaction. Use a fresh bounded
		// context even if a network client canceled its request.
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if restore := s.Storage.RewindPending(cleanup, ref.UploadID, committedOffset); restore != nil {
			return empty, security.ErrUnavailable
		}
	}
	return empty, err
}

// Revalidate while reading a slow request body, not merely once before it.
// A callback error propagates into the disk adapter's rollback path.
type authorizedReader struct {
	source    io.Reader
	ctx       context.Context
	authorize func() error
	since     int
}

func (a *authorizedReader) Read(p []byte) (int, error) {
	if err := a.ctx.Err(); err != nil {
		return 0, err
	}
	if a.since == 0 || a.since >= 256<<10 {
		if err := a.authorize(); err != nil {
			return 0, err
		}
		a.since = 0
	}
	if len(p) > 256<<10-a.since {
		p = p[:256<<10-a.since]
	}
	n, err := a.source.Read(p)
	a.since += n
	return n, err
}
