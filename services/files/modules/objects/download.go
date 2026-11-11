package objects

import (
	"context"
	"encoding/json"
	"io"
	"strings"

	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/models"
)

// StreamDownload is a private Files-internal primitive, not an exposed HTTP
// endpoint. A future private transport must first verify the Gate-signed
// invocation and bind its exact workspace/root/file scope to this context.
//
// At most 256 KiB is copied per authorization check. Every chunk verifies
// active root Access again; failures and request cancellation stop streaming.
// The byte store path and blob key are NEVER returned to the caller.
func (s *Module) StreamDownload(ctx context.Context, ref filesv1.FileRef, dst io.Writer) (filesv1.File, error) {
	var empty filesv1.File
	if s == nil || s.DB == nil || s.Storage == nil || s.Authorize == nil ||
		ctx == nil || dst == nil {
		return empty, security.ErrUnavailable
	}
	cl, verified := rpc.VerifiedClaims(ctx)
	meta, hasMeta := rpc.Metadata(ctx)
	if !verified || !hasMeta || !strings.HasPrefix(cl.Subject, "user:") ||
		cl.SessionID == "" || cl.WorkspaceID != ref.WorkspaceID {
		return empty, security.ErrUnauthenticated
	}
	var scope filesv1.Scope
	if json.Unmarshal(meta.Payload, &scope) != nil || scope != ref.Scope ||
		scope.WorkspaceID == "" || scope.RootID == "" {
		return empty, security.ErrDenied
	}
	if err := s.Authorize(ctx, ref.RootID, "files.read"); err != nil {
		return empty, err
	}
	var row models.File
	err := s.DB.WithContext(ctx).Where(
		"id=? AND workspace_id=? AND acl_root_id=? AND state='ready'",
		ref.FileID, ref.WorkspaceID, ref.RootID).Take(&row).Error
	if err != nil {
		return empty, dbFileError(err)
	}
	reader, err := s.Storage.Open(ctx, row.BlobKey)
	if err != nil {
		return empty, unavailable(err)
	}
	defer reader.Close()
	stat, err := reader.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() != row.Size {
		return empty, security.ErrUnavailable
	}
	data := make([]byte, 256<<10)
	var sent int64
	for sent < row.Size {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		// No cached ACL grants; session and root checks must remain live
		// throughout transfer (including after an initial successful check).
		if err := s.Authorize(ctx, ref.RootID, "files.read"); err != nil {
			return empty, err
		}
		want := int64(len(data))
		if left := row.Size-sent; left < want {
			want = left
		}
		n, err := io.ReadFull(reader, data[:int(want)])
		if err != nil {
			return empty, security.ErrUnavailable
		}
		wrote, err := dst.Write(data[:n])
		sent += int64(wrote)
		if err != nil {
			return empty, err
		}
		if wrote != n {
			return empty, io.ErrShortWrite
		}
	}
	// Even a zero-length file requires current authorization and ready state.
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := s.Authorize(ctx, ref.RootID, "files.read"); err != nil {
		return empty, err
	}
	return fileDTO(row), nil
}
