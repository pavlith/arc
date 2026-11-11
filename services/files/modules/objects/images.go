package objects

import (
	"context"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/resource"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/files/api/v1"
)

func (s *Module) validateImage(ctx context.Context, id, mime string, size int64) error {
	if mime == "application/octet-stream" {
		return nil
	}
	if (mime != "image/png" && mime != "image/jpeg") || size > 4<<20 {
		return invalid()
	}
	f, err := s.Storage.OpenPending(ctx, id)
	if err != nil {
		return unavailable(err)
	}
	defer f.Close()
	cfg, format, err := image.DecodeConfig(io.LimitReader(f, 4<<20))
	if err != nil || "image/"+format != mime || cfg.Width < 1 || cfg.Height < 1 || cfg.Width > 1024 || cfg.Height > 1024 {
		return invalid()
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return unavailable(err)
	}
	if _, _, err := image.Decode(io.LimitReader(f, 4<<20)); err != nil {
		return invalid()
	}
	return ctx.Err()
}
func (s *Module) prepareAvatar(ctx context.Context, q v1.FileRef) (v1.AvatarResult, error) {
	var empty v1.AvatarResult
	cl, ok := rpc.VerifiedClaims(ctx)
	if !ok || cl.SessionID == "" || q.WorkspaceID != "" {
		return empty, security.ErrDenied
	}
	var owner string
	if err := s.DB.WithContext(ctx).Raw("SELECT owner_id FROM roots WHERE acl_root_id=? AND workspace_id='' AND state='active'", q.RootID).Row().Scan(&owner); err != nil {
		return empty, unavailable(err)
	}
	if cl.Subject != "user:"+owner {
		return empty, security.ErrDenied
	}
	file, err := s.getFile(ctx, q)
	if err != nil {
		return empty, err
	}
	if file.MIME != "image/png" && file.MIME != "image/jpeg" {
		return empty, invalid()
	}
	claim := resource.AvatarClaim{Ref: resource.Ref{Kind: "file", RootID: q.RootID, ID: q.FileID}, UserID: strings.TrimPrefix(cl.Subject, "user:"), SessionID: cl.SessionID, Provider: s.Signer.ServiceID, Kid: s.Signer.Kid, ExpiresAt: time.Now().UTC().Add(time.Minute)}
	receipt, err := resource.SignAvatar(s.Signer.PrivateKey, claim)
	return v1.AvatarResult{Receipt: receipt}, err
}
