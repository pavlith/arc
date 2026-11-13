package mail

import (
	"context"
	"encoding/json"
	"io"

	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/mail/api/v1"
	"github.com/pavlith/arc/services/mail/imapclient"
)

// StreamDownload requires Core's verified context for the exact private request.
// The consumer receives decoded MIME bytes, or the unchanged raw message.
func (s *Module) StreamDownload(ctx context.Context, q v1.DownloadRequest, consume func(io.Reader) error) error {
	if ctx == nil || consume == nil || !validScope(q.Scope) || q.Generation < 1 || !q.DownloadQuery.Valid() {
		return invalid()
	}
	cl, verified := rpc.VerifiedClaims(ctx)
	meta, hasMeta := rpc.Metadata(ctx)
	var signed v1.DownloadRequest
	if !verified || !hasMeta || cl.Operation != v1.PrivateDownload.ID || json.Unmarshal(meta.Payload, &signed) != nil || signed != q {
		return security.ErrDenied
	}
	if err := s.Authorize(ctx, q.RootID, "mail.read"); err != nil {
		return err
	}
	snapshot, err := s.root(ctx, q.Scope)
	if err != nil {
		return err
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.Authorize(ctx, q.RootID, "mail.read"); err != nil {
			return err
		}
		row, err := s.root(ctx, q.Scope)
		if err != nil {
			return err
		}
		if row.Revision != snapshot.Revision || row.Generation != snapshot.Generation || row.CredentialVersion != snapshot.CredentialVersion || row.State != "enabled" {
			return conflict()
		}
		return nil
	}
	_, result, err := s.remoteRead(ctx, q.Scope, "mail.read", q.Generation, func(ctx context.Context, settings imapclient.Settings, password []byte) imapclient.Result {
		status := s.Probe.Download(ctx, settings, password, q.DownloadQuery, check, func(source io.Reader) error {
			if err := check(); err != nil {
				return err
			}
			return consume(&authorizedReader{ctx: ctx, source: source, check: check})
		})
		return imapclient.Result{Status: status}
	})
	if err != nil {
		return err
	}
	if result.Status != "ok" {
		return security.ErrUnavailable
	}
	return check()
}

type authorizedReader struct {
	ctx    context.Context
	source io.Reader
	check  func() error
}

func (r *authorizedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if err := r.check(); err != nil {
		return 0, err
	}
	if len(p) > imapclient.DownloadBlockSize {
		p = p[:imapclient.DownloadBlockSize]
	}
	n := 0
	var err error
	for n < len(p) {
		var count int
		count, err = r.source.Read(p[n:])
		n += count
		if err != nil {
			break
		}
		if count == 0 {
			err = io.ErrNoProgress
			break
		}
	}
	// Remote FETCH, decoding and authorization can take time. Check again before
	// releasing this block, even if the last read also reports EOF.
	if checkErr := r.check(); checkErr != nil {
		return 0, checkErr
	}
	return n, err
}
