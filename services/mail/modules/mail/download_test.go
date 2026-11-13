package mail

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"testing"

	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/mail/api/v1"
	"github.com/pavlith/arc/services/mail/credentials"
	"github.com/pavlith/arc/services/mail/imapclient"
)

func TestStreamStopsOnRevokeBindingChangeAndCancellation(t *testing.T) {
	s, scope, _ := fixture(t)
	info, err := s.key(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := credentials.Seal(info.PublicInfo, []byte("unique sensitive fixture password"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = command(t, s, v1.SetCredentials.ID, "mail.connection.manage", "stream-key", v1.SetCredential{Scope: scope, Revision: 1, KeyID: info.KeyID, Sealed: sealed}, s.setCredentials)
	if err != nil {
		t.Fatal(err)
	}
	q := v1.DownloadRequest{Scope: scope, Generation: 1, DownloadQuery: imapclient.DownloadQuery{StructureQuery: imapclient.StructureQuery{WireName: base64.RawURLEncoding.EncodeToString([]byte("INBOX")), UIDValidity: 77, UID: 102}}}
	for _, mode := range []string{"revoke", "binding", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			allowed := true
			s.Check = func(context.Context, string, string) error {
				if !allowed {
					return security.ErrDenied
				}
				return nil
			}
			ctx, cancel := context.WithCancel(invocation(t, v1.PrivateDownload.ID, "", "", q))
			defer cancel()
			first := 0
			err := s.StreamDownload(ctx, q, func(reader io.Reader) error {
				data := make([]byte, imapclient.DownloadBlockSize)
				n, e := reader.Read(data)
				if e != nil || n != len(data) {
					t.Fatalf("first authorized block %d %v", n, e)
				}
				first = n
				switch mode {
				case "revoke":
					allowed = false
				case "binding":
					if e := s.DB.Exec("UPDATE accounts SET revision=revision+1 WHERE acl_root_id=?", scope.RootID).Error; e != nil {
						t.Fatal(e)
					}
				case "cancel":
					cancel()
				}
				n, e = reader.Read(data)
				if n != 0 || e == nil {
					t.Fatalf("bytes after invalidation %d %v", n, e)
				}
				return e
			})
			if err == nil || first != imapclient.DownloadBlockSize {
				t.Fatal("stream accepted invalidation", err, first)
			}
		})
	}
	ctx := invocation(t, v1.PrivateDownload.ID, "", "", q)
	changed := q
	changed.UID = 101
	if err := s.StreamDownload(ctx, changed, func(io.Reader) error { t.Fatal("tampered UID reached consumer"); return nil }); !errors.Is(err, security.ErrDenied) {
		t.Fatal("request proof binding", err)
	}
}
