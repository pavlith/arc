package imapclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"testing"

	"github.com/pavlith/arc/test/imapfixture"
)

func TestDownloadPartialUIDValidationAndDecoding(t *testing.T) {
	for _, mode := range []string{"plain", "download-wrong-uid", "download-truncated", "download-incomplete"} {
		t.Run(mode, func(t *testing.T) {
			server := imapfixture.New(t, mode, map[string]string{"user": "secret"})
			client, err := New(Config{Endpoints: []Endpoint{{Host: server.Host, Port: server.Port, CIDRs: []string{"127.0.0.1/32"}}}, RootCAs: server.Roots})
			if err != nil {
				t.Fatal(err)
			}
			q := DownloadQuery{StructureQuery: StructureQuery{WireName: base64.RawURLEncoding.EncodeToString([]byte("INBOX")), UIDValidity: 77, UID: 102}}
			var got bytes.Buffer
			read := func(r io.Reader) error { _, err := io.Copy(&got, r); return err }
			result := client.Download(context.Background(), Settings{Host: server.Host, Port: server.Port, Login: "user"}, []byte("secret"), q, func() error { return nil }, read)
			if mode != "plain" {
				if result == "ok" || got.Len() != 0 {
					t.Fatal("unverified or incomplete block released", result, got.Len())
				}
				return
			}
			if result != "ok" || !bytes.Equal(got.Bytes(), imapfixture.MessageContent()) {
				t.Fatal("raw multi-block message", result, got.Len())
			}
			got.Reset()
			q.Section = "2"
			result = client.Download(context.Background(), Settings{Host: server.Host, Port: server.Port, Login: "user"}, []byte("secret"), q, func() error { return nil }, read)
			if result != "ok" || !bytes.Equal(got.Bytes(), imapfixture.AttachmentContent()) {
				t.Fatal("decoded attachment", result, got.String())
			}
			got.Reset()
			q.UIDValidity = 78
			result = client.Download(context.Background(), Settings{Host: server.Host, Port: server.Port, Login: "user"}, []byte("secret"), q, func() error { return nil }, read)
			if result != "uidvalidity_changed" || got.Len() != 0 {
				t.Fatal("stale UID namespace released bytes", result)
			}
		})
	}
}
