package imapclient

import (
	"bufio"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/pavlith/arc/test/imapfixture"
)

func TestFolderDiscovery(t *testing.T) {
	server := imapfixture.New(t, "plain", map[string]string{"user": "secret"})
	client, err := New(Config{Endpoints: []Endpoint{{Host: server.Host, Port: server.Port, CIDRs: []string{"127.0.0.1/32"}}}, RootCAs: server.Roots})
	if err != nil {
		t.Fatal(err)
	}
	got := client.Folders(context.Background(), Settings{Host: server.Host, Port: server.Port, Login: "user"}, []byte("secret"))
	if got.Status != "ok" || len(got.Folders) != 4 || got.Folders[2].Name != "Почта" || got.Folders[1].Delimiter != nil || got.Folders[1].Selectable || got.Folders[3].Name != "Reports" {
		t.Fatal(got)
	}
}
func TestFolderParserAndEncodingBounds(t *testing.T) {
	for _, tc := range []struct {
		line, tail, want string
		utf8             bool
	}{
		{`(\HasNoChildren) "/" "日本語"`, "", "日本語", true},
		{`() nil "A&-B"`, "", "A&B", false},
		{`() "/" {7}`, "Reports\r\n", "Reports", false},
	} {
		p := &protocol{reader: bufio.NewReader(strings.NewReader(tc.tail))}
		got, err := p.parseList(tc.line, tc.utf8)
		if err != nil || got.Name != tc.want {
			t.Fatal(tc, got, err)
		}
	}
	for _, line := range []string{`() "/" {999999}`, `() "/" "&broken"`, `() "/" "&2AA-"`, `() "/" "&AGE-"`, `() "/" "unterminated`, `() "/" "name" extra`, `() "/" {3}`} {
		p := &protocol{reader: bufio.NewReader(strings.NewReader(""))}
		if _, err := p.parseList(line, false); err == nil {
			t.Fatal("invalid LIST accepted", line)
		}
	}
	replies := strings.Repeat("* LIST () NIL INBOX\r\n", 65) + "M4 OK done\r\n"
	for _, reply := range []string{replies, "* LIST () NIL INBOX\r\n* LIST () NIL INBOX\r\nM4 OK done\r\n", "* LIST () NIL INBOX\r\n* LIST () NIL inbox\r\nM4 OK done\r\n"} {
		p := &protocol{reader: bufio.NewReader(strings.NewReader(reply)), writer: io.Discard}
		got, status := p.listFolders(false)
		if status == "ok" || len(got) != 0 {
			t.Fatal("partial/duplicate folder list", status)
		}
	}
}
