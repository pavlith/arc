package imapclient

import (
	"bufio"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/pavlith/arc/test/imapfixture"
)

func TestMessageUIDWindowsAndValidity(t *testing.T) {
	server := imapfixture.New(t, "plain", map[string]string{"user": "secret"})
	client, err := New(Config{Endpoints: []Endpoint{{Host: server.Host, Port: server.Port, CIDRs: []string{"127.0.0.1/32"}}}, RootCAs: server.Roots})
	if err != nil {
		t.Fatal(err)
	}
	settings := Settings{Host: server.Host, Port: server.Port, Login: "user"}
	q := MessageQuery{WireName: base64.RawURLEncoding.EncodeToString([]byte("INBOX")), UIDWindow: 1}
	first := client.Messages(context.Background(), settings, []byte("secret"), q)
	if first.Status != "ok" || first.Page.UIDValidity != 77 || len(first.Page.Messages) != 1 || first.Page.Messages[0].UID != 102 || first.Page.Messages[0].Subject != "Привет" || first.Page.Messages[0].From[0].Mailbox != "alice" {
		t.Fatal(first)
	}
	q.UIDValidity = 77
	q.BeforeUID = first.Page.NextBeforeUID
	next := client.Messages(context.Background(), settings, []byte("secret"), q)
	if next.Status != "ok" || len(next.Page.Messages) != 1 || next.Page.Messages[0].UID != 101 || next.Page.Messages[0].Subject != "Hello world" {
		t.Fatal(next)
	}
	q.UIDValidity = 78
	stale := client.Messages(context.Background(), settings, []byte("secret"), q)
	if stale.Status != "uidvalidity_changed" || len(stale.Page.Messages) != 0 || stale.Page.NextBeforeUID != 0 {
		t.Fatal("UID namespace mismatch", stale)
	}
	for _, name := range server.Commands() {
		switch name {
		case "CAPABILITY", "AUTHENTICATE", "LOGOUT", "EXAMINE", "UID":
		default:
			t.Fatal("unexpected command", name)
		}
	}
}
func TestMessageDataLiteralAndBounds(t *testing.T) {
	wire := `(UID 7 FLAGS () INTERNALDATE "13-Nov-2026 10:00:00 +0000" RFC822.SIZE 200 ENVELOPE (NIL {5}` + "\r\n" + `Hello NIL NIL NIL NIL NIL NIL NIL "<id>"))` + "\r\n"
	p := &protocol{reader: bufio.NewReader(strings.NewReader(wire))}
	line, err := p.read()
	if err != nil {
		t.Fatal(err)
	}
	tokens := 0
	parser := dataParser{p: p, line: line, tokens: &tokens}
	value, err := parser.read(0)
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := fetchAttributes(value)
	if err != nil {
		t.Fatal(err)
	}
	message, err := messageSummary(attrs)
	if err != nil || message.Subject != "Hello" || message.UID != 7 {
		t.Fatal(message, err)
	}
	for _, bad := range []string{`{999999}`, `((((((((((NIL))))))))))`, `("broken\q")`, `(UID 1 UID 2)`} {
		p := &protocol{reader: bufio.NewReader(strings.NewReader(""))}
		tokens := 0
		parser := dataParser{p: p, line: bad, tokens: &tokens}
		value, err := parser.read(0)
		if err == nil {
			_, err = fetchAttributes(value)
		}
		if err == nil {
			t.Fatal("malformed/ambiguous data accepted", bad)
		}
	}
	q := MessageQuery{WireName: base64.RawURLEncoding.EncodeToString([]byte("INBOX\r\nBAD")), UIDWindow: 1}
	if q.Valid() {
		t.Fatal("folder command injection accepted")
	}
}
