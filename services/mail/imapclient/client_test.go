package imapclient

import (
	"context"
	"github.com/pavlith/arc/test/imapfixture"
	"testing"
	"time"
)

func TestTLSAuthenticationAndReadOnlyCommands(t *testing.T) {
	for _, mode := range []string{"login", "plain", "continuation"} {
		t.Run(mode, func(t *testing.T) {
			server := imapfixture.New(t, mode, map[string]string{"alice": "password \\\""})
			cfg := Config{Endpoints: []Endpoint{{Host: server.Host, Port: server.Port, CIDRs: []string{"127.0.0.1/32"}}}, RootCAs: server.Roots}
			client, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			settings := Settings{Host: server.Host, Port: server.Port, Login: "alice"}
			if got := client.Check(context.Background(), settings, []byte("password \\\"")); got.Status != "ok" || len(got.Capabilities) < 1 {
				t.Fatal(got)
			}
			if got := client.Check(context.Background(), settings, []byte("wrong")); got.Status != "authentication_failed" {
				t.Fatal(got)
			}
			for _, name := range server.Commands() {
				if name != "CAPABILITY" && name != "LOGIN" && name != "AUTHENTICATE" && name != "LOGOUT" {
					t.Fatal("unexpected remote mutation", name)
				}
			}
			cfg.RootCAs = nil
			untrusted, _ := New(cfg)
			if got := untrusted.Check(context.Background(), settings, []byte("password")); got.Status != "tls_failed" {
				t.Fatal("TLS bypass", got)
			}
			cfg.RootCAs = server.Roots
			cfg.Endpoints[0].CIDRs = []string{"192.0.2.0/24"}
			denied, _ := New(cfg)
			if got := denied.Check(context.Background(), settings, []byte("password")); got.Status != "destination_denied" {
				t.Fatal("CIDR bypass", got)
			}
		})
	}
}
func TestProtocolBoundsAndDeadline(t *testing.T) {
	for _, mode := range []string{"oversized", "stall"} {
		t.Run(mode, func(t *testing.T) {
			server := imapfixture.New(t, mode, map[string]string{"user": "secret"})
			client, err := New(Config{Endpoints: []Endpoint{{Host: server.Host, Port: server.Port, CIDRs: []string{"127.0.0.1/32"}}}, RootCAs: server.Roots, TimeoutMS: 100})
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			got := client.Check(context.Background(), Settings{Host: server.Host, Port: server.Port, Login: "user"}, []byte("secret"))
			if got.Status == "ok" || time.Since(start) > time.Second {
				t.Fatal("unbounded probe", got)
			}
		})
	}
}
