package transport_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/sdk/transport"
)

func TestTransportRejectsInvalidServiceAndEndpoints(t *testing.T) {
	if _, err := transport.New(nil, transport.Config{Name: "service", Version: "1.0.0"}); !errors.Is(err, transport.ErrInvalid) {
		t.Fatal("accepted absent NATS connection", err)
	}
	if err := (*transport.Service)(nil).AddEndpoint("bad", func(transport.Request) {}); !errors.Is(err, transport.ErrInvalid) {
		t.Fatal("accepted nil service", err)
	}
	if err := (*transport.Service)(nil).Stop(); err != nil {
		t.Fatal("nil service Stop", err)
	}
	if got := (*transport.Service)(nil).Info(); got.ID != "" {
		t.Fatal("nil Info should not fabricate service identity")
	}
}

func TestNATSMonitoringAndRouting(t *testing.T) {
	url := os.Getenv("ARC_IDENTITY_NATS_URL")
	dir := os.Getenv("ARC_IDENTITY_NATS_SECRETS")
	if url == "" || dir == "" {
		t.Skip("real TLS NATS fixture not configured")
	}
	opt, err := nats.NkeyOptionFromSeed(filepath.Join(dir, "nats-echo-service.seed"))
	if err != nil {
		t.Fatal(err)
	}
	nc, err := nats.Connect(url, opt, nats.RootCAs(filepath.Join(dir, "ca.crt")),
		nats.Name("arc-transport-test"), nats.Timeout(3*time.Second),
		nats.PermissionErrOnSubscribe(true))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()

	s, err := transport.New(nc, transport.Config{Name: "arc-transport-test", Version: "1.2.3",
		Metadata: map[string]string{"instance_id": "instance-1", "contract_digest": "test-digest"}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	if s.Info().ID == "" {
		t.Fatal("missing Micro-compatible service ID")
	}
	if err := s.AddEndpoint("test_endpoint", func(req transport.Request) {
		_ = req.Respond(append([]byte("echo:"), req.Data()...))
	}, transport.WithEndpointSubject("rpc.transport.v1.echo"),
		transport.WithEndpointQueueGroup("q.transport.v1")); err != nil {
		t.Fatal(err)
	}
	if err := s.AddEndpoint("test_endpoint", func(transport.Request) {}); !errors.Is(err, transport.ErrInvalid) {
		t.Fatal("duplicate endpoint accepted", err)
	}
	if err := s.AddEndpoint("invalid", func(transport.Request) {}, transport.WithEndpointSubject("rpc.*.evil")); !errors.Is(err, transport.ErrInvalid) {
		t.Fatal("wildcard endpoint accepted", err)
	}
	if err := nc.FlushTimeout(4 * time.Second); err != nil {
		t.Fatal(err)
	}
	id := s.Info().ID
	infoMsg, err := nc.Request("$SRV.INFO.arc-transport-test."+id, nil, 4*time.Second)
	if err != nil {
		t.Fatal("INFO control", err)
	}
	var info transport.Info
	if err := json.Unmarshal(infoMsg.Data, &info); err != nil {
		t.Fatal(err)
	}
	if info.ID != id || info.Name != "arc-transport-test" ||
		info.Type != "io.nats.micro.v1.info_response" || len(info.Endpoints) != 1 ||
		info.Endpoints[0].Subject != "rpc.transport.v1.echo" {
		t.Fatalf("incompatible INFO: %+v", info)
	}
	ping, err := nc.Request("$SRV.PING.arc-transport-test."+id, nil, 4*time.Second)
	if err != nil {
		t.Fatal("PING control", err)
	}
	var response struct {
		Name string `json:"name"`
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(ping.Data, &response); err != nil || response.ID != id ||
		response.Type != "io.nats.micro.v1.ping_response" {
		t.Fatalf("incompatible PING: %+v %v", response, err)
	}
	echo, err := nc.Request("rpc.transport.v1.echo", []byte("hello"), 4*time.Second)
	if err != nil || string(echo.Data) != "echo:hello" {
		t.Fatal("endpoint", err, string(echo.Data))
	}
	statsMsg, err := nc.Request("$SRV.STATS.arc-transport-test."+id, nil, 4*time.Second)
	if err != nil {
		t.Fatal("STATS control", err)
	}
	var stats transport.Stats
	if err := json.Unmarshal(statsMsg.Data, &stats); err != nil || stats.ID != id ||
		stats.Type != "io.nats.micro.v1.stats_response" ||
		len(stats.Endpoints) != 1 || stats.Endpoints[0].NumRequests < 1 {
		t.Fatalf("incompatible STATS %+v %v", stats, err)
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := s.Stop(); err != nil {
		t.Fatal("stop not idempotent", err)
	}
	if err := s.AddEndpoint("after_stop", func(transport.Request) {}); !errors.Is(err, transport.ErrStopped) {
		t.Fatal("stopped transport accepted endpoint", err)
	}
	if err := nc.FlushTimeout(4 * time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := nc.Request("$SRV.INFO.arc-transport-test."+id, nil, 500*time.Millisecond); err == nil {
		t.Fatal("stopped micro instance still responding to discovery")
	}
}
