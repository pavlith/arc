package agent_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pavlith/arc/sdk"
	contract "github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/services/agent"
)

func TestPrivateConfigRejectsUnknownAndUnsafeDrivers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	cfg := agent.FileConfig{NodeID: "node-one", ServiceID: "service-account", Kid: "node-key", KeyFile: filepath.Join(dir, "service.seed"), CoreSnapshotKeyFile: filepath.Join(dir, "public.json"), StateDirectory: filepath.Join(dir, "state"), PollSeconds: 1, NATS: sdk.Config{URL: "tls://localhost:4222", NKeySeedFile: filepath.Join(dir, "nats.seed"), TLSCAFile: filepath.Join(dir, "ca.crt")}}
	raw, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.ReadConfig(path); err != nil {
		t.Fatal(err)
	}
	for _, content := range [][]byte{append([]byte(`{"shell":"id",`), raw[1:]...), []byte(`{"node_id":"one","node_id":"two"}`)} {
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := agent.ReadConfig(path); err == nil {
			t.Fatal("unknown or duplicate config fields accepted")
		}
	}
	cfg.Templates = []contract.Template{{ID: "worker", Revision: 1, Kind: contract.Systemd, Target: "ssh.service", MaxReplicas: 1}}
	raw, _ = json.Marshal(cfg)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.ReadConfig(path); err == nil {
		t.Fatal("bootstrap unit accepted")
	}
	cfg.Templates = nil
	raw, _ = json.Marshal(cfg)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.ReadConfig(path); err == nil {
		t.Fatal("public privileged configuration accepted")
	}
}
