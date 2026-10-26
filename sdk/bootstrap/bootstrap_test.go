package bootstrap_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pavlith/arc/sdk/bootstrap"
)

type config struct {
	bootstrap.Config
	Extra string `json:"extra"`
}

func TestServiceConfigStrictAndIndependent(t *testing.T) {
	file := filepath.Join(t.TempDir(), "service.json")
	if err := os.WriteFile(file, []byte(`{"service_id":"task-1","instance":"instance","extra":"task"}`), 0600); err != nil {
		t.Fatal(err)
	}
	var cfg config
	if err := bootstrap.ReadConfig(file, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.ServiceID != "task-1" || cfg.Instance != "instance" || cfg.Extra != "task" {
		t.Fatalf("embedded service config not decoded: %+v", cfg)
	}
	for _, raw := range []string{
		`{"service_id":"task-1","instance":"instance","foreign_service":"oops"}`,
		`{"service_id":"task-1","service_id":"task-2"}`,
		`{"service_id":"task-1"} {}`,
		`[]`,
	} {
		if err := os.WriteFile(file, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if err := bootstrap.ReadConfig(file, &config{}); !errors.Is(err, bootstrap.ErrInvalid) {
			t.Fatalf("invalid config unexpectedly accepted: %s (%v)", raw, err)
		}
	}
}
func TestOpenFailsClosedWithoutProcessIdentity(t *testing.T) {
	if _, err := bootstrap.Open(nil, bootstrap.Config{}); !errors.Is(err, bootstrap.ErrInvalid) {
		t.Fatal("missing process credentials accepted", err)
	}
	if _, err := bootstrap.Open(nil, bootstrap.Config{ServiceID: "one"}); !errors.Is(err, bootstrap.ErrInvalid) {
		t.Fatal("missing instance accepted", err)
	}
}
