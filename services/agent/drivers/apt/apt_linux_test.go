package apt

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestReadOnlyPlanAndInjectionGuards(t *testing.T) {
	var seen []string
	manager := &Manager{run: func(_ context.Context, bin string, args ...string) ([]byte, error) {
		if bin != "/usr/bin/apt-get" {
			t.Fatalf("unexpected command: %s", bin)
		}
		seen = append([]string(nil), args...)
		return []byte("Reading package lists...\nInst docker.io [24] (25 Ubuntu:26.04)\nInst containerd (2.0 Ubuntu:26.04)\nRemv old-service [1]\nConf docker.io (25)\n"), nil
	}}
	plan, err := manager.PlanInstall(context.Background(), []string{"docker.io"})
	if err != nil || !reflect.DeepEqual(plan.Install, []string{"docker.io", "containerd"}) ||
		!reflect.DeepEqual(plan.Remove, []string{"old-service"}) || !plan.NeedsApproval {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	if !slices.Contains(seen, "-s") || !slices.Contains(seen, "--") {
		t.Fatalf("APT was not invoked in simulation mode: %v", seen)
	}
	for _, bad := range []string{"--purge", "-o", "x;id", "x y", "../etc/shadow", strings.Repeat("a", 130)} {
		if _, err := manager.PlanInstall(context.Background(), []string{bad}); !errors.Is(err, ErrInvalid) {
			t.Errorf("accepted dangerous package name %q: %v", bad, err)
		}
	}
	if _, err := manager.PlanInstall(context.Background(), []string{"curl", "curl"}); !errors.Is(err, ErrInvalid) {
		t.Fatal("accepted duplicate package")
	}
}

func TestDpkgInventoryFiltersUninstalled(t *testing.T) {
	manager := &Manager{run: func(_ context.Context, bin string, args ...string) ([]byte, error) {
		if bin != "/usr/bin/dpkg-query" {
			t.Fatalf("unexpected command: %s", bin)
		}
		return []byte("curl\t8.1\tinstalled\nunused\t1.0\tnot-installed\n"), nil
	}}
	pkgs, err := manager.ListInstalled(context.Background())
	if err != nil || len(pkgs) != 1 || pkgs[0].Name != "curl" {
		t.Fatalf("inventory: %+v %v", pkgs, err)
	}
}
