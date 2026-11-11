package host

import (
	"context"
	"strings"
	"testing"
)

func TestParseUbuntuFacts(t *testing.T) {
	id, version, err := osRelease("NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"26.04\"\n")
	if err != nil || id != "ubuntu" || version != "26.04" {
		t.Fatalf("os release: %q %q %v", id, version, err)
	}
	if _, _, err := osRelease("ID=ubuntu\n"); err == nil {
		t.Fatal("incomplete os release accepted")
	}
	n, err := memoryTotal("MemTotal:       4096 kB\nMemFree: 100 kB\n")
	if err != nil || n != 4096*1024 {
		t.Fatalf("memory: %d %v", n, err)
	}
	if _, err := memoryTotal("MemTotal: invalid kB\n"); err == nil {
		t.Fatal("invalid memory accepted")
	}
	if _, err := memoryTotal("MemTotal: " + strings.Repeat("9", 100) + " kB\n"); err == nil {
		t.Fatal("overflow accepted")
	}
}

func TestReadOnlyHostCollection(t *testing.T) {
	facts, err := Collect(context.Background())
	if err != nil {
		t.Skipf("host facts unsupported in test runner: %v", err)
	}
	if err := facts.Validate(); err != nil {
		t.Fatalf("invalid collected facts: %v", err)
	}
}
