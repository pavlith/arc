package agent_test

import (
	"testing"

	"github.com/pavlith/arc/sdk/agent"
)

func TestHostFactsBounded(t *testing.T) {
	facts := agent.HostFacts{
		OS: "ubuntu", Version: "26.04", Architecture: "amd64",
		Kernel: "6.12.0-generic", CPUThreads: 2,
		MemoryBytes: 4 << 30, RootTotal: 10 << 30, RootAvailable: 5 << 30,
	}
	if err := facts.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		edit func(*agent.HostFacts)
	}{
		{"newline", func(f *agent.HostFacts) { f.Kernel = "6.12\nsecret" }},
		{"oversized", func(f *agent.HostFacts) { f.Version = string(make([]byte, 200)) }},
		{"empty", func(f *agent.HostFacts) { f.OS = "" }},
		{"bad cpu", func(f *agent.HostFacts) { f.CPUThreads = 0 }},
		{"disk overflow", func(f *agent.HostFacts) { f.RootAvailable = f.RootTotal + 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := facts
			tc.edit(&bad)
			if bad.Validate() == nil {
				t.Fatal("accepted invalid host facts")
			}
		})
	}
}
