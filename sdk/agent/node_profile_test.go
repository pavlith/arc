package agent_test

import (
	"testing"

	"github.com/pavlith/arc/sdk/agent"
)

func profileFixture() agent.NodeProfile {
	return agent.NodeProfile{
		ID: "standard", Revision: 1,
		Ubuntu: []string{"24.04", "26.04"},
		Packages: []agent.PackagePin{
			{Name: "curl", Version: "8.5.0-2ubuntu10.6"},
			{Name: "git", Version: "1:2.43.0-1ubuntu7.3"},
		},
		Docker: true, LXD: false,
		Updates: agent.UpdatePolicy{Security: "unattended", Packages: "manual", Reboot: "manual"},
	}
}

func TestNodeProfileValidationAndDigest(t *testing.T) {
	good := profileFixture()
	if err := good.Validate(); err != nil || agent.NodeProfileDigest(good) == "" {
		t.Fatalf("valid profile rejected: %v", err)
	}
	cases := map[string]func(*agent.NodeProfile){
		"wrong revision":               func(p *agent.NodeProfile) { p.Revision = 0 },
		"bootstrap ID":                 func(p *agent.NodeProfile) { p.ID = "arc-agent" },
		"empty release":                func(p *agent.NodeProfile) { p.Ubuntu = nil },
		"unsupported release":          func(p *agent.NodeProfile) { p.Ubuntu = []string{"99.99"} },
		"duplicated release":           func(p *agent.NodeProfile) { p.Ubuntu = []string{"24.04", "24.04"} },
		"unsafe package":               func(p *agent.NodeProfile) { p.Packages[0].Name = "openssh-server" },
		"kernel package":               func(p *agent.NodeProfile) { p.Packages[0].Name = "linux-image-generic" },
		"option injection":             func(p *agent.NodeProfile) { p.Packages[0].Name = "--purge" },
		"unversioned package":          func(p *agent.NodeProfile) { p.Packages[0].Version = "" },
		"bad version":                  func(p *agent.NodeProfile) { p.Packages[0].Version = "1;id" },
		"duplicate packages":           func(p *agent.NodeProfile) { p.Packages[1].Name = p.Packages[0].Name },
		"unsorted packages":            func(p *agent.NodeProfile) { p.Packages[0].Name = "zsh" },
		"unapproved regular upgrades":  func(p *agent.NodeProfile) { p.Updates.Packages = "automatic" },
		"automatic reboot":             func(p *agent.NodeProfile) { p.Updates.Reboot = "automatic" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			bad := profileFixture()
			mutate(&bad)
			if bad.Validate() == nil || agent.NodeProfileDigest(bad) != "" {
				t.Fatal("invalid NodeProfile accepted")
			}
		})
	}
	changed := profileFixture()
	changed.Revision = 2
	if agent.NodeProfileDigest(changed) == agent.NodeProfileDigest(good) {
		t.Fatal("revision must bind the immutable digest")
	}
}
