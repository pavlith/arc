package apt

import (
	"context"
	"slices"

	"github.com/pavlith/arc/sdk/agent"
)

// ProfilePackagePlan is a read-only plan bound to an approved profile digest.
// The digest is diagnostic identity, not a signed permission to apply changes.
type ProfilePackagePlan struct {
	ProfileDigest string `json:"profile_digest"`
	Plan          Plan   `json:"plan"`
}

// PlanProfilePackages simulates pinned package changes for a supported Ubuntu
// host. Docker/LXD flags and OS upgrades are explicitly outside this APT plan.
func (m *Manager) PlanProfilePackages(ctx context.Context, profile agent.NodeProfile, host agent.HostFacts) (ProfilePackagePlan, error) {
	if profile.Validate() != nil || host.Validate() != nil || host.OS != "ubuntu" ||
		!host.APT || !slices.Contains(profile.Ubuntu, host.Version) {
		return ProfilePackagePlan{}, ErrInvalid
	}
	digest := agent.NodeProfileDigest(profile)
	names := make([]string, 0, len(profile.Packages))
	for _, pkg := range profile.Packages {
		names = append(names, pkg.Name+"="+pkg.Version)
	}
	if len(names) == 0 {
		return ProfilePackagePlan{ProfileDigest: digest, Plan: Plan{Requested: []string{}}}, nil
	}
	plan, err := m.simulate(ctx, names)
	if err != nil {
		return ProfilePackagePlan{}, err
	}
	return ProfilePackagePlan{ProfileDigest: digest, Plan: plan}, nil
}
