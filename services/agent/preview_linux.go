package agent

import (
	"context"

	"github.com/pavlith/arc/services/agent/modules/apt"
	"github.com/pavlith/arc/services/agent/modules/host"
)

// PreviewProfileFile obtains a Core-approved, signed profile with this node's
// private credentials, then runs a read-only local APT simulation. It does not
// start reconciliation, install software or open a privileged shell.
func PreviewProfileFile(ctx context.Context, configPath, profileID string, revision int64) (apt.ProfilePackagePlan, error) {
	cfg, err := ReadConfig(configPath)
	if err != nil || revision < 1 {
		return apt.ProfilePackagePlan{}, ErrInvalid
	}
	link, err := openNodeClient(ctx, cfg)
	if err != nil {
		return apt.ProfilePackagePlan{}, err
	}
	defer link.Close()
	facts, err := host.Collect(ctx)
	if err != nil {
		return apt.ProfilePackagePlan{}, ErrUnavailable
	}
	return apt.New().PreviewApprovedProfile(ctx, link.provider, link.coreKey, cfg.NodeID, profileID, revision, facts)
}
