// Package runtime executes approved workload state through node-local drivers.
package runtime

import (
	"context"
	"crypto/ed25519"
	"errors"
	"maps"
	"github.com/pavlith/arc/sdk/security"

	contract "github.com/pavlith/arc/sdk/agent"
)

var ErrInvalid = errors.New("agent: invalid service configuration")
var ErrInvalidSnapshot = errors.New("agent: invalid resource snapshot")

type Config struct {
	NodeID    string
	CoreKey   ed25519.PublicKey
	Templates map[string]contract.Template
	Journal   contract.Journal
	Drivers   map[contract.Kind]contract.Driver
}

type Module struct {
	executor contract.Executor
}

func New(cfg Config) (*Module, error) {
	if !contract.ValidID(cfg.NodeID) || cfg.Journal == nil || len(cfg.CoreKey) != ed25519.PublicKeySize {
		return nil, ErrInvalid
	}
	for id, template := range cfg.Templates {
		if id != template.ID || template.Validate() != nil || cfg.Drivers[template.Kind] == nil {
			return nil, ErrInvalid
		}
	}
	return &Module{executor: contract.Executor{
		NodeID:    cfg.NodeID,
		CoreKey:   append(ed25519.PublicKey(nil), cfg.CoreKey...),
		Templates: maps.Clone(cfg.Templates),
		Drivers:   maps.Clone(cfg.Drivers),
		Journal:   cfg.Journal,
	}}, nil
}

// Apply binds the signed snapshot to the requested resource before the executor
// checks the journal and dispatches to the driver.
func (m *Module) Apply(ctx context.Context, resourceID, requestID string, raw []byte) (contract.Snapshot, contract.Observation, error) {
	snapshot, observation, err := m.executor.ReconcileResource(ctx, raw, requestID, resourceID)
	if errors.Is(err, contract.ErrInvalid) || errors.Is(err, security.ErrUnauthenticated) {
		return contract.Snapshot{}, contract.Observation{}, ErrInvalidSnapshot
	}
	return snapshot, observation, err
}
