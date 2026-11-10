package agent

import (
	"context"
	"crypto/ed25519"
	"sync"
	"time"

	"github.com/pavlith/arc/sdk/security"
)

type Observation struct {
	ResourceID string `json:"resource_id"`
	NodeID     string `json:"node_id"`
	Revision   int64  `json:"revision"`
	State      State  `json:"state"`
	// Running is host state, not Fabric API readiness.
	Running int `json:"running"`
}

type Record struct {
	Revision    int64
	Digest      string
	OperationID string
	Complete    bool
	Observation Observation
}

// Journal must persist before Apply. A production process must hold exclusive
// ownership of its journal and host namespace for its entire lifetime.
type Journal interface {
	Load(context.Context, string) (Record, bool, error)
	Save(context.Context, string, Record) error
}

// Driver must be idempotent across process crashes. Delete retains data, and
// ownership must be established independently of labels supplied by workloads.
type Driver interface {
	Apply(context.Context, Spec, Template) (Observation, error)
}

// Executor serializes the node. It requires a new verified pull even for retries;
// no method executes a stored intent without online Core confirmation.
type Executor struct {
	NodeID    string
	CoreKey   ed25519.PublicKey
	Templates map[string]Template
	Drivers   map[Kind]Driver
	Journal   Journal
	Now       func() time.Time
	mu        sync.Mutex
}

func (e *Executor) Reconcile(ctx context.Context, raw []byte, request string) (Observation, error) {
	if e == nil {
		return Observation{}, security.ErrUnavailable
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	started := time.Now()
	now := started
	if e.Now != nil {
		now = e.Now()
	}
	s, err := Verify(raw, e.CoreKey, e.NodeID, request, now, e.Templates)
	if err != nil {
		return Observation{}, err
	}
	driver := e.Drivers[s.Spec.Kind]
	if driver == nil || e.Journal == nil {
		return Observation{}, security.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	record, exists, err := e.Journal.Load(ctx, s.Spec.ID)
	if err != nil {
		return Observation{}, security.ErrUnavailable
	}
	digest := SpecDigest(s.Spec)
	if exists {
		if s.Spec.Revision < record.Revision || (s.Spec.Revision == record.Revision && (digest != record.Digest || record.OperationID != s.OperationID)) {
			return Observation{}, ErrStale
		}
		if s.Spec.Revision == record.Revision && record.Complete {
			return record.Observation, nil
		}
	}
	record = Record{Revision: s.Spec.Revision, Digest: digest, OperationID: s.OperationID}
	if err := e.Journal.Save(ctx, s.Spec.ID, record); err != nil {
		return Observation{}, security.ErrUnavailable
	}
	// Stop starting new effects when the online authorization expires. A driver
	// must respect cancellation between host API calls; existing workloads survive.
	deadline := time.Unix(s.ExpiresAt, 0)
	// Allow a test clock without changing the actual remaining lease duration.
	remaining := deadline.Sub(now) - time.Since(started)
	if remaining <= 0 {
		return Observation{}, ErrStale
	}
	effectCtx, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	obs, err := driver.Apply(effectCtx, s.Spec, e.Templates[s.Spec.TemplateID])
	if err != nil {
		return Observation{}, err
	}
	if err := effectCtx.Err(); err != nil {
		return Observation{}, err
	}
	if obs.ResourceID != s.Spec.ID || obs.NodeID != e.NodeID || obs.Revision != s.Spec.Revision || obs.State != s.Spec.State || obs.Running != s.Spec.Replicas {
		return Observation{}, ErrInvalid
	}
	record.Complete = true
	record.Observation = obs
	if err := e.Journal.Save(ctx, s.Spec.ID, record); err != nil {
		return Observation{}, security.ErrUnavailable
	}
	return obs, nil
}
