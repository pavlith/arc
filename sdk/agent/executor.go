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

// Inspector re-observes an already completed revision on a fresh online pull.
// A drifted resource may be repaired idempotently; inspection errors fail closed.
type Inspector interface {
	Inspect(context.Context, Spec, Template) (Observation, error)
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
	remaining := time.Unix(s.ExpiresAt, 0).Sub(now) - time.Since(started)
	if remaining <= 0 {
		return Observation{}, ErrStale
	}
	effectCtx, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	record, exists, err := e.Journal.Load(effectCtx, s.Spec.ID)
	if err != nil {
		return Observation{}, security.ErrUnavailable
	}
	digest := SpecDigest(s.Spec)
	completed := false
	if exists {
		if s.Spec.Revision < record.Revision || (s.Spec.Revision == record.Revision && (digest != record.Digest || record.OperationID != s.OperationID)) {
			return Observation{}, ErrStale
		}
		completed = s.Spec.Revision == record.Revision && record.Complete
		if completed {
			inspector, ok := driver.(Inspector)
			if !ok {
				return record.Observation, nil
			}
			current, err := inspector.Inspect(effectCtx, s.Spec, e.Templates[s.Spec.TemplateID])
			if err != nil {
				return Observation{}, err
			}
			if err := effectCtx.Err(); err != nil {
				return Observation{}, err
			}
			if current.ResourceID != s.Spec.ID || current.NodeID != e.NodeID || current.Revision != s.Spec.Revision || current.State != s.Spec.State {
				return Observation{}, ErrInvalid
			}
			if current.Running == s.Spec.Replicas {
				return current, nil
			}
		}
	}
	// A completed intent remains durable during drift repair. Resetting its
	// high-water mark would weaken crash/replay protection.
	if !completed {
		record = Record{Revision: s.Spec.Revision, Digest: digest, OperationID: s.OperationID}
		if err := e.Journal.Save(effectCtx, s.Spec.ID, record); err != nil {
			return Observation{}, security.ErrUnavailable
		}
	}
	if err := effectCtx.Err(); err != nil {
		return Observation{}, err
	}
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
	if err := e.Journal.Save(effectCtx, s.Spec.ID, record); err != nil {
		return Observation{}, security.ErrUnavailable
	}
	return obs, nil
}
