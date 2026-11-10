// Package agent owns the independently deployed Linux infrastructure executor.
package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	contract "github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
)

var ErrInvalid = errors.New("agent: invalid service configuration")
var ErrUnavailable = errors.New("agent: reconciliation unavailable")

type Config struct {
	NodeID       string
	Provider     contract.RuntimeProvider
	CoreKey      ed25519.PublicKey
	Templates    map[string]contract.Template
	Journal      contract.Journal
	Drivers      map[contract.Kind]contract.Driver
	PollInterval time.Duration
	// Observe receives bounded codes only, never remote/driver error text or tokens.
	Observe func(resource, code string)
}
type Service struct {
	node     string
	provider contract.RuntimeProvider
	executor *contract.Executor
	interval time.Duration
	observe  func(string, string)
	pending  map[string]contract.Report
	mu       sync.Mutex
}

func New(cfg Config) (*Service, error) {
	if !contract.ValidID(cfg.NodeID) || cfg.Provider == nil || cfg.Journal == nil || len(cfg.CoreKey) != ed25519.PublicKeySize {
		return nil, ErrInvalid
	}
	interval := cfg.PollInterval
	if interval == 0 {
		interval = 5 * time.Second
	}
	if interval < time.Second || interval > time.Minute {
		return nil, ErrInvalid
	}
	templates := make(map[string]contract.Template, len(cfg.Templates))
	for id, t := range cfg.Templates {
		if id != t.ID || t.Validate() != nil || cfg.Drivers[t.Kind] == nil {
			return nil, ErrInvalid
		}
		templates[id] = t
	}
	drivers := make(map[contract.Kind]contract.Driver, len(cfg.Drivers))
	for k, d := range cfg.Drivers {
		drivers[k] = d
	}
	return &Service{node: cfg.NodeID, provider: cfg.Provider, executor: &contract.Executor{NodeID: cfg.NodeID, CoreKey: append(ed25519.PublicKey(nil), cfg.CoreKey...), Templates: templates, Drivers: drivers, Journal: cfg.Journal}, interval: interval, observe: cfg.Observe, pending: map[string]contract.Report{}}, nil
}
func nonce(prefix string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", ErrUnavailable
	}
	return prefix + hex.EncodeToString(b[:]), nil
}
func (s *Service) note(resource, code string) {
	if s.observe != nil {
		s.observe(resource, code)
	}
}

// Step serializes the whole node, starts with online inventory and never infers
// deletions from missing resources or executes a stored snapshot after an outage.
func (s *Service) Step(ctx context.Context) (result error) {
	ctx = rpc.StartCorrelation(ctx)
	start := time.Now()
	defer func() {
		correlation := rpc.Correlation(ctx)
		code := rpc.DiagnosticCode(result)
		if errors.Is(result, ErrUnavailable) {
			code = rpc.CodeUnavailable
		}
		slog.InfoContext(ctx, "arc reconcile", "operation", "runtime.reconcile", "node_id", s.node,
			"request_id", correlation.RequestID, "traceparent", correlation.Traceparent,
			"duration_ms", float64(time.Since(start))/float64(time.Millisecond), "error_code", code)
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	after := ""
	failed := false
	for page := 0; page < 1024; page++ {
		inventory, err := s.provider.Inventory(ctx, contract.InventoryRequest{NodeID: s.node, AfterID: after})
		if err != nil {
			s.note("", "INVENTORY_UNAVAILABLE")
			return ErrUnavailable
		}
		if len(inventory.ResourceIDs) > 100 {
			return ErrUnavailable
		}
		previous := after
		for _, id := range inventory.ResourceIDs {
			if !contract.ValidID(id) || id <= previous {
				return ErrUnavailable
			}
			previous = id
		}
		if inventory.NextID != "" && (len(inventory.ResourceIDs) == 0 || inventory.NextID != previous) {
			return ErrUnavailable
		}
		for _, id := range inventory.ResourceIDs {
			if err := s.reconcile(ctx, id); err != nil {
				failed = true
			}
		}
		if inventory.NextID == "" {
			if failed {
				return ErrUnavailable
			}
			return nil
		}
		after = inventory.NextID
	}
	return ErrUnavailable
}
func (s *Service) reconcile(ctx context.Context, id string) error {
	if report, ok := s.pending[id]; ok {
		err := s.provider.Report(ctx, report)
		if err != nil && rpc.ErrorCode(err) != rpc.CodeConflict {
			s.note(id, "REPORT_UNAVAILABLE")
			return ErrUnavailable
		}
		delete(s.pending, id)
	}
	request, err := nonce("pull-")
	if err != nil {
		return err
	}
	signed, err := s.provider.Pull(ctx, contract.PullRequest{NodeID: s.node, ResourceID: id, RequestID: request})
	if err != nil {
		if rpc.ErrorCode(err) == rpc.CodeConflict {
			return nil
		}
		s.note(id, "PULL_UNAVAILABLE")
		return ErrUnavailable
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		return ErrUnavailable
	}
	snapshot, err := contract.Verify(raw, s.executor.CoreKey, s.node, request, time.Now(), s.executor.Templates)
	if err != nil || snapshot.Spec.ID != id {
		s.note(id, "INVALID_SNAPSHOT")
		return ErrUnavailable
	}
	obs, execErr := s.executor.Reconcile(ctx, raw, request)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// Never turn proof, stale revision, journal or ownership uncertainty into a
	// destructive retry. Core receives only bounded failure metadata.
	status := contract.Succeeded
	code := ""
	if execErr != nil {
		if errors.Is(execErr, contract.ErrStale) || errors.Is(execErr, security.ErrUnauthenticated) {
			s.note(id, "INVALID_SNAPSHOT")
			return ErrUnavailable
		}
		status = contract.Failed
		code = "DRIVER_FAILED"
		if errors.Is(execErr, security.ErrDenied) {
			code = "POLICY_DENIED"
		}
		if errors.Is(execErr, security.ErrUnavailable) {
			s.note(id, "EXECUTOR_UNAVAILABLE")
			return ErrUnavailable
		}
		obs = contract.Observation{ResourceID: id, NodeID: s.node, Revision: snapshot.Spec.Revision, State: snapshot.Spec.State}
	}
	event, err := nonce("report-")
	if err != nil {
		return err
	}
	report := contract.Report{EventID: event, OperationID: snapshot.OperationID, SpecDigest: contract.SpecDigest(snapshot.Spec), Status: status, ErrorCode: code, Observation: obs}
	s.pending[id] = report
	if err := s.provider.Report(ctx, report); err != nil {
		s.note(id, "REPORT_UNAVAILABLE")
		return ErrUnavailable
	}
	delete(s.pending, id)
	if execErr != nil {
		s.note(id, "DRIVER_FAILED")
		return ErrUnavailable
	}
	return nil
}

// Run retries online rounds with bounded exponential backoff. Cancellation only
// stops Agent work; it does not stop or delete managed workloads.
func (s *Service) Run(ctx context.Context) error {
	delay := s.interval
	for ctx.Err() == nil {
		err := s.Step(ctx)
		if ctx.Err() != nil {
			break
		}
		wait := s.interval
		if err != nil {
			wait = delay
			delay *= 2
			if delay > time.Minute {
				delay = time.Minute
			}
		} else {
			delay = s.interval
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	return nil
}
