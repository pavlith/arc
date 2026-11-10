// Package reconcile applies the desired state reported by Core to the local node.
package reconcile

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	contract "github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/agent/modules/runtime"
)

var ErrInvalid = runtime.ErrInvalid
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
	runtime  *runtime.Module
	interval time.Duration
	observe  func(string, string)
	reports  contract.ReportJournal
	lastSent map[string]string
	mu       sync.Mutex
}

func New(cfg Config) (*Service, error) {
	if cfg.Provider == nil {
		return nil, ErrInvalid
	}
	interval := cfg.PollInterval
	if interval == 0 {
		interval = 5 * time.Second
	}
	if interval < time.Second || interval > time.Minute {
		return nil, ErrInvalid
	}
	reports, ok := cfg.Journal.(contract.ReportJournal)
	if !ok {
		return nil, ErrInvalid
	}
	execution, err := runtime.New(runtime.Config{
		NodeID: cfg.NodeID, CoreKey: cfg.CoreKey, Templates: cfg.Templates,
		Journal: cfg.Journal, Drivers: cfg.Drivers,
	})
	if err != nil {
		return nil, err
	}
	return &Service{node: cfg.NodeID, provider: cfg.Provider, runtime: execution, interval: interval, observe: cfg.Observe, reports: reports, lastSent: map[string]string{}}, nil
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
	// A receipt was persisted before its first send. Retry the same event ID
	// after reconnect or process restart; never replay an unverified host effect.
	pending, exists, err := s.reports.LoadPending(ctx, id)
	if err != nil {
		s.note(id, "JOURNAL_UNAVAILABLE")
		return ErrUnavailable
	}
	if exists {
		err := s.provider.Report(ctx, pending)
		if err != nil && rpc.ErrorCode(err) != rpc.CodeConflict {
			s.note(id, "REPORT_UNAVAILABLE")
			return ErrUnavailable
		}
		if err := s.reports.DeletePending(ctx, id); err != nil {
			return ErrUnavailable
		}
		if err == nil {
			s.lastSent[id] = pending.EventID
		}
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
	snapshot, obs, execErr := s.runtime.Apply(ctx, id, request, raw)
	if execErr == runtime.ErrInvalidSnapshot {
		s.note(id, "INVALID_SNAPSHOT")
		return ErrUnavailable
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	status := contract.Succeeded
	code := ""
	if execErr != nil {
		if errors.Is(execErr, contract.ErrStale) || errors.Is(execErr, security.ErrUnauthenticated) {
			s.note(id, "INVALID_SNAPSHOT")
			return ErrUnavailable
		}
		// Host timeouts, offline engines and partial rollouts stay retryable.
		// A new online signed pull is required before every subsequent effect.
		if !errors.Is(execErr, security.ErrDenied) {
			s.note(id, "EXECUTOR_UNAVAILABLE")
			return ErrUnavailable
		}
		status = contract.Failed
		code = "POLICY_DENIED"
		obs = contract.Observation{ResourceID: id, NodeID: s.node, Revision: snapshot.Spec.Revision, State: snapshot.Spec.State}
	}
	report := contract.Report{OperationID: snapshot.OperationID, SpecDigest: contract.SpecDigest(snapshot.Spec), Status: status, ErrorCode: code, Observation: obs}
	// Stable event IDs suppress duplicate Core effects after Agent crashes.
	// No fresh report is generated for identical observed state.
	fingerprint, err := json.Marshal(report)
	if err != nil {
		return ErrUnavailable
	}
	sum := sha256.Sum256(fingerprint)
	report.EventID = "report-" + hex.EncodeToString(sum[:])
	if s.lastSent[id] == report.EventID {
		return nil
	}
	if err := s.reports.SavePending(ctx, id, report); err != nil {
		s.note(id, "JOURNAL_UNAVAILABLE")
		return ErrUnavailable
	}
	if err := s.provider.Report(ctx, report); err != nil {
		s.note(id, "REPORT_UNAVAILABLE")
		return ErrUnavailable
	}
	if err := s.reports.DeletePending(ctx, id); err != nil {
		s.note(id, "JOURNAL_UNAVAILABLE")
		return ErrUnavailable
	}
	s.lastSent[id] = report.EventID
	if execErr != nil {
		s.note(id, "POLICY_DENIED")
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
