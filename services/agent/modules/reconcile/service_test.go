package reconcile_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	contract "github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/services/agent/journal"
	"github.com/pavlith/arc/services/agent/modules/reconcile"
)

type provider struct {
	key                              ed25519.PrivateKey
	spec                             contract.Spec
	inventoryID                      string
	offline, failReport, badSnapshot bool
	reports                          []contract.Report
}

func (p *provider) Inventory(context.Context, contract.InventoryRequest) (contract.InventoryPage, error) {
	if p.offline {
		return contract.InventoryPage{}, errors.New("offline")
	}
	id := p.inventoryID
	if id == "" {
		id = p.spec.ID
	}
	return contract.InventoryPage{ResourceIDs: []string{id}}, nil
}
func (p *provider) Pull(_ context.Context, r contract.PullRequest) (contract.SignedSnapshot, error) {
	if p.offline {
		return contract.SignedSnapshot{}, errors.New("offline")
	}
	if p.badSnapshot {
		r.RequestID = "wrong-challenge"
	}
	now := time.Now().Unix()
	return contract.Sign(contract.Snapshot{Version: 1, RequestID: r.RequestID, OperationID: "operation-" + strconv.FormatInt(p.spec.Revision, 10), IssuedAt: now, ExpiresAt: now + 30, Spec: p.spec}, p.key)
}
func (p *provider) Report(_ context.Context, r contract.Report) error {
	p.reports = append(p.reports, r)
	if p.failReport {
		return &rpc.Error{Code: rpc.CodeUnavailable}
	}
	return nil
}

type host struct {
	calls, inspects int
	running         int
	failure         error
}

func (h *host) Apply(_ context.Context, s contract.Spec, _ contract.Template) (contract.Observation, error) {
	h.calls++
	if h.failure != nil {
		return contract.Observation{}, h.failure
	}
	h.running = s.Replicas
	return contract.Observation{ResourceID: s.ID, NodeID: s.NodeID, Revision: s.Revision, State: s.State, Running: h.running}, nil
}
func (h *host) Inspect(_ context.Context, s contract.Spec, _ contract.Template) (contract.Observation, error) {
	h.inspects++
	return contract.Observation{ResourceID: s.ID, NodeID: s.NodeID, Revision: s.Revision, State: s.State, Running: h.running}, nil
}
func TestAgentOnlineReconcileDriftAndReportRetry(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := contract.Template{ID: "task", Revision: 1, Kind: contract.Docker, Target: "registry/task@sha256:" + strings.Repeat("a", 64), MaxReplicas: 1}
	p := &provider{key: key, spec: contract.Spec{ID: "task", NodeID: "node-one", Kind: contract.Docker, TemplateID: template.ID, TemplateRevision: 1, TemplateDigest: contract.TemplateDigest(template), Revision: 1, State: contract.Running, Replicas: 1}}
	path := filepath.Join(t.TempDir(), "journal")
	store, err := journal.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h := &host{}
	service, err := reconcile.New(reconcile.Config{NodeID: "node-one", Provider: p, CoreKey: pub, Templates: map[string]contract.Template{"task": template}, Journal: store, Drivers: map[contract.Kind]contract.Driver{contract.Docker: h}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p.failReport = true
	if service.Step(ctx) == nil || h.calls != 1 {
		t.Fatal("report failure lost or host effect absent")
	}
	event := p.reports[0].EventID
	// Simulate a process crash while Core acknowledgement is uncertain.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = journal.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service, err = reconcile.New(reconcile.Config{NodeID: "node-one", Provider: p, CoreKey: pub, Templates: map[string]contract.Template{"task": template}, Journal: store, Drivers: map[contract.Kind]contract.Driver{contract.Docker: h}})
	if err != nil {
		t.Fatal(err)
	}
	p.offline = true
	if service.Step(ctx) == nil || h.calls != 1 {
		t.Fatal("offline cached state executed")
	}
	p.offline = false
	p.failReport = false
	if err := service.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if p.reports[1].EventID != event || h.calls != 1 || h.inspects == 0 {
		t.Fatal("pending receipt retry or idempotent inspection failed")
	}
	// An unchanged observation must not create a fresh operational receipt.
	if err := service.Step(ctx); err != nil || len(p.reports) != 2 {
		t.Fatalf("unchanged state created duplicate report: reports=%d err=%v", len(p.reports), err)
	}
	h.running = 0
	if err := service.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if h.calls != 2 || h.running != 1 {
		t.Fatal("fresh online drift was not repaired")
	}
	h.running = 0
	p.badSnapshot = true
	if service.Step(ctx) == nil || h.calls != 2 {
		t.Fatal("invalid signed snapshot repaired host")
	}
	p.badSnapshot = false
	p.inventoryID = "another-resource"
	if service.Step(ctx) == nil || h.calls != 2 {
		t.Fatal("snapshot for a different resource repaired host")
	}
	p.inventoryID = ""
	p.spec.Revision = 2
	if err := service.Step(ctx); err != nil || h.calls != 3 {
		t.Fatalf("new revision: %d %v", h.calls, err)
	}
	// Restart restores the high-water mark, never a cached command.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = journal.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	p.badSnapshot = false
	p.spec.Revision = 1
	restarted, err := reconcile.New(reconcile.Config{NodeID: "node-one", Provider: p, CoreKey: pub, Templates: map[string]contract.Template{"task": template}, Journal: store, Drivers: map[contract.Kind]contract.Driver{contract.Docker: h}})
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Step(ctx) == nil || h.calls != 3 {
		t.Fatal("restart accepted stale/invalid revision")
	}
}

func TestAgentTransientHostFailureKeepsOperationPending(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := contract.Template{ID: "task", Revision: 1, Kind: contract.Docker, Target: "registry/task@sha256:" + strings.Repeat("a", 64), MaxReplicas: 1}
	p := &provider{key: key, spec: contract.Spec{ID: "task", NodeID: "node-one", Kind: contract.Docker, TemplateID: template.ID, TemplateRevision: 1, TemplateDigest: contract.TemplateDigest(template), Revision: 1, State: contract.Running, Replicas: 1}}
	store, err := journal.Open(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h := &host{failure: context.DeadlineExceeded}
	service, err := reconcile.New(reconcile.Config{NodeID: "node-one", Provider: p, CoreKey: pub, Templates: map[string]contract.Template{"task": template}, Journal: store, Drivers: map[contract.Kind]contract.Driver{contract.Docker: h}})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Step(context.Background()); err == nil || len(p.reports) != 0 {
		t.Fatalf("temporary failure was reported as terminal: err=%v reports=%v", err, p.reports)
	}
	h.failure = nil
	if err := service.Step(context.Background()); err != nil || len(p.reports) != 1 || h.calls != 2 {
		t.Fatalf("retry after fresh pull failed: err=%v reports=%v calls=%d", err, p.reports, h.calls)
	}
}
