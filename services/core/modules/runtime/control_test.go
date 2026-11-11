package runtime_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/agent/journal"
	"github.com/pavlith/arc/services/core/migrations"
	"github.com/pavlith/arc/services/core/modules/runtime"
	"github.com/pavlith/arc/test/testdb"
	"gorm.io/gorm"
)

type controlPolicy struct {
	actor, caller string
	denied        bool
}

func (p *controlPolicy) Manager(context.Context) (string, error) {
	if p.denied {
		return "", security.ErrDenied
	}
	return p.actor, nil
}
func (p *controlPolicy) Node(context.Context) (string, error) {
	if p.denied {
		return "", security.ErrDenied
	}
	return p.caller, nil
}

type controlFixture struct {
	control  *runtime.Control
	policy   *controlPolicy
	db       *gorm.DB
	pub      ed25519.PublicKey
	key      ed25519.PrivateKey
	now      time.Time
	template agent.Template
}

func newControlFixture(t *testing.T) *controlFixture {
	t.Helper()
	db, _ := testdb.Open(t, "core")
	for _, sql := range []string{
		`INSERT INTO identity_users(id,email) VALUES('admin','admin@example.com'),('other','other@example.com')`,
		`INSERT INTO identity_service_accounts(id,service_definition,deployment) VALUES('node-sa','arc-agent','one'),('other-sa','arc-agent','two')`,
	} {
		if err := db.Exec(sql).Error; err != nil {
			t.Fatal(err)
		}
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &controlFixture{db: db, pub: pub, key: key, now: time.Unix(1800000000, 0).UTC(), policy: &controlPolicy{actor: "user:admin", caller: "node-sa"}, template: agent.Template{ID: "task", Revision: 1, Kind: agent.Docker, Target: "registry/arc/task@sha256:" + strings.Repeat("a", 64), MaxReplicas: 3}}
	f.control, err = runtime.NewControl(runtime.ControlConfig{DB: db, Policy: f.policy, SigningKey: key, Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.control.RegisterNode(context.Background(), runtime.NodeRegistration{ID: "node-one", ServiceAccountID: "node-sa", Capabilities: []agent.Kind{agent.Docker}}); err != nil {
		t.Fatal(err)
	}
	if err := f.control.RegisterNode(context.Background(), runtime.NodeRegistration{ID: "node-two", ServiceAccountID: "other-sa", Capabilities: []agent.Kind{agent.Docker}}); err != nil {
		t.Fatal(err)
	}
	if err := f.control.ApproveTemplate(context.Background(), "node-one", f.template); err != nil {
		t.Fatal(err)
	}
	return f
}
func change(key string, expected int64) runtime.Change {
	return runtime.Change{IdempotencyKey: key, ExpectedRevision: expected, Spec: agent.Spec{ID: "task-prod", NodeID: "node-one", Kind: agent.Docker, TemplateID: "task", TemplateRevision: 1, State: agent.Running, Replicas: 1}}
}
func countRows(t *testing.T, db *gorm.DB, table string) int64 {
	t.Helper()
	var count int64
	if err := db.Table(table).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	return count
}

type fakeHost struct{ calls int }

func (h *fakeHost) Apply(_ context.Context, s agent.Spec, _ agent.Template) (agent.Observation, error) {
	h.calls++
	return agent.Observation{ResourceID: s.ID, NodeID: s.NodeID, Revision: s.Revision, State: s.State, Running: s.Replicas}, nil
}
func (h *fakeHost) Inspect(_ context.Context, s agent.Spec, _ agent.Template) (agent.Observation, error) {
	return agent.Observation{ResourceID: s.ID, NodeID: s.NodeID, Revision: s.Revision, State: s.State, Running: s.Replicas}, nil
}

func TestControlSQLiteAgentRoundTrip(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	request := change("create", 0)
	receipt, err := f.control.Apply(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := f.control.Apply(ctx, request)
	if err != nil || replay != receipt {
		t.Fatalf("receipt replay: %+v %v", replay, err)
	}
	for _, table := range []string{"runtime_resources", "runtime_operations", "runtime_revisions", "runtime_outbox"} {
		if n := countRows(t, f.db, table); n != 1 {
			t.Fatalf("%s duplicate: %d", table, n)
		}
	}
	request.Spec.Replicas = 2
	if _, err := f.control.Apply(ctx, request); !errors.Is(err, runtime.ErrConflict) {
		t.Fatalf("same key changed payload: %v", err)
	}
	inventory, err := f.control.Inventory(ctx, agent.InventoryRequest{NodeID: "node-one"})
	if err != nil || len(inventory.ResourceIDs) != 1 || inventory.ResourceIDs[0] != "task-prod" {
		t.Fatalf("node reconnect discovery: %+v %v", inventory, err)
	}
	pull := agent.PullRequest{NodeID: "node-one", ResourceID: "task-prod", RequestID: "fresh-request-123456"}
	signed, err := f.control.Pull(ctx, pull)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(signed)
	state, err := journal.Open(filepath.Join(t.TempDir(), "agent"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	host := &fakeHost{}
	executor := &agent.Executor{NodeID: "node-one", CoreKey: f.pub, Templates: map[string]agent.Template{"task": f.template}, Drivers: map[agent.Kind]agent.Driver{agent.Docker: host}, Journal: state, Now: func() time.Time { return f.now }}
	observed, err := executor.Reconcile(ctx, raw, pull.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	report := agent.Report{EventID: "event-one", OperationID: receipt.OperationID, SpecDigest: agent.SpecDigest(receipt.Desired), Status: agent.Succeeded, Observation: observed}
	if err := f.control.Report(ctx, report); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Second)
	if err := f.control.Report(ctx, report); err != nil {
		t.Fatal(err)
	}
	if countRows(t, f.db, "runtime_reports") != 1 {
		t.Fatal("duplicate report persisted")
	}
	got, err := f.control.Resource(ctx, "task-prod")
	if err != nil || got.Observed == nil || got.Observed.Report != report || got.Observed.ReceivedAt.Equal(f.now) {
		t.Fatalf("observation replay changed state: %+v %v", got, err)
	}
	op, err := f.control.Operation(ctx, receipt.OperationID)
	if err != nil || op.Status != agent.Succeeded {
		t.Fatalf("operation not completed: %+v %v", op, err)
	}
	if _, err := executor.Reconcile(ctx, raw, pull.RequestID); err != nil || host.calls != 1 {
		t.Fatalf("duplicate host effect: %d %v", host.calls, err)
	}
	nodes, err := f.control.Nodes(ctx, "")
	if err != nil || len(nodes) != 2 || nodes[0].LastSeenAt == nil {
		t.Fatalf("node liveness: %+v %v", nodes, err)
	}
}

func TestControlRevisionOwnershipAndReports(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	receipt, err := f.control.Apply(ctx, change("create", 0))
	if err != nil {
		t.Fatal(err)
	}
	pull := agent.PullRequest{NodeID: "node-one", ResourceID: "task-prod", RequestID: "fresh-request-123456"}
	f.policy.caller = "other-sa"
	if _, err := f.control.Inventory(ctx, agent.InventoryRequest{NodeID: "node-one"}); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("foreign node inventory: %v", err)
	}
	own, err := f.control.Inventory(ctx, agent.InventoryRequest{NodeID: "node-two"})
	if err != nil || len(own.ResourceIDs) != 0 {
		t.Fatalf("other node resources leaked: %+v %v", own, err)
	}

	if _, err := f.control.Pull(ctx, pull); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("foreign node pull: %v", err)
	}
	report := agent.Report{EventID: "event-one", OperationID: receipt.OperationID, SpecDigest: agent.SpecDigest(receipt.Desired), Status: agent.Succeeded, Observation: agent.Observation{ResourceID: "task-prod", NodeID: "node-one", Revision: 1, State: agent.Running, Running: 1}}
	if err := f.control.Report(ctx, report); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("foreign node report: %v", err)
	}
	f.policy.caller = "node-sa"
	bad := report
	bad.SpecDigest = strings.Repeat("0", 64)
	if err := f.control.Report(ctx, bad); !errors.Is(err, runtime.ErrInvalid) {
		t.Fatalf("wrong digest: %v", err)
	}
	bad = report
	bad.Observation.Running = 0
	if err := f.control.Report(ctx, bad); !errors.Is(err, runtime.ErrInvalid) {
		t.Fatalf("premature success: %v", err)
	}
	if err := f.control.Report(ctx, report); err != nil {
		t.Fatal(err)
	}
	bad = report
	bad.Status = agent.InProgress
	if err := f.control.Report(ctx, bad); !errors.Is(err, runtime.ErrConflict) {
		t.Fatalf("report receipt conflict: %v", err)
	}
	next := change("stop", 1)
	next.Spec.State = agent.Stopped
	next.Spec.Replicas = 0
	stopped, err := f.control.Apply(ctx, next)
	if err != nil || stopped.Desired.Revision != 2 {
		t.Fatalf("stop: %+v %v", stopped, err)
	}
	// Already recorded duplicate reports are harmless even after a new revision.
	if err := f.control.Report(ctx, report); err != nil {
		t.Fatal(err)
	}
	report.EventID = "old-revision-new-event"
	if err := f.control.Report(ctx, report); !errors.Is(err, runtime.ErrConflict) {
		t.Fatalf("stale report accepted: %v", err)
	}
	before, err := f.control.Resource(ctx, "task-prod")
	if err != nil || before.Observed.Report.Observation.Revision != 1 || before.Desired.Revision != 2 {
		t.Fatalf("desired/observed conflated: %+v %v", before, err)
	}
	moved := change("move", 2)
	moved.Spec.NodeID = "node-two"
	if err := f.control.ApproveTemplate(ctx, "node-two", f.template); err != nil {
		t.Fatal(err)
	}
	if _, err := f.control.Apply(ctx, moved); !errors.Is(err, runtime.ErrConflict) {
		t.Fatalf("resource retargeted: %v", err)
	}
	deleted := change("delete", 2)
	deleted.Spec.State = agent.Deleted
	deleted.Spec.Replicas = 0
	if _, err := f.control.Apply(ctx, deleted); err != nil {
		t.Fatal(err)
	}
	if _, err := f.control.Apply(ctx, change("resurrect", 3)); !errors.Is(err, runtime.ErrConflict) {
		t.Fatalf("deleted ownership reused: %v", err)
	}
	previous, err := f.control.Operation(ctx, stopped.OperationID)
	if err != nil || previous.Status != agent.Cancelled {
		t.Fatalf("superseded operation: %+v %v", previous, err)
	}
	if countRows(t, f.db, "runtime_revisions") != 3 {
		t.Fatal("immutable revision history lost")
	}
}

func TestControlFailsClosedAndRevokes(t *testing.T) {
	if _, err := runtime.NewControl(runtime.ControlConfig{}); !errors.Is(err, security.ErrUnavailable) {
		t.Fatal(err)
	}
	f := newControlFixture(t)
	ctx := context.Background()
	request := change("create", 0)
	receipt, err := f.control.Apply(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	f.policy.denied = true
	if _, err := f.control.Apply(ctx, request); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("revoked manager replay: %v", err)
	}
	if _, err := f.control.Resources(ctx, ""); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("unprivileged inventory: %v", err)
	}
	f.policy.denied = false
	f.policy.actor = "service:admin"
	if _, err := f.control.Apply(ctx, request); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("service actor management: %v", err)
	}
	f.policy.actor = "user:admin"
	if err := f.db.Exec(`UPDATE identity_users SET status='disabled' WHERE id='admin'`).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := f.control.Apply(ctx, request); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("disabled user replay: %v", err)
	}
	if err := f.db.Exec(`UPDATE identity_users SET status='active' WHERE id='admin'`).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.control.RevokeTemplate(ctx, "node-one", "task", 1); err != nil {
		t.Fatal(err)
	}
	pull := agent.PullRequest{NodeID: "node-one", ResourceID: receipt.Desired.ID, RequestID: "fresh-request-123456"}
	if _, err := f.control.Pull(ctx, pull); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("revoked template pull: %v", err)
	}
	if err := f.control.ApproveTemplate(ctx, "node-one", f.template); !errors.Is(err, runtime.ErrConflict) {
		t.Fatalf("revoked template resurrected: %v", err)
	}
	if err := f.control.DisableNode(ctx, "node-one"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.control.Pull(ctx, pull); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("disabled node pull: %v", err)
	}
	if err := f.control.RegisterNode(ctx, runtime.NodeRegistration{ID: "node-one", ServiceAccountID: "node-sa", Capabilities: []agent.Kind{agent.Docker}}); !errors.Is(err, runtime.ErrConflict) {
		t.Fatalf("disabled node reactivated: %v", err)
	}
}

func TestControlAtomicityAndConcurrentCAS(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	// Fail the last write: every earlier desired/operation/revision/audit write
	// must roll back with it, including the deferred current-operation FK.
	if err := f.db.Exec(`CREATE TRIGGER reject_runtime_hint BEFORE INSERT ON runtime_outbox BEGIN SELECT RAISE(ABORT,'injected outbox failure'); END`).Error; err != nil {
		t.Fatal(err)
	}
	audits := countRows(t, f.db, "runtime_audit")
	if _, err := f.control.Apply(ctx, change("create", 0)); !errors.Is(err, security.ErrUnavailable) {
		t.Fatalf("outbox failure lost: %v", err)
	}
	for _, table := range []string{"runtime_resources", "runtime_operations", "runtime_revisions", "runtime_outbox"} {
		if countRows(t, f.db, table) != 0 {
			t.Fatalf("partial commit in %s", table)
		}
	}
	if countRows(t, f.db, "runtime_audit") != audits {
		t.Fatal("audit escaped rollback")
	}
	if err := f.db.Exec(`DROP TRIGGER reject_runtime_hint`).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := f.control.Apply(ctx, change("create", 0)); err != nil {
		t.Fatal(err)
	}
	sqlDB, err := f.db.DB()
	if err != nil {
		t.Fatal(err)
	}
	other, err := database.Open(ctx, testdb.Path(t, sqlDB))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(other)
	second, err := runtime.NewControl(runtime.ControlConfig{DB: other, Policy: f.policy, SigningKey: f.key, Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 6)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			control := f.control
			if i%2 == 1 {
				control = second
			}
			request := change(fmt.Sprintf("update-%d", i), 1)
			request.Spec.Replicas = 2
			_, err := control.Apply(ctx, request)
			results <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if !errors.Is(err, runtime.ErrConflict) {
			t.Errorf("CAS error: %v", err)
		}
	}
	if wins != 1 || countRows(t, f.db, "runtime_operations") != 2 || countRows(t, f.db, "runtime_outbox") != 2 {
		t.Fatalf("CAS did not serialize: %d", wins)
	}
}

func TestRuntimeControlMigrationUpgradePreservesLegacy(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "core.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(db)
	all := migrations.SQLite()
	if err := database.Migrate(ctx, db, all[:5]); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO runtime_desired_deployments(id,service_name,spec,replicas,revision) VALUES('legacy','task','{"image":"old:tag"}',1,7)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx, db, all); err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx, db, all); err != nil {
		t.Fatal(err)
	}
	var revision int64
	if err := db.Table("runtime_desired_deployments").Select("revision").Where("id='legacy'").Scan(&revision).Error; err != nil || revision != 7 {
		t.Fatalf("legacy changed: %d %v", revision, err)
	}
	if countRows(t, db, "runtime_resources") != 0 {
		t.Fatal("legacy arbitrary spec became executable")
	}
}

func TestControlHistoryAndAdmissionGuards(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	if err := f.db.Exec(`INSERT INTO identity_service_accounts(id,service_definition,deployment) VALUES('core-sa','arc-core','bootstrap')`).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.control.RegisterNode(ctx, runtime.NodeRegistration{ID: "bad-node", ServiceAccountID: "core-sa", Capabilities: []agent.Kind{agent.Docker}}); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("bootstrap service account enrolled: %v", err)
	}
	template := f.template
	template.Target = "registry/task:latest"
	if err := f.control.ApproveTemplate(ctx, "node-one", template); !errors.Is(err, runtime.ErrInvalid) {
		t.Fatalf("mutable image approved: %v", err)
	}
	template = f.template
	template.Kind = agent.Systemd
	template.Target = "task.service"
	template.MaxReplicas = 1
	if err := f.control.ApproveTemplate(ctx, "node-one", template); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("unsupported node driver approved: %v", err)
	}
	request := change("bootstrap", 0)
	request.Spec.ID = "arc-core"
	if _, err := f.control.Apply(ctx, request); !errors.Is(err, runtime.ErrInvalid) {
		t.Fatalf("bootstrap managed: %v", err)
	}
	receipt, err := f.control.Apply(ctx, change("create", 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		`UPDATE runtime_revisions SET digest='` + strings.Repeat("b", 64) + `'`,
		`DELETE FROM runtime_revisions`, `UPDATE runtime_audit SET actor='attacker'`, `DELETE FROM runtime_audit`,
		`UPDATE runtime_templates SET spec='{}'`, `UPDATE runtime_nodes SET service_account_id='other-sa' WHERE id='node-one'`,
		`DELETE FROM runtime_resources`, `UPDATE runtime_operations SET requested_revision=2`,
		`UPDATE runtime_resources SET revision=3 WHERE id='task-prod'`,
	} {
		if err := f.db.Exec(sql).Error; err == nil {
			t.Fatalf("history mutation allowed: %s", sql)
		}
	}
	if err := f.db.Exec(`UPDATE identity_service_accounts SET disabled_at=CURRENT_TIMESTAMP WHERE id='node-sa'`).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := f.control.Pull(ctx, agent.PullRequest{NodeID: "node-one", ResourceID: receipt.Desired.ID, RequestID: "fresh-request-123456"}); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("disabled service account pull: %v", err)
	}
}

func TestControlReportRollbackAndTerminalFailure(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	receipt, err := f.control.Apply(ctx, change("create", 0))
	if err != nil {
		t.Fatal(err)
	}
	report := agent.Report{EventID: "report-one", OperationID: receipt.OperationID, SpecDigest: agent.SpecDigest(receipt.Desired), Status: agent.InProgress, Observation: agent.Observation{ResourceID: "task-prod", NodeID: "node-one", Revision: 1, State: agent.Running}}
	if err := f.db.Exec(`CREATE TRIGGER reject_report_audit BEFORE INSERT ON runtime_audit WHEN NEW.action='node.report' BEGIN SELECT RAISE(ABORT,'injected audit failure'); END`).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.control.Report(ctx, report); !errors.Is(err, security.ErrUnavailable) {
		t.Fatalf("report write failure: %v", err)
	}
	if countRows(t, f.db, "runtime_reports") != 0 || countRows(t, f.db, "runtime_observations") != 0 {
		t.Fatal("receipt or observation escaped rollback")
	}
	op, err := f.control.Operation(ctx, receipt.OperationID)
	if err != nil || op.Status != agent.Pending {
		t.Fatalf("operation escaped rollback: %+v %v", op, err)
	}
	nodes, err := f.control.Nodes(ctx, "")
	if err != nil || nodes[0].LastSeenAt != nil {
		t.Fatalf("liveness escaped rollback: %+v %v", nodes, err)
	}
	if err := f.db.Exec(`DROP TRIGGER reject_report_audit`).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.control.Report(ctx, report); err != nil {
		t.Fatal(err)
	}
	report.EventID = "report-failed"
	report.Status = agent.Failed
	report.ErrorCode = "DRIVER_FAILED"
	if err := f.control.Report(ctx, report); err != nil {
		t.Fatal(err)
	}
	op, err = f.control.Operation(ctx, receipt.OperationID)
	if err != nil || op.Status != agent.Failed || op.ErrorCode != "DRIVER_FAILED" {
		t.Fatalf("failure not recorded: %+v %v", op, err)
	}
	if _, err := f.control.Pull(ctx, agent.PullRequest{NodeID: "node-one", ResourceID: "task-prod", RequestID: "fresh-request-123456"}); !errors.Is(err, runtime.ErrConflict) {
		t.Fatalf("terminal failed operation restarted: %v", err)
	}
	report.EventID = "invented-success"
	report.Status = agent.Succeeded
	report.ErrorCode = ""
	report.Observation.Running = 1
	if err := f.control.Report(ctx, report); !errors.Is(err, runtime.ErrConflict) {
		t.Fatalf("terminal failure overwritten: %v", err)
	}
	if _, err := f.control.Apply(ctx, change("explicit-retry", 1)); err != nil {
		t.Fatal(err)
	}
}

func TestInventoryCoalescesNodeLiveness(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	readSeen := func() time.Time {
		t.Helper()
		var row struct{ LastSeenAt *time.Time }
		if err := f.db.Table("runtime_nodes").Select("last_seen_at").Where("id=?", "node-one").Take(&row).Error; err != nil {
			t.Fatal(err)
		}
		if row.LastSeenAt == nil {
			t.Fatal("node has no liveness timestamp")
		}
		return *row.LastSeenAt
	}
	if _, err := f.control.Inventory(ctx, agent.InventoryRequest{NodeID: "node-one"}); err != nil {
		t.Fatal(err)
	}
	first := readSeen()
	f.now = f.now.Add(30 * time.Second)
	if _, err := f.control.Inventory(ctx, agent.InventoryRequest{NodeID: "node-one"}); err != nil {
		t.Fatal(err)
	}
	if !readSeen().Equal(first) {
		t.Fatal("unchanged node caused unnecessary heartbeat write")
	}
	f.now = f.now.Add(61 * time.Second)
	if _, err := f.control.Inventory(ctx, agent.InventoryRequest{NodeID: "node-one"}); err != nil {
		t.Fatal(err)
	}
	if !readSeen().After(first) {
		t.Fatal("online node liveness did not refresh")
	}
}

func TestHostFactsVisibleOnlyToAuthorizedCoreNodeReader(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	host := &agent.HostFacts{
		OS: "ubuntu", Version: "26.04", Architecture: "amd64",
		Kernel: "6.12.0-generic", CPUThreads: 4,
		MemoryBytes: 4 << 30, RootTotal: 10 << 30,
		RootAvailable: 7 << 30, APT: true, Systemd: true,
	}
	if _, err := f.control.Inventory(ctx, agent.InventoryRequest{NodeID: "node-one", Host: host}); err != nil {
		t.Fatal(err)
	}
	nodes, err := f.control.Nodes(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, n := range nodes {
		if n.ID == "node-one" {
			found = true
			if n.Host == nil || *n.Host != *host {
				t.Fatalf("facts not preserved: %+v", n.Host)
			}
		}
	}
	if !found {
		t.Fatal("registered node not returned")
	}
	if _, err := f.control.Inventory(ctx, agent.InventoryRequest{NodeID: "node-one", AfterID: "other", Host: host}); !errors.Is(err, runtime.ErrInvalid) {
		t.Fatalf("host facts unexpectedly accepted in page continuation: %v", err)
	}
	bad := *host
	bad.Kernel = "invalid kernel with spaces"
	if _, err := f.control.Inventory(ctx, agent.InventoryRequest{NodeID: "node-one", Host: &bad}); !errors.Is(err, runtime.ErrInvalid) {
		t.Fatalf("invalid facts accepted: %v", err)
	}
	f.policy.caller = "other-sa"
	if _, err := f.control.Inventory(ctx, agent.InventoryRequest{NodeID: "node-one", Host: host}); err == nil {
		t.Fatal("cross-node facts injection accepted")
	}
}
