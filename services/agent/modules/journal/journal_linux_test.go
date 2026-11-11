package journal_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/services/agent/modules/journal"
)

func TestDurableRevisionsAndSingleWriter(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agent")
	s, err := journal.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if second, err := journal.Open(dir); err == nil {
		second.Close()
		t.Fatal("second host writer allowed")
	}
	r := agent.Record{Revision: 2, Digest: strings.Repeat("a", 64), OperationID: "op-one"}
	if err = s.Save(context.Background(), "task", r); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = journal.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, ok, err := s.Load(context.Background(), "task")
	if err != nil || !ok || got != r {
		t.Fatalf("restart lost intent: %+v %v %v", got, ok, err)
	}
	old := r
	old.Revision = 1
	if err = s.Save(context.Background(), "task", old); !errors.Is(err, agent.ErrStale) {
		t.Fatalf("stale persisted: %v", err)
	}
	if err = os.WriteFile(filepath.Join(dir, "revisions.json"), []byte(`{"task":`), 0600); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if corrupt, err := journal.Open(dir); err == nil {
		corrupt.Close()
		t.Fatal("corrupt state reset high-water mark")
	}
}

func TestPendingReportsSurviveRestartAndRejectReplacement(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "agent")
	store, err := journal.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	report := agent.Report{
		EventID: "report-one", OperationID: "op-one",
		Status: agent.Succeeded, SpecDigest: strings.Repeat("a", 64),
		Observation: agent.Observation{NodeID: "node-one", ResourceID: "task", Revision: 1, State: agent.Running, Running: 1},
	}
	if err := store.SavePending(ctx, "task", report); err != nil {
		t.Fatal(err)
	}
	replacement := report
	replacement.EventID = "report-two"
	if err := store.SavePending(ctx, "task", replacement); !errors.Is(err, agent.ErrStale) {
		t.Fatalf("pending report was replaced: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = journal.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	got, exists, err := store.LoadPending(ctx, "task")
	if err != nil || !exists || got != report {
		t.Fatalf("lost pending receipt: %+v %v %v", got, exists, err)
	}
	if err := store.DeletePending(ctx, "task"); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := store.LoadPending(ctx, "task"); exists || err != nil {
		t.Fatalf("acked receipt still pending: exists=%v err=%v", exists, err)
	}
}

func TestLegacyRevisionMigratesWithoutRewritingWholeJournal(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "agent")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	legacy := `{"task":{"Revision":1,"Digest":"` + strings.Repeat("a", 64) + `","OperationID":"op-old","Complete":true,"Observation":{"resource_id":"task","node_id":"node-one","revision":1,"state":"running","running":1}}}`
	if err := os.WriteFile(filepath.Join(dir, "revisions.json"), []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := journal.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	old, ok, err := store.Load(ctx, "task")
	if err != nil || !ok || old.Revision != 1 {
		t.Fatalf("legacy revision not recovered: %+v %v %v", old, ok, err)
	}
	newRecord := agent.Record{Revision: 2, Digest: strings.Repeat("b", 64), OperationID: "op-new"}
	if err := store.Save(ctx, "task", newRecord); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "revisions", "task.json")); err != nil {
		t.Fatalf("per-resource revision missing: %v", err)
	}
	store, err = journal.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	got, ok, err := store.Load(ctx, "task")
	if err != nil || !ok || got != newRecord {
		t.Fatalf("migration lost latest revision: %+v %v %v", got, ok, err)
	}
}
