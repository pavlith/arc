package journal_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/services/agent/journal"
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
