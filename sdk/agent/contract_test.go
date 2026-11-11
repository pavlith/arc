package agent_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/security"
)

type journal map[string]agent.Record

func (j journal) Load(_ context.Context, id string) (agent.Record, bool, error) {
	r, ok := j[id]
	return r, ok, nil
}
func (j journal) Save(_ context.Context, id string, r agent.Record) error { j[id] = r; return nil }

type fake struct {
	calls int
	fail  bool
}

func (f *fake) Apply(_ context.Context, s agent.Spec, _ agent.Template) (agent.Observation, error) {
	f.calls++
	if f.fail {
		return agent.Observation{}, errors.New("host unavailable")
	}
	return agent.Observation{ResourceID: s.ID, NodeID: s.NodeID, Revision: s.Revision, State: s.State, Running: s.Replicas}, nil
}
func (f *fake) Inspect(_ context.Context, s agent.Spec, _ agent.Template) (agent.Observation, error) {
	return agent.Observation{ResourceID: s.ID, NodeID: s.NodeID, Revision: s.Revision, State: s.State, Running: s.Replicas}, nil
}

func fixture(t *testing.T) (agent.Snapshot, agent.Template, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := agent.Template{ID: "task", Revision: 1, Kind: agent.Docker, Target: "registry/arc/task@sha256:" + strings.Repeat("a", 64), MaxReplicas: 3}
	s := agent.Snapshot{Version: 1, RequestID: "fresh-request-123456", OperationID: "op-one", IssuedAt: 1000, ExpiresAt: 1030, Spec: agent.Spec{ID: "task-prod", NodeID: "node-one", Kind: agent.Docker, TemplateID: "task", TemplateRevision: 1, TemplateDigest: agent.TemplateDigest(template), Revision: 1, State: agent.Running, Replicas: 1}}
	return s, template, pub, key
}
func encoded(t *testing.T, s agent.Snapshot, key ed25519.PrivateKey) []byte {
	t.Helper()
	signed, err := agent.Sign(s, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestSnapshotBoundary(t *testing.T) {
	s, template, pub, key := fixture(t)
	templates := map[string]agent.Template{template.ID: template}
	now := time.Unix(1001, 0)
	raw := encoded(t, s, key)
	if _, err := agent.Verify(raw, pub, "node-one", s.RequestID, now, templates); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*agent.Snapshot){
		"wrong node":        func(s *agent.Snapshot) { s.Spec.NodeID = "node-two" },
		"wrong request":     func(s *agent.Snapshot) { s.RequestID = "other-request-123456" },
		"expired":           func(s *agent.Snapshot) { s.ExpiresAt = 1001 },
		"future":            func(s *agent.Snapshot) { s.IssuedAt = 1002 },
		"long lease":        func(s *agent.Snapshot) { s.ExpiresAt = 1100 },
		"bootstrap":         func(s *agent.Snapshot) { s.Spec.ID = "arc-core" },
		"template":          func(s *agent.Snapshot) { s.Spec.TemplateID = "unknown" },
		"template revision": func(s *agent.Snapshot) { s.Spec.TemplateRevision = 2 },
		"template digest":   func(s *agent.Snapshot) { s.Spec.TemplateDigest = strings.Repeat("0", 64) },
		"replicas":          func(s *agent.Snapshot) { s.Spec.Replicas = 4 },
		"kind":              func(s *agent.Snapshot) { s.Spec.Kind = agent.Systemd },
		"revision":          func(s *agent.Snapshot) { s.Spec.Revision = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := s
			mutate(&bad)
			if _, err := agent.Verify(encoded(t, bad, key), pub, "node-one", s.RequestID, now, templates); err == nil {
				t.Fatal("invalid snapshot accepted")
			}
		})
	}
	// Even correctly signed unknown execution parameters are rejected.
	signed, _ := agent.Sign(s, key)
	signed.Payload = append([]byte(nil), signed.Payload...)
	signed.Payload = []byte(strings.Replace(string(signed.Payload), `"replicas":1`, `"replicas":1,"privileged":true`, 1))
	tampered, _ := json.Marshal(signed)
	if _, err := agent.Verify(tampered, pub, "node-one", s.RequestID, now, templates); err == nil {
		t.Fatal("tampered signature accepted")
	}
	// Unknown host parameters fail even when Core signed them.
	canonical, err := security.CanonicalJSON(signed.Payload)
	if err != nil {
		t.Fatal(err)
	}
	signed.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, append([]byte("arc.runtime.snapshot.v1\n"), canonical...)))
	signedUnknown, _ := json.Marshal(signed)
	if _, err := agent.Verify(signedUnknown, pub, "node-one", s.RequestID, now, templates); err == nil {
		t.Fatal("signed forbidden host parameter accepted")
	}
	// A caller cannot add forbidden fields to an otherwise valid envelope.
	raw = []byte(strings.Replace(string(raw), `"signature":`, `"shell":"id","signature":`, 1))
	if _, err := agent.Verify(raw, pub, "node-one", s.RequestID, now, templates); err == nil {
		t.Fatal("unknown envelope field accepted")
	}
}
func TestExecutorReplayRevisionAndRecovery(t *testing.T) {
	s, template, pub, key := fixture(t)
	j := journal{}
	driver := &fake{}
	e := &agent.Executor{NodeID: "node-one", CoreKey: pub, Templates: map[string]agent.Template{"task": template}, Drivers: map[agent.Kind]agent.Driver{agent.Docker: driver}, Journal: j, Now: func() time.Time { return time.Unix(1001, 0) }}
	run := func(s agent.Snapshot) error {
		_, err := e.Reconcile(context.Background(), encoded(t, s, key), s.RequestID)
		return err
	}
	if err := run(s); err != nil {
		t.Fatal(err)
	}
	s.RequestID = "fresh-request-987654"
	if err := run(s); err != nil || driver.calls != 1 {
		t.Fatalf("duplicate effect: %d %v", driver.calls, err)
	}
	conflict := s
	conflict.Spec.Replicas = 2
	if err := run(conflict); !errors.Is(err, agent.ErrStale) {
		t.Fatalf("same revision changed: %v", err)
	}
	s.Spec.Revision = 2
	s.OperationID = "op-two"
	driver.fail = true
	if err := run(s); err == nil {
		t.Fatal("driver failure lost")
	}
	if j[s.Spec.ID].Revision != 2 || j[s.Spec.ID].Complete {
		t.Fatal("intent not persisted before host effect")
	}
	old := s
	old.Spec.Revision = 1
	if err := run(old); !errors.Is(err, agent.ErrStale) {
		t.Fatalf("stale applied: %v", err)
	}
	// A reconstructed process shares durable state, but still needs a fresh pull.
	e = &agent.Executor{NodeID: e.NodeID, CoreKey: pub, Templates: e.Templates, Drivers: e.Drivers, Journal: j, Now: e.Now}
	driver.fail = false
	if err := run(s); err != nil {
		t.Fatal(err)
	}
	if !j[s.Spec.ID].Complete || driver.calls != 3 {
		t.Fatalf("recovery: %+v calls=%d", j, driver.calls)
	}
	e.Now = func() time.Time { return time.Unix(1040, 0) }
	if err := run(s); err == nil || driver.calls != 3 {
		t.Fatal("expired cached state executed")
	}
}
func TestTemplateAllowlist(t *testing.T) {
	_, valid, _, _ := fixture(t)
	for _, target := range []string{"task:latest", "unix:///var/run/docker.sock", "task@sha256:abc"} {
		bad := valid
		bad.Target = target
		if bad.Validate() == nil {
			t.Fatalf("mutable or invalid image accepted: %s", target)
		}
	}
	for _, unit := range []string{"arc-core.service", "docker.service", "ssh.service", "../task.service", "task.service;id"} {
		bad := agent.Template{ID: "unit", Revision: 1, Kind: agent.Systemd, Target: unit, MaxReplicas: 1}
		if bad.Validate() == nil {
			t.Fatalf("unsafe unit accepted: %s", unit)
		}
	}
}

func TestSnapshotBindsTemplateContents(t *testing.T) {
	s, template, pub, key := fixture(t)
	template.Target = "registry/arc/task@sha256:" + strings.Repeat("b", 64)
	if _, err := agent.Verify(encoded(t, s, key), pub, "node-one", s.RequestID, time.Unix(1001, 0), map[string]agent.Template{"task": template}); err == nil {
		t.Fatal("same template ID/revision with different image accepted")
	}
}
