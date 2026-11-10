package systemd

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/pavlith/arc/sdk/agent"
)

func TestApprovedNamespaceAndDependencyGuards(t *testing.T) {
	template := agent.Template{ID: "worker", Revision: 1, Kind: agent.Systemd, Target: "arc-managed-worker.service", MaxReplicas: 1}
	spec := agent.Spec{ID: "worker", NodeID: "node-one", Kind: agent.Systemd, TemplateID: "worker", TemplateRevision: 1, TemplateDigest: agent.TemplateDigest(template), Revision: 1, State: agent.Running, Replicas: 1}
	active := false
	effects := 0
	metadata := func() string {
		state := "inactive"
		if active {
			state = "active"
		}
		values := map[string]string{"Id": template.Target, "LoadState": "loaded", "ActiveState": state, "FragmentPath": "/etc/systemd/system/" + template.Target}
		var output strings.Builder
		for _, key := range strings.Split(properties, ",") {
			output.WriteString(key + "=" + values[key] + "\n")
		}
		return output.String()
	}
	raw := ""
	d := &Driver{checkFile: func(string) error { return nil }, run: func(_ context.Context, args ...string) ([]byte, error) {
		if args[len(args)-1] != template.Target {
			t.Fatal("unapproved unit argument")
		}
		switch args[0] {
		case "show":
			if raw != "" {
				return []byte(raw), nil
			}
			return []byte(metadata()), nil
		case "start":
			effects++
			active = true
		case "stop":
			effects++
			active = false
		default:
			t.Fatal("arbitrary systemctl command")
		}
		return nil, nil
	}}
	if _, err := d.Apply(context.Background(), spec, template); err != nil || effects != 1 {
		t.Fatalf("start: %d %v", effects, err)
	}
	if _, err := d.Apply(context.Background(), spec, template); err != nil || effects != 1 {
		t.Fatal("duplicate start")
	}
	for _, extra := range []string{"RequiredBy=arc-core.service\n", "PropagatesStopTo=ssh.service\n", "Wants=arc-core.service\n", "DropInPaths=/etc/systemd/system/evil.conf\n"} {
		property, _, _ := strings.Cut(extra, "=")
		raw = strings.Replace(metadata(), property+"=\n", extra, 1)
		if _, err := d.Apply(context.Background(), spec, template); !errors.Is(err, ErrPolicy) || effects != 1 {
			t.Fatalf("dependency/drop-in accepted: %v", err)
		}
	}
	raw = strings.Replace(metadata(), "Id=arc-managed-worker.service", "Id=arc-core.service", 1)
	if _, err := d.Apply(context.Background(), spec, template); !errors.Is(err, ErrPolicy) {
		t.Fatal("bootstrap alias accepted")
	}
	raw = ""
	spec.State = agent.Deleted
	spec.Replicas = 0
	if _, err := d.Apply(context.Background(), spec, template); err != nil || effects != 2 || active {
		t.Fatalf("delete did not retain unit and stop: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.Apply(ctx, spec, template); !errors.Is(err, context.Canceled) || effects != 2 {
		t.Fatal("cancelled command executed")
	}
}
func TestSystemdMissingUnitReadOnly(t *testing.T) {
	if os.Getenv("ARC_AGENT_SYSTEMD_SMOKE") != "1" {
		t.Skip("set ARC_AGENT_SYSTEMD_SMOKE=1 for read-only host validation")
	}
	template := agent.Template{ID: "arc-smoke-nonexistent", Revision: 1, Kind: agent.Systemd, Target: "arc-managed-arc-smoke-nonexistent.service", MaxReplicas: 1}
	spec := agent.Spec{ID: template.ID, NodeID: "node-one", Kind: agent.Systemd, TemplateID: template.ID, TemplateRevision: 1, TemplateDigest: agent.TemplateDigest(template), Revision: 1, State: agent.Running, Replicas: 1}
	// The missing fragment and LoadState deny effects before any start/stop call.
	if _, err := New().Inspect(context.Background(), spec, template); !errors.Is(err, ErrPolicy) {
		t.Fatalf("missing unit accepted or host systemd unavailable: %v", err)
	}
}
