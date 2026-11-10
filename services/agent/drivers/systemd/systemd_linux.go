// Package systemd manages operator-installed units in a fixed Arc namespace.
// It never installs units, enables them at boot, purges data or invokes a shell.
package systemd

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/security"
)

var ErrPolicy = security.ErrDenied
var ErrDriver = errors.New("systemd: operation failed")

type Driver struct {
	run       func(context.Context, ...string) ([]byte, error)
	checkFile func(string) error
}

func New() *Driver { return &Driver{run: run, checkFile: checkFile} }
func run(ctx context.Context, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", args...)
	// No inherited environment, pager, credential-bearing output or error text.
	command.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "SYSTEMD_PAGER="}
	var output boundedOutput
	command.Stdout = &output
	if command.Run() != nil {
		return nil, ErrDriver
	}
	return output.raw, nil
}

type boundedOutput struct{ raw []byte }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(b.raw)+len(p) > 65536 {
		return 0, ErrDriver
	}
	b.raw = append(b.raw, p...)
	return len(p), nil
}
func checkFile(path string) error {
	for _, entry := range []string{"/etc", "/etc/systemd", "/etc/systemd/system", path} {
		info, err := os.Lstat(entry)
		if err != nil {
			return ErrPolicy
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Mode()&os.ModeSymlink != 0 {
			return ErrPolicy
		}
		if entry == path && !info.Mode().IsRegular() {
			return ErrPolicy
		}
	}
	return nil
}

const properties = "Id,LoadState,ActiveState,FragmentPath,DropInPaths,Requires,Wants,Requisite,BindsTo,PartOf,Upholds,Conflicts,RequiredBy,RequisiteOf,BoundBy,ConsistsOf,PropagatesStopTo"

func (d *Driver) inspect(ctx context.Context, s agent.Spec, t agent.Template) (agent.Observation, error) {
	out := agent.Observation{ResourceID: s.ID, NodeID: s.NodeID, Revision: s.Revision, State: s.State}
	if s.Validate(t, s.NodeID) != nil || s.Kind != agent.Systemd || t.Target != "arc-managed-"+s.ID+".service" {
		return out, ErrPolicy
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	raw, err := d.run(ctx, "show", "--no-pager", "--no-ask-password", "--property="+properties, "--", t.Target)
	if err != nil {
		return out, ErrDriver
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return out, ErrDriver
		}
		if _, duplicate := fields[key]; duplicate {
			return out, ErrDriver
		}
		fields[key] = value
	}
	for _, property := range strings.Split(properties, ",") {
		if _, ok := fields[property]; !ok {
			return out, ErrPolicy
		}
	}
	path := "/etc/systemd/system/" + t.Target
	if fields["Id"] != t.Target || fields["LoadState"] != "loaded" || fields["FragmentPath"] != path || fields["DropInPaths"] != "" {
		return out, ErrPolicy
	}
	if err := d.checkFile(path); err != nil {
		return out, ErrPolicy
	}
	for _, key := range strings.Split("RequiredBy,RequisiteOf,BoundBy,ConsistsOf,PropagatesStopTo", ",") {
		if fields[key] != "" {
			return out, ErrPolicy
		}
	}
	for _, key := range strings.Split("Requires,Wants,Requisite,BindsTo,PartOf,Upholds,Conflicts", ",") {
		for _, dependency := range strings.Fields(fields[key]) {
			switch dependency {
			case "basic.target", "sysinit.target", "shutdown.target", "local-fs.target", "system.slice", "-.mount", "systemd-journald.socket":
			default:
				return out, ErrPolicy
			}
		}
	}
	switch fields["ActiveState"] {
	case "active":
		out.Running = 1
	case "inactive", "failed":
	case "activating", "deactivating", "reloading":
		return out, ErrDriver
	default:
		return out, ErrDriver
	}
	return out, nil
}
func (d *Driver) Inspect(ctx context.Context, s agent.Spec, t agent.Template) (agent.Observation, error) {
	return d.inspect(ctx, s, t)
}
func (d *Driver) Apply(ctx context.Context, s agent.Spec, t agent.Template) (agent.Observation, error) {
	observed, err := d.inspect(ctx, s, t)
	if err != nil {
		return observed, err
	}
	if observed.Running == s.Replicas {
		return observed, nil
	}
	if err := ctx.Err(); err != nil {
		return observed, err
	}
	action := "stop"
	if s.State == agent.Running {
		action = "start"
	}
	if _, err := d.run(ctx, action, "--no-pager", "--no-ask-password", "--", t.Target); err != nil {
		return observed, ErrDriver
	}
	observed, err = d.inspect(ctx, s, t)
	if err != nil || observed.Running != s.Replicas {
		return observed, ErrDriver
	}
	return observed, nil
}
