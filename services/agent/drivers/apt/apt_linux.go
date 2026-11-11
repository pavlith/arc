// Package apt contains an intentionally read-only Ubuntu APT planner.
// Applying changes requires a separately approved signed host operation.
package apt

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"regexp"
	"strings"
)

var ErrInvalid = errors.New("apt: invalid package request")
var ErrUnavailable = errors.New("apt: unavailable")

var packageName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?$`)

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Plan struct {
	Requested []string `json:"requested"`
	Install   []string `json:"install"`
	Remove    []string `json:"remove"`
	// Never authorize execution based on a simulation alone: Core must approve
	// a typed operation and the Agent must revalidate the live host state.
	NeedsApproval bool `json:"needs_approval"`
}

type Runner func(context.Context, string, ...string) ([]byte, error)

type Manager struct {
	run Runner
}

func New() *Manager { return &Manager{run: run} }

type limitedOutput struct {
	bytes.Buffer
}

func (b *limitedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 2<<20 {
		return 0, ErrUnavailable
	}
	return b.Buffer.Write(p)
}

func run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	var out limitedOutput
	cmd.Stdout = &out
	// Error details may disclose local configuration; no stderr is exported.
	if cmd.Run() != nil {
		return nil, ErrUnavailable
	}
	return out.Bytes(), nil
}

func (m *Manager) execute(ctx context.Context, path string, args ...string) ([]byte, error) {
	if m == nil || m.run == nil || ctx == nil {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return m.run(ctx, path, args...)
}

// ListInstalled reads dpkg status without taking package-manager write locks.
func (m *Manager) ListInstalled(ctx context.Context) ([]Package, error) {
	raw, err := m.execute(ctx, "/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Status}\n")
	if err != nil {
		return nil, ErrUnavailable
	}
	var packages []Package
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 3 || !packageName.MatchString(fields[0]) || len(fields[1]) > 256 {
			return nil, ErrUnavailable
		}
		if fields[2] == "installed" {
			packages = append(packages, Package{Name: fields[0], Version: fields[1]})
		}
		if len(packages) > 20000 {
			return nil, ErrUnavailable
		}
	}
	return packages, nil
}

// PlanInstall invokes only apt-get simulation, never install/update/remove.
// It rejects package option injection and explicitly exposes removals.
func (m *Manager) PlanInstall(ctx context.Context, requested []string) (Plan, error) {
	var plan Plan
	if len(requested) == 0 || len(requested) > 32 {
		return plan, ErrInvalid
	}
	seen := make(map[string]bool, len(requested))
	for _, name := range requested {
		if len(name) > 128 || !packageName.MatchString(name) || seen[name] {
			return Plan{}, ErrInvalid
		}
		seen[name] = true
		plan.Requested = append(plan.Requested, name)
	}
	args := []string{"-s", "-o", "Debug::NoLocking=1", "--no-install-recommends", "install", "--"}
	args = append(args, plan.Requested...)
	raw, err := m.execute(ctx, "/usr/bin/apt-get", args...)
	if err != nil {
		return Plan{}, ErrUnavailable
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "Inst":
			if !packageName.MatchString(fields[1]) {
				return Plan{}, ErrUnavailable
			}
			plan.Install = append(plan.Install, fields[1])
		case "Remv":
			if !packageName.MatchString(fields[1]) {
				return Plan{}, ErrUnavailable
			}
			plan.Remove = append(plan.Remove, fields[1])
		}
	}
	plan.NeedsApproval = len(plan.Remove) != 0
	return plan, nil
}

// Preserve a static reference to io so output-size limits stay explicit when
// a command implementation is swapped during testing.
var _ io.Writer = (*limitedOutput)(nil)
