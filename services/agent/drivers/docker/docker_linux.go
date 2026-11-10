// Package docker manages Arc-owned containers through the local Docker Engine.
package docker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/security"
)

type Driver struct {
	client *http.Client
	dir    string
	node   string
	mu     sync.Mutex
}

var _ agent.Driver = (*Driver)(nil)
var _ agent.Inspector = (*Driver)(nil)

// Open must be called while holding the exclusive Agent journal lock.
func Open(stateDir, node string) (*Driver, error) {
	if !filepath.IsAbs(stateDir) || !agent.ValidID(node) {
		return nil, agent.ErrInvalid
	}
	dir := filepath.Join(stateDir, "docker-"+node)
	if err := privateDirectory(dir); err != nil {
		return nil, err
	}
	return &Driver{dir: dir, node: node, client: localEngine(engineSocket)}, nil
}

func (d *Driver) Close() { d.client.CloseIdleConnections() }

type hostConfig struct {
	ReadonlyRootfs  bool
	Privileged      bool
	NetworkMode     string
	PidMode         string
	IpcMode         string
	UTSMode         string
	CgroupnsMode    string
	CapAdd          []string
	CapDrop         []string
	SecurityOpt     []string
	Binds           []string
	Mounts          []any
	Devices         []any
	DeviceRequests  []any
	PortBindings    map[string]any
	PublishAllPorts bool
	Memory          int64
	MemorySwap      int64
	NanoCpus        int64
	PidsLimit       int64
	RestartPolicy   struct{ Name string }
	LogConfig       struct {
		Type   string
		Config map[string]string
	}
}

const workloadUser = "65532:65532"
const memoryLimit = 256 << 20
const cpuLimit = 1_000_000_000
const pidsLimit = 128

func restrictedHost() hostConfig {
	return hostConfig{
		ReadonlyRootfs: true, NetworkMode: "none", IpcMode: "private", CgroupnsMode: "private",
		CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges"},
		Memory: memoryLimit, MemorySwap: memoryLimit, NanoCpus: cpuLimit, PidsLimit: pidsLimit,
		RestartPolicy: struct{ Name string }{Name: "no"},
		LogConfig: struct {
			Type   string
			Config map[string]string
		}{Type: "local", Config: map[string]string{"max-size": "1m", "max-file": "3"}},
	}
}

type container struct {
	ID         string `json:"Id"`
	Name       string
	Image      string
	HostConfig hostConfig
	Mounts     []any
	Config     struct{ Image, User string }
	State      *struct {
		Running, Paused, Restarting bool
	}
}

func (c container) allowed() bool {
	h := c.HostConfig
	return c.Config.User == workloadUser && h.ReadonlyRootfs && !h.Privileged && h.NetworkMode == "none" &&
		h.PidMode == "" && h.IpcMode == "private" && h.UTSMode == "" && h.CgroupnsMode == "private" && !h.PublishAllPorts &&
		len(h.Binds)+len(h.Mounts)+len(h.Devices)+len(h.DeviceRequests)+len(h.PortBindings)+len(c.Mounts)+len(h.CapAdd) == 0 &&
		len(h.CapDrop) == 1 && h.CapDrop[0] == "ALL" && len(h.SecurityOpt) == 1 && h.SecurityOpt[0] == "no-new-privileges" &&
		h.Memory == memoryLimit && h.MemorySwap == memoryLimit && h.NanoCpus == cpuLimit && h.PidsLimit == pidsLimit &&
		h.RestartPolicy.Name == "no" && h.LogConfig.Type == "local" && h.LogConfig.Config["max-size"] == "1m" && h.LogConfig.Config["max-file"] == "3"
}

func (d *Driver) inspect(ctx context.Context, record ownership) (container, error) {
	lookup := record.ID
	if lookup == "" {
		lookup = record.Name
	}
	var current container
	err := d.call(ctx, http.MethodGet, "/containers/"+lookup+"/json", nil, &current)
	if err != nil {
		return container{}, err
	}
	if !containerID.MatchString(current.ID) || current.Name != "/"+record.Name || current.Image != record.Image || current.State == nil ||
		(record.ID != "" && current.ID != record.ID) {
		return container{}, security.ErrDenied
	}
	return current, nil
}

func (d *Driver) approvedImage(ctx context.Context, target string) (string, error) {
	for _, part := range strings.Split(target, "/") {
		if part == "." || part == ".." || part == "" {
			return "", security.ErrDenied
		}
	}
	var engine struct {
		OSType          string
		MemoryLimit     bool
		SwapLimit       bool
		CPUCfsPeriod    bool
		CPUCfsQuota     bool
		PidsLimit       bool
		SecurityOptions []string
	}
	if err := d.call(ctx, http.MethodGet, "/info", nil, &engine); err != nil {
		return "", security.ErrUnavailable
	}
	seccomp := slices.Contains(engine.SecurityOptions, "name=seccomp,profile=builtin")
	if engine.OSType != "linux" || !engine.MemoryLimit || !engine.SwapLimit || !engine.CPUCfsPeriod || !engine.CPUCfsQuota || !engine.PidsLimit || !seccomp {
		return "", security.ErrDenied
	}
	var image struct {
		ID     string `json:"Id"`
		Config *struct{ Volumes map[string]any }
	}
	err := d.call(ctx, http.MethodGet, "/images/"+target+"/json", nil, &image)
	if err != nil {
		return "", security.ErrUnavailable
	}
	if !imageID.MatchString(image.ID) || image.Config == nil || len(image.Config.Volumes) != 0 {
		return "", security.ErrDenied
	}
	return image.ID, nil
}

func (d *Driver) create(ctx context.Context, resource string, records []ownership, slot int, target string) (container, error) {
	if err := d.save(ctx, resource, records); err != nil {
		return container{}, err
	}
	record := records[slot]
	input := struct {
		Image      string
		User       string
		HostConfig hostConfig
	}{target, workloadUser, restrictedHost()}
	var created struct{ ID string }
	if err := d.call(ctx, http.MethodPost, "/containers/create?name="+record.Name, input, &created); err != nil {
		return container{}, security.ErrUnavailable
	}
	if !containerID.MatchString(created.ID) {
		return container{}, security.ErrUnavailable
	}
	record.ID = created.ID
	records[slot] = record
	if err := d.save(ctx, resource, records); err != nil {
		return container{}, err
	}
	return d.inspect(ctx, record)
}

func (d *Driver) stop(ctx context.Context, current container) error {
	if !current.State.Running {
		return nil
	}
	return d.call(ctx, http.MethodPost, "/containers/"+current.ID+"/stop?t=3", nil, nil)
}

func (d *Driver) remove(ctx context.Context, current container) error {
	if err := d.stop(ctx, current); err != nil {
		return err
	}
	err := d.call(ctx, http.MethodDelete, "/containers/"+current.ID+"?v=false", nil, nil)
	if errors.Is(err, errMissing) {
		return nil
	}
	return err
}

func (d *Driver) validate(spec agent.Spec, template agent.Template) error {
	if spec.Kind != agent.Docker || spec.Validate(template, d.node) != nil {
		return security.ErrDenied
	}
	return nil
}

func (d *Driver) Apply(ctx context.Context, spec agent.Spec, template agent.Template) (agent.Observation, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.validate(spec, template); err != nil {
		return agent.Observation{}, err
	}
	records, err := d.load(spec.ID)
	if err != nil {
		return agent.Observation{}, err
	}
	var image string
	if spec.State == agent.Running {
		image, err = d.approvedImage(ctx, template.Target)
		if err != nil {
			return agent.Observation{}, err
		}
	}
	for slot := len(records) - 1; slot >= 0; slot-- {
		record := records[slot]
		current, err := d.inspect(ctx, record)
		missing := errors.Is(err, errMissing)
		if err != nil && !missing {
			return agent.Observation{}, err
		}
		keep := spec.State == agent.Stopped || (spec.State == agent.Running && slot < spec.Replicas && record.Image == image && (missing || current.Config.Image == template.Target))
		if keep && !missing {
			if spec.State == agent.Stopped {
				if err := d.stop(ctx, current); err != nil {
					return agent.Observation{}, security.ErrUnavailable
				}
			}
			continue
		}
		if keep && record.ID == "" && spec.State == agent.Running {
			continue
		}
		if !missing {
			if err := d.remove(ctx, current); err != nil {
				return agent.Observation{}, security.ErrUnavailable
			}
		}
		records = append(records[:slot], records[slot+1:]...)
		if err := d.save(ctx, spec.ID, records); err != nil {
			return agent.Observation{}, err
		}
	}
	for len(records) < spec.Replicas {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return agent.Observation{}, security.ErrUnavailable
		}
		records = append(records, ownership{Name: "arc-managed-" + hex.EncodeToString(random[:]), Image: image})
	}
	for slot := 0; slot < spec.Replicas; slot++ {
		current, err := d.inspect(ctx, records[slot])
		if errors.Is(err, errMissing) && records[slot].ID == "" {
			current, err = d.create(ctx, spec.ID, records, slot, template.Target)
		}
		if err != nil {
			if errors.Is(err, errMissing) {
				err = security.ErrUnavailable
			}
			return agent.Observation{}, err
		}
		if !current.allowed() || current.Config.Image != template.Target || current.State.Paused || current.State.Restarting {
			return agent.Observation{}, security.ErrDenied
		}
		if records[slot].ID == "" {
			records[slot].ID = current.ID
			if err := d.save(ctx, spec.ID, records); err != nil {
				return agent.Observation{}, err
			}
		}
		if !current.State.Running {
			if err := d.call(ctx, http.MethodPost, "/containers/"+current.ID+"/start", nil, nil); err != nil {
				return agent.Observation{}, security.ErrUnavailable
			}
		}
	}
	observation, err := d.observe(ctx, spec, template, records)
	if err == nil && observation.Running != spec.Replicas {
		err = security.ErrUnavailable
	}
	return observation, err
}

func (d *Driver) Inspect(ctx context.Context, spec agent.Spec, template agent.Template) (agent.Observation, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.validate(spec, template); err != nil {
		return agent.Observation{}, err
	}
	records, err := d.load(spec.ID)
	if err != nil {
		return agent.Observation{}, err
	}
	return d.observe(ctx, spec, template, records)
}

func (d *Driver) observe(ctx context.Context, spec agent.Spec, template agent.Template, records []ownership) (agent.Observation, error) {
	out := agent.Observation{ResourceID: spec.ID, NodeID: spec.NodeID, Revision: spec.Revision, State: spec.State}
	for _, record := range records {
		current, err := d.inspect(ctx, record)
		if errors.Is(err, errMissing) {
			continue
		}
		if err != nil {
			return agent.Observation{}, err
		}
		if spec.State == agent.Running && (!current.allowed() || current.State.Paused || current.State.Restarting) {
			return agent.Observation{}, security.ErrDenied
		}
		if current.State.Running && (spec.State != agent.Running || current.Config.Image == template.Target) {
			out.Running++
		}
	}
	return out, nil
}
