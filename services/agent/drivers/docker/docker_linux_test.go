package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/security"
)

var fakeImageID = "sha256:" + strings.Repeat("a", 64)

type fakeEngine struct {
	mu                  sync.Mutex
	containers          map[string]*container
	creates, starts     int
	lostResponse        bool
	imageDeclaresVolume bool
	unsafeLimits        bool
}

func (f *fakeEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path, supported := strings.CutPrefix(r.URL.Path, apiVersion)
	if !supported {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch {
	case r.Method == http.MethodGet && path == "/info":
		write(map[string]any{"OSType": "linux", "MemoryLimit": !f.unsafeLimits, "SwapLimit": true,
			"CPUCfsPeriod": true, "CPUCfsQuota": true, "PidsLimit": true, "SecurityOptions": []string{"name=seccomp,profile=builtin"}})
		return
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/images/"):
		volumes := map[string]any{}
		if f.imageDeclaresVolume {
			volumes["/data"] = struct{}{}
		}
		write(map[string]any{"Id": fakeImageID, "Config": map[string]any{"Volumes": volumes}})
		return
	case r.Method == http.MethodPost && path == "/containers/create":
		name := r.URL.Query().Get("name")
		var c container
		var input struct {
			User, Image string
			HostConfig  hostConfig
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || !containerName.MatchString(name) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		c.Name, c.Image, c.HostConfig = "/"+name, fakeImageID, input.HostConfig
		c.Config.Image, c.Config.User = input.Image, input.User
		c.State = &struct{ Running, Paused, Restarting bool }{}
		if !c.allowed() {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		f.creates++
		c.ID = fmt.Sprintf("%064x", f.creates)
		f.containers[c.ID] = &c
		if f.lostResponse {
			f.lostResponse = false
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		write(map[string]string{"Id": c.ID})
		return
	}
	path, found := strings.CutPrefix(path, "/containers/")
	if !found {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	key, action, _ := strings.Cut(path, "/")
	c := f.containers[key]
	for _, candidate := range f.containers {
		if candidate.Name == "/"+key {
			c = candidate
			break
		}
	}
	if c == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	switch {
	case r.Method == http.MethodGet && action == "json":
		write(c)
	case r.Method == http.MethodPost && action == "start" && key == c.ID:
		f.starts++
		c.State.Running = true
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && action == "stop" && key == c.ID:
		c.State.Running = false
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodDelete && action == "" && key == c.ID && !c.State.Running && r.URL.Query().Get("v") == "false":
		delete(f.containers, c.ID)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func dockerFixture(t *testing.T, engine *fakeEngine) (func() *Driver, agent.Template, agent.Spec) {
	t.Helper()
	dir, err := os.MkdirTemp("", "arc-docker-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "engine.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: engine}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(listener) }()
	open := func() *Driver {
		driver, err := Open(dir, "node-one")
		if err != nil {
			t.Fatal(err)
		}
		driver.client = localEngine(socket)
		t.Cleanup(driver.Close)
		return driver
	}
	template := agent.Template{ID: "worker", Revision: 1, Kind: agent.Docker, Target: "registry.example/worker@sha256:" + strings.Repeat("b", 64), MaxReplicas: 2}
	spec := agent.Spec{ID: "worker", NodeID: "node-one", Kind: agent.Docker, TemplateID: template.ID,
		TemplateRevision: template.Revision, TemplateDigest: agent.TemplateDigest(template), Revision: 1, State: agent.Running, Replicas: 2}
	return open, template, spec
}

func TestDockerRecoversCreateAndManagesReplicas(t *testing.T) {
	engine := &fakeEngine{containers: map[string]*container{}, lostResponse: true}
	open, template, spec := dockerFixture(t, engine)
	ctx := context.Background()
	first := open()
	if _, err := first.Apply(ctx, spec, template); !errors.Is(err, security.ErrUnavailable) {
		t.Fatalf("lost create response: %v", err)
	}
	first.Close()
	driver := open()
	if got, err := driver.Apply(ctx, spec, template); err != nil || got.Running != 2 {
		t.Fatalf("recovery: %+v, %v", got, err)
	}
	engine.mu.Lock()
	creates, starts := engine.creates, engine.starts
	for _, c := range engine.containers {
		c.State.Running = false
		break
	}
	engine.mu.Unlock()
	if creates != 2 || starts != 2 {
		t.Fatalf("recovery created %d and started %d containers", creates, starts)
	}
	if got, err := driver.Inspect(ctx, spec, template); err != nil || got.Running != 1 {
		t.Fatalf("drift observation: %+v, %v", got, err)
	}
	template.Target = "registry.example/worker@sha256:" + strings.Repeat("c", 64)
	template.Revision++
	spec.Revision, spec.TemplateRevision = 2, template.Revision
	spec.TemplateDigest, spec.Replicas = agent.TemplateDigest(template), 1
	if got, err := driver.Apply(ctx, spec, template); err != nil || got.Running != 1 {
		t.Fatalf("update and scale down: %+v, %v", got, err)
	}
	engine.mu.Lock()
	creates, remaining := engine.creates, len(engine.containers)
	engine.mu.Unlock()
	if creates != 3 || remaining != 1 {
		t.Fatalf("update created %d total and left %d containers", creates, remaining)
	}
	spec.State, spec.Replicas = agent.Stopped, 0
	if got, err := driver.Apply(ctx, spec, template); err != nil || got.Running != 0 {
		t.Fatalf("stop: %+v, %v", got, err)
	}
	spec.State = agent.Deleted
	if got, err := driver.Apply(ctx, spec, template); err != nil || got.Running != 0 {
		t.Fatalf("delete: %+v, %v", got, err)
	}
	engine.mu.Lock()
	remaining = len(engine.containers)
	engine.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("delete left %d containers", remaining)
	}
}

func TestDockerRejectsMissingIsolationAndForeignContainer(t *testing.T) {
	engine := &fakeEngine{containers: map[string]*container{}, unsafeLimits: true}
	open, template, spec := dockerFixture(t, engine)
	driver := open()
	ctx := context.Background()
	if _, err := driver.Apply(ctx, spec, template); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("missing memory limits: %v", err)
	}
	engine.mu.Lock()
	engine.unsafeLimits = false
	engine.imageDeclaresVolume = true
	engine.mu.Unlock()
	if _, err := driver.Apply(ctx, spec, template); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("implicit image volume: %v", err)
	}
	engine.mu.Lock()
	engine.imageDeclaresVolume = false
	priorCreates := engine.creates
	engine.mu.Unlock()
	if priorCreates != 0 {
		t.Fatal("policy denied workloads after creation")
	}
	spec.Replicas = 1
	if _, err := driver.Apply(ctx, spec, template); err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	for _, c := range engine.containers {
		c.Name = "/different-owner"
	}
	engine.mu.Unlock()
	spec.State, spec.Replicas = agent.Deleted, 0
	if _, err := driver.Apply(ctx, spec, template); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("different owner: %v", err)
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	for _, c := range engine.containers {
		if !c.State.Running {
			t.Fatal("foreign container was stopped")
		}
	}
}

func TestDockerEngineLifecycle(t *testing.T) {
	target := os.Getenv("ARC_AGENT_DOCKER_TEST_IMAGE")
	if target == "" {
		t.Skip("set ARC_AGENT_DOCKER_TEST_IMAGE to an approved local image digest on a test node")
	}
	template := agent.Template{ID: "docker-smoke", Revision: 1, Kind: agent.Docker, Target: target, MaxReplicas: 1}
	if err := template.Validate(); err != nil {
		t.Fatal(err)
	}
	driver, err := Open(t.TempDir(), "node-smoke")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(driver.Close)
	spec := agent.Spec{ID: template.ID, NodeID: "node-smoke", Kind: template.Kind, TemplateID: template.ID,
		TemplateRevision: template.Revision, TemplateDigest: agent.TemplateDigest(template), Revision: 1, State: agent.Running, Replicas: 1}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		spec.Revision, spec.State, spec.Replicas = 3, agent.Deleted, 0
		if _, err := driver.Apply(ctx, spec, template); err != nil {
			t.Errorf("remove smoke container: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	if got, err := driver.Apply(ctx, spec, template); err != nil || got.Running != 1 {
		t.Fatalf("start: %+v, %v", got, err)
	}
	if got, err := driver.Inspect(ctx, spec, template); err != nil || got.Running != 1 {
		t.Fatalf("inspect: %+v, %v", got, err)
	}
	spec.Revision, spec.State, spec.Replicas = 2, agent.Stopped, 0
	if got, err := driver.Apply(ctx, spec, template); err != nil || got.Running != 0 {
		t.Fatalf("stop: %+v, %v", got, err)
	}
}
