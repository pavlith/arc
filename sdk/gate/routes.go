package gate

import (
	"context"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/fabric"
	"github.com/pavlith/arc/sdk/security"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type entry struct {
	route    fabric.Route
	op       contract.Operation
	compiled *contract.Compiled
}
type table struct {
	revision int64
	digest   string
	entries  []entry
	kid      string
}
type routes struct {
	current atomic.Pointer[table]
	mu      sync.Mutex
}

func (r *routes) apply(s fabric.SignedSnapshot, keys security.JWKS) error {
	snap, e := fabric.VerifySnapshotJWKS(keys, s, 0)
	if e != nil {
		return e
	}
	next := &table{revision: snap.Revision, digest: snap.Digest, kid: snap.Kid}
	artifacts := map[string]*contract.Compiled{}
	for digest, a := range snap.Artifacts {
		m, e := contract.Compile(a)
		if e != nil || m.Digest != digest {
			return contract.ErrInvalid
		}
		artifacts[digest] = m
	}
	for _, route := range snap.Routes {
		m := artifacts[route.Digest]
		if m == nil {
			return contract.ErrInvalid
		}
		o, e := m.Operation(route.Operation)
		if e != nil || !o.HTTP.Expose || o.Kind == "command" && (o.HTTP.Method == "GET" || o.HTTP.Method == "HEAD") || contract.ValidateHTTP(o.HTTP) != nil || route.APIMajor != m.Manifest.Service.APIMajor || route.Service != m.Manifest.Service.Name || route.Path != o.HTTP.Path || route.Method != o.HTTP.Method || route.Subject != o.Subject || route.SuccessStatus != o.HTTP.SuccessStatus || !reflect.DeepEqual(route.Bindings, o.HTTP.Bindings) {
			return contract.ErrInvalid
		}
		for _, old := range next.entries {
			if contract.RoutesOverlap(old.op.HTTP, o.HTTP) {
				return contract.ErrInvalid
			}
		}
		// A public path parameter needs an explicit, signed payload binding.
		for _, seg := range strings.Split(route.Path, "/") {
			if strings.HasPrefix(seg, "{") {
				name := strings.TrimSuffix(strings.TrimPrefix(seg, "{"), "}")
				found := false
				for _, b := range route.Bindings {
					if b.Source == "path" && b.Name == name {
						found = true
					}
				}
				if !found {
					return contract.ErrInvalid
				}
			}
		}
		next.entries = append(next.entries, entry{route, o, m})
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	old := r.current.Load()
	if old != nil && (next.revision < old.revision || next.revision == old.revision && next.digest != old.digest) {
		return security.ErrDenied
	}
	r.current.Store(next)
	return nil
}
func (t *table) match(method, path string) (entry, map[string]string, bool) {
	if t == nil {
		return entry{}, nil, false
	}
	parts := strings.Split(path, "/")
	for _, e := range t.entries {
		if e.route.Method != method {
			continue
		}
		pattern := strings.Split(e.route.Path, "/")
		if len(pattern) != len(parts) {
			continue
		}
		params := map[string]string{}
		valid := true
		for i, p := range pattern {
			if strings.HasPrefix(p, "{") {
				if parts[i] == "" {
					valid = false
					break
				}
				params[strings.TrimSuffix(strings.TrimPrefix(p, "{"), "}")] = parts[i]
			} else if p != parts[i] {
				valid = false
				break
			}
		}
		if valid {
			return e, params, true
		}
	}
	return entry{}, nil, false
}
func (g *Gate) Reconcile(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s, keys, e := g.cfg.Backend.Fetch(ctx)
	if e != nil {
		g.available.Store(false)
		return e
	}
	e = g.routes.apply(s, keys)
	g.available.Store(e == nil)
	return e
}
func (g *Gate) Run(ctx context.Context, hints <-chan struct{}) {
	ticker := time.NewTicker(g.cfg.ReconcileInterval)
	defer ticker.Stop()
	_ = g.Reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = g.Reconcile(ctx)
		case _, ok := <-hints:
			if !ok {
				hints = nil
				continue
			}
			_ = g.Reconcile(ctx)
		}
	}
}
func (g *Gate) Revision() int64 {
	if t := g.routes.current.Load(); t != nil {
		return t.revision
	}
	return -1
}
