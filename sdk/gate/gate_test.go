package gate

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/fabric"
	"github.com/pavlith/arc/sdk/identity"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
)

// closedBackend is an unavailable boundary, never a permissive auth substitute.
type closedBackend struct{}

func (closedBackend) Fetch(context.Context) (fabric.SignedSnapshot, security.JWKS, error) {
	return fabric.SignedSnapshot{}, security.JWKS{}, security.ErrUnavailable
}
func (closedBackend) Login(context.Context, identity.LoginRequest) (identity.LoginResult, error) {
	return identity.LoginResult{}, security.ErrUnavailable
}
func (closedBackend) Authenticate(context.Context, identity.Authentication) (identity.Session, error) {
	return identity.Session{}, security.ErrUnavailable
}
func (closedBackend) Refresh(context.Context, identity.RefreshRequest) (identity.LoginResult, error) {
	return identity.LoginResult{}, security.ErrUnavailable
}
func (closedBackend) Logout(context.Context, identity.SessionRequest) error {
	return security.ErrUnavailable
}
func (closedBackend) Exchange(context.Context, identity.UserExchange) (identity.TokenResult, error) {
	return identity.TokenResult{}, security.ErrUnavailable
}
func (closedBackend) Invoke(context.Context, *contract.Compiled, contract.Operation, json.RawMessage, string, string) (json.RawMessage, error) {
	return nil, security.ErrUnavailable
}
func fixtureSnapshot(t *testing.T, rev int64) (fabric.RouteSnapshot, ed25519.PrivateKey, security.JWKS) {
	t.Helper()
	a := gateArtifact()
	m, e := contract.Compile(a)
	if e != nil {
		t.Fatal(e)
	}
	key := testKey(129)
	now := time.Now()
	keys := security.PublicJWKS([]security.Key{{Kid: "snapshot-test", Public: key.Public().(ed25519.PublicKey), NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}}, now)
	snap := fabric.RouteSnapshot{Revision: rev, IssuedAt: now, Artifacts: map[string]contract.Artifact{m.Digest: a}}
	for _, o := range m.Manifest.Operations {
		snap.Routes = append(snap.Routes, fabric.Route{Method: o.HTTP.Method, Path: o.HTTP.Path, Service: m.Manifest.Service.Name, Operation: o.ID, Subject: o.Subject, Digest: m.Digest, SuccessStatus: o.HTTP.SuccessStatus, APIMajor: m.Manifest.Service.APIMajor, Bindings: o.HTTP.Bindings})
	}
	return snap, key, keys
}
func TestSnapshotValidationAndAtomicReplace(t *testing.T) {
	snap, key, keys := fixtureSnapshot(t, 2)
	signed, e := fabric.SignSnapshot(snap, "snapshot-test", key)
	if e != nil {
		t.Fatal(e)
	}
	var routes routes
	if e = routes.apply(signed, keys); e != nil {
		t.Fatal(e)
	}
	old := routes.current.Load()
	for _, name := range []string{"signature", "unknown_key", "rollback", "same_revision_conflict", "route_subject", "collision", "reserved", "unbound"} {
		t.Run(name, func(t *testing.T) {
			var q fabric.RouteSnapshot
			raw, _ := json.Marshal(snap)
			_ = json.Unmarshal(raw, &q)
			k := keys
			switch name {
			case "rollback":
				q.Revision = 1
			case "same_revision_conflict":
				q.Routes = q.Routes[:1]
			case "route_subject":
				q.Revision = 3
				q.Routes[0].Subject = "rpc.evil.v1.read"
			case "collision":
				q.Revision = 3
				q.Routes = append(q.Routes, q.Routes[0])
			case "reserved":
				q.Revision = 3
				q.Routes[0].Path = "/api/v1/arc/login"
			case "unbound":
				q.Revision = 3
				q.Routes[0].Bindings = nil
			case "unknown_key":
				k = security.JWKS{Keys: []security.JWK{}}
			}
			s, e := fabric.SignSnapshot(q, "snapshot-test", key)
			if e != nil {
				t.Fatal(e)
			}
			if name == "signature" {
				s.Signature[0] ^= 1
			}
			if e = routes.apply(s, k); e == nil {
				t.Fatal("invalid snapshot accepted")
			}
			if routes.current.Load() != old {
				t.Fatal("invalid snapshot replaced active table")
			}
		})
	}
	// Readers always see a single immutable table while newer revisions race.
	var wg sync.WaitGroup
	var bad atomic.Bool
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 300 {
				table := routes.current.Load()
				en, _, ok := table.match("GET", "/api/v1/tasks/read/resource-id")
				if !ok || en.route.Digest != en.compiled.Digest || en.op.Subject != en.route.Subject {
					bad.Store(true)
				}
			}
		}()
	}
	for i := 3; i < 35; i++ {
		wg.Add(1)
		go func(rev int64) {
			defer wg.Done()
			q := snap
			q.Revision = rev
			s, e := fabric.SignSnapshot(q, "snapshot-test", key)
			if e == nil {
				_ = routes.apply(s, keys)
			}
		}(int64(i))
	}
	wg.Wait()
	if bad.Load() || routes.current.Load().revision != 34 {
		t.Fatal("inconsistent concurrent snapshot table", bad.Load(), routes.current.Load().revision)
	}
}
func TestReservedAndCollidingHTTPPaths(t *testing.T) {
	for _, p := range []string{"/healthz", "/health/ready", "/dav/files", "/api/v1/arc/auth/login", "/api/v1/tasks/*", "/api/v1/tasks/{x}/../arc", "/api/v1/tasks/%2f"} {
		if contract.ValidateHTTP(contract.HTTP{Expose: true, Path: p}) == nil {
			t.Fatal("reserved/unsafe HTTP path", p)
		}
	}
	if !contract.RoutesOverlap(contract.HTTP{Method: "GET", Path: "/api/v1/tasks/{id}"}, contract.HTTP{Method: "GET", Path: "/api/v1/tasks/static"}) {
		t.Fatal("static/parameter collision missed")
	}
}
func TestSafeErrorsProxyAndRateLimits(t *testing.T) {
	for code, status := range map[rpc.Code]int{rpc.CodeUnauthenticated: 401, rpc.CodePermissionDenied: 403, rpc.CodeNotFound: 404, rpc.CodeValidation: 400, rpc.CodeConflict: 409, rpc.CodeRateLimited: 429, rpc.CodeUnavailable: 503, rpc.CodeDeadlineExceeded: 504, rpc.CodeInternal: 500} {
		w := httptest.NewRecorder()
		writeError(w, "request", &rpc.Error{Code: code, Message: "postgres secret stacktrace"})
		if w.Code != status || strings.Contains(w.Body.String(), "secret") {
			t.Fatal("unsafe HTTP error mapping", code, w.Code)
		}
	}
	w := httptest.NewRecorder()
	writeError(w, "request", errors.New("password plaintext"))
	if w.Code != 500 || strings.Contains(w.Body.String(), "password") {
		t.Fatal("internal error leak")
	}
	g, e := New(Config{Backend: closedBackend{}, PublicOrigin: "https://arc.example", TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, RequestsPerMinute: 1})
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("GET", "https://arc.example/api/v1/tasks/read/r", nil)
	r.RemoteAddr = "192.0.2.4:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.2")
	client, secure, e := g.peer(r)
	if e != nil || client != "192.0.2.4" || !secure {
		t.Fatal("untrusted forwarded IP used")
	}
	r.RemoteAddr = "10.0.0.5:1234"
	r.TLS = nil
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-For", "203.0.113.2, 10.0.0.6")
	client, secure, e = g.peer(r)
	if e != nil || client != "203.0.113.2" || !secure {
		t.Fatal("trusted proxy chain ignored")
	}
	r.TLS = &tls.ConnectionState{}
	r.RemoteAddr = "192.0.2.4:1234"
	w = httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatal("cold start must be closed", w.Code)
	}
	w = httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 429 {
		t.Fatal("rate limit missing", w.Code)
	}
	r = httptest.NewRequest("POST", "https://arc.example/api/v1/arc/auth/login", strings.NewReader(`{"email":"x","password":"x"}`))
	r.RemoteAddr = "192.0.2.5:1234"
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("login without Origin accepted", w.Code)
	}
}
