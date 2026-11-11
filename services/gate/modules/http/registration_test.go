package gate

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/identity"
)

type registrationBackend struct {
	closedBackend
	calls int
	err   error
}

func (b *registrationBackend) RegisterInvited(_ context.Context, q identity.RegisterInvitedRequest) (identity.RegisterInvitedResult, error) {
	b.calls++
	return identity.RegisterInvitedResult{UserID: "new-user", WorkspaceID: "workspace", RecoveryCode: "one-time-fixture"}, b.err
}

func TestInvitedRegistrationBoundary(t *testing.T) {
	const body = `{"email":"new@example.test","password":"a long password","token":"invitation"}`
	for _, name := range []string{"success", "missing_origin", "foreign_origin", "unknown_field", "missing_field", "unavailable", "denied", "get", "open_registration"} {
		t.Run(name, func(t *testing.T) {
			backend := &registrationBackend{}
			g, err := New(Config{Backend: backend, PublicOrigin: "https://arc.example"})
			if err != nil {
				t.Fatal(err)
			}
			input, origin, method, path := body, "https://arc.example", "POST", "/api/v1/arc/auth/register-invited"
			want, calls := 201, 1
			switch name {
			case "missing_origin":
				origin, want, calls = "", 403, 0
			case "foreign_origin":
				origin, want, calls = "https://other.example", 403, 0
			case "unknown_field":
				input, want, calls = strings.TrimSuffix(body, "}")+`,"role":"owner"}`, 400, 0
			case "missing_field":
				input, want, calls = `{"email":"new@example.test","password":"a long password"}`, 400, 0
			case "unavailable":
				backend.err, want = security.ErrUnavailable, 503
			case "denied":
				backend.err, want = security.ErrDenied, 403
			case "get":
				method, want, calls = "GET", 404, 0
			case "open_registration":
				path, want, calls = "/api/v1/arc/auth/register", 404, 0
			}
			req := httptest.NewRequest(method, "https://arc.example"+path, strings.NewReader(input))
			req.Header.Set("Origin", origin)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			g.ServeHTTP(w, req)
			if w.Code != want || backend.calls != calls {
				t.Fatalf("status=%d calls=%d; want %d/%d", w.Code, backend.calls, want, calls)
			}
			if w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 {
				t.Fatal("registration response must not be cached or create a session")
			}
			if (want == 201) != strings.Contains(w.Body.String(), "one-time-fixture") {
				t.Fatal("recovery result leaked on failure or missing on success")
			}
		})
	}
}

func TestInvitedRegistrationGateRateLimit(t *testing.T) {
	backend := &registrationBackend{}
	g, err := New(Config{Backend: backend, PublicOrigin: "https://arc.example", LoginsPerMinute: 1})
	if err != nil {
		t.Fatal(err)
	}
	for i, status := range []int{201, 429} {
		req := httptest.NewRequest("POST", "https://arc.example/api/v1/arc/auth/register-invited", strings.NewReader(`{"email":"new@example.test","password":"a long password","token":"invitation"}`))
		req.Header.Set("Origin", "https://arc.example")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		g.ServeHTTP(w, req)
		if w.Code != status || backend.calls != 1 {
			t.Fatalf("attempt %d: status=%d calls=%d", i, w.Code, backend.calls)
		}
	}
}
