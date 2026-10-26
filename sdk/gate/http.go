package gate

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/identity"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
)

const csrfCookie = "__Host-arc_csrf"
const refreshCookie = "__Host-arc_refresh"

type Config struct {
	Backend           Backend
	PublicOrigin      string
	AllowedOrigins    []string
	TrustedProxies    []netip.Prefix
	ReconcileInterval time.Duration
	RequestTimeout    time.Duration
	BodyLimit         int64
	RequestsPerMinute int
	LoginsPerMinute   int
}
type bucket struct {
	start time.Time
	count int
}
type Gate struct {
	available atomic.Bool
	cfg       Config
	routes    routes
	origins   map[string]bool
	mu        sync.Mutex
	limits    map[string]bucket
}

func New(cfg Config) (*Gate, error) {
	if cfg.Backend == nil {
		return nil, errors.New("gate: missing Core backend")
	}
	origins := map[string]bool{}
	for _, origin := range append(cfg.AllowedOrigins, cfg.PublicOrigin) {
		u, e := url.Parse(origin)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return nil, errors.New("gate: HTTPS origins required")
		}
		origins[origin] = true
	}
	if cfg.ReconcileInterval <= 0 {
		cfg.ReconcileInterval = 15 * time.Second
	}
	if cfg.RequestTimeout <= 0 || cfg.RequestTimeout > 10*time.Second {
		cfg.RequestTimeout = 10 * time.Second
	}
	if cfg.BodyLimit <= 0 || cfg.BodyLimit > 200<<10 {
		cfg.BodyLimit = 200 << 10
	}
	if cfg.RequestsPerMinute <= 0 {
		cfg.RequestsPerMinute = 120
	}
	if cfg.LoginsPerMinute <= 0 {
		cfg.LoginsPerMinute = 10
	}
	return &Gate{cfg: cfg, origins: origins, limits: map[string]bucket{}}, nil
}
func Status(code rpc.Code) int {
	switch code {
	case rpc.CodeUnauthenticated:
		return 401
	case rpc.CodePermissionDenied:
		return 403
	case rpc.CodeNotFound:
		return 404
	case rpc.CodeValidation:
		return 400
	case rpc.CodeConflict:
		return 409
	case rpc.CodeRateLimited:
		return 429
	case rpc.CodeUnavailable:
		return 503
	case rpc.CodeDeadlineExceeded:
		return 504
	default:
		return 500
	}
}
func writeError(w http.ResponseWriter, id string, e error) {
	code := rpc.ErrorCode(e)
	var typed *rpc.Error
	if !errors.As(e, &typed) {
		switch {
		case errors.Is(e, security.ErrUnavailable):
			code = rpc.CodeUnavailable
		case errors.Is(e, security.ErrUnauthenticated):
			code = rpc.CodeUnauthenticated
		case errors.Is(e, security.ErrDenied):
			code = rpc.CodePermissionDenied
		case errors.Is(e, context.DeadlineExceeded):
			code = rpc.CodeDeadlineExceeded
		default:
			code = rpc.CodeInternal
		}
	}
	if code == rpc.CodeRateLimited {
		w.Header().Set("Retry-After", "60")
	}
	writeJSON(w, Status(code), map[string]any{"request_id": id, "error": map[string]any{"code": code, "message": string(code)}})
}
func fault(code rpc.Code) error { return &rpc.Error{Code: code, Message: string(code)} }
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if status != 204 {
		_ = json.NewEncoder(w).Encode(v)
	}
}

var requestIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)
var tracePattern = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)

func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get("X-Request-ID")
	if id == "" {
		id = NewID()
	}
	w.Header().Set("X-Request-ID", id)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.Header().Set("Cache-Control", "no-store")
	defer func() {
		if recover() != nil {
			writeError(w, id, fault(rpc.CodeInternal))
		}
	}()
	if !requestIDPattern.MatchString(id) {
		writeError(w, "invalid", fault(rpc.CodeValidation))
		return
	}
	if r.URL.Path == "/healthz" {
		if r.Method != "GET" {
			writeError(w, id, fault(rpc.CodeNotFound))
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
		return
	}
	if r.URL.Path == "/readyz" {
		if r.Method != "GET" {
			writeError(w, id, fault(rpc.CodeNotFound))
			return
		}
		if g.Revision() < 0 || !g.available.Load() {
			writeError(w, id, fault(rpc.CodeUnavailable))
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ready"})
		return
	}
	client, secure, e := g.peer(r)
	if e != nil || !secure {
		writeError(w, id, fault(rpc.CodeValidation))
		return
	}
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	if !g.cors(w, r) {
		writeError(w, id, fault(rpc.CodePermissionDenied))
		return
	}
	if r.Method == "OPTIONS" {
		w.WriteHeader(204)
		return
	}
	if !g.rate(client, "all", g.cfg.RequestsPerMinute) {
		writeError(w, id, fault(rpc.CodeRateLimited))
		return
	}
	trace := r.Header.Get("Traceparent")
	if trace != "" && (!tracePattern.MatchString(trace) || strings.HasPrefix(trace, "00-00000000000000000000000000000000-") || trace[36:52] == "0000000000000000") {
		writeError(w, id, fault(rpc.CodeValidation))
		return
	}
	deadline := time.Now().Add(g.cfg.RequestTimeout)
	if raw := r.Header.Get("X-Request-Deadline"); raw != "" {
		d, e := time.Parse(time.RFC3339Nano, raw)
		if e != nil {
			writeError(w, id, fault(rpc.CodeValidation))
			return
		}
		if d.Before(deadline) {
			deadline = d
		}
	}
	if !deadline.After(time.Now()) {
		writeError(w, id, fault(rpc.CodeDeadlineExceeded))
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	ctx = rpc.WithOutgoing(ctx, rpc.Outgoing{RequestID: id, Traceparent: trace})
	r = r.WithContext(ctx)
	r.Body = http.MaxBytesReader(w, r.Body, g.cfg.BodyLimit)
	if strings.HasPrefix(r.URL.Path, "/api/v1/arc/") {
		g.auth(w, r, id, client)
		return
	}
	t := g.routes.current.Load()
	if t == nil {
		writeError(w, id, fault(rpc.CodeUnavailable))
		return
	}
	if r.URL.RawPath != "" || path.Clean(r.URL.Path) != r.URL.Path || strings.ContainsAny(r.URL.Path, "\\%") {
		writeError(w, id, fault(rpc.CodeValidation))
		return
	}
	en, params, ok := t.match(r.Method, r.URL.Path)
	if !ok {
		writeError(w, id, fault(rpc.CodeNotFound))
		return
	}
	payload, e := bindPayload(r, en, params)
	if e != nil {
		g.inputError(w, id, e)
		return
	}
	a, e := g.external(r, en.op.Kind == "command")
	if e != nil {
		writeError(w, id, e)
		return
	}
	if _, e = g.cfg.Backend.Authenticate(ctx, a); e != nil {
		writeError(w, id, e)
		return
	}
	idem := r.Header.Get("Idempotency-Key")
	if en.op.Kind == "command" && (idem == "" || len(idem) > 128) {
		writeError(w, id, fault(rpc.CodeValidation))
		return
	}
	budget := time.Duration(en.op.TimeoutMS) * time.Millisecond
	opCtx, opCancel := context.WithTimeout(ctx, budget)
	defer opCancel()
	workspace := ""
	if en.op.Auth.WorkspaceFrom != "" {
		workspace, e = contract.Extract(payload, en.op.Auth.WorkspaceFrom)
		if e != nil {
			writeError(w, id, fault(rpc.CodeValidation))
			return
		}
	}
	token, e := g.cfg.Backend.Exchange(opCtx, identity.UserExchange{Session: a.Session, AccessToken: a.AccessToken, Target: identity.Target{Audience: fmt.Sprintf("%s/v%d", en.route.Service, en.route.APIMajor), Operation: en.route.Operation, WorkspaceID: workspace}})
	if e != nil {
		writeError(w, id, e)
		return
	}
	data, e := g.cfg.Backend.Invoke(opCtx, en.compiled, en.op, payload, token.Token, idem)
	if e != nil {
		writeError(w, id, e)
		return
	}
	if en.compiled.Validate(en.op.ResponseSchema, data) != nil {
		writeError(w, id, fault(rpc.CodeInternal))
		return
	}
	writeJSON(w, en.route.SuccessStatus, json.RawMessage(data))
}
func (g *Gate) inputError(w http.ResponseWriter, id string, e error) {
	var large *http.MaxBytesError
	if errors.As(e, &large) {
		writeJSON(w, 413, map[string]any{"request_id": id, "error": map[string]string{"code": "VALIDATION_ERROR", "message": "body too large"}})
		return
	}
	writeError(w, id, fault(rpc.CodeValidation))
}
func readObject(r *http.Request) (map[string]any, error) {
	raw, e := io.ReadAll(r.Body)
	if e != nil {
		return nil, e
	}
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	typ, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || typ != "application/json" {
		return nil, contract.ErrInvalid
	}
	if _, e = security.CanonicalJSON(raw); e != nil {
		return nil, e
	}
	var out map[string]any
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	if d.Decode(&out) != nil || out == nil {
		return nil, contract.ErrInvalid
	}
	for k := range out {
		if contract.ReservedIdentityField(k) {
			return nil, contract.ErrInvalid
		}
	}
	return out, nil
}
func bindPayload(r *http.Request, en entry, params map[string]string) (json.RawMessage, error) {
	body, e := readObject(r)
	if e != nil {
		return nil, e
	}
	query, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		return nil, e
	}
	used := map[string]bool{}
	for _, b := range en.route.Bindings {
		var value string
		if b.Source == "path" {
			value = params[b.Name]
		} else {
			xs, ok := query[b.Name]
			if !ok {
				continue
			}
			if len(xs) != 1 {
				return nil, contract.ErrInvalid
			}
			value = xs[0]
			used[b.Name] = true
		}
		if _, exists := body[b.Field]; exists {
			return nil, contract.ErrInvalid
		}
		var v any = value
		switch b.Type {
		case "integer":
			n, e := strconv.ParseInt(value, 10, 64)
			if e != nil {
				return nil, e
			}
			v = n
		case "number":
			n, e := strconv.ParseFloat(value, 64)
			if e != nil {
				return nil, e
			}
			v = n
		case "boolean":
			if value != "true" && value != "false" {
				return nil, contract.ErrInvalid
			}
			v = value == "true"
		}
		body[b.Field] = v
	}
	for name := range query {
		if !used[name] {
			return nil, contract.ErrInvalid
		}
	}
	raw, e := json.Marshal(body)
	if e != nil || en.compiled.Validate(en.op.RequestSchema, raw) != nil {
		return nil, contract.ErrInvalid
	}
	return raw, nil
}
func (g *Gate) external(r *http.Request, mutation bool) (identity.Authentication, error) {
	var a identity.Authentication
	auth := r.Header.Get("Authorization")
	session, _ := r.Cookie("__Host-arc_session")
	if auth != "" {
		if session != nil || !strings.HasPrefix(auth, "Bearer ") || len(strings.TrimPrefix(auth, "Bearer ")) < 1 {
			return a, fault(rpc.CodeUnauthenticated)
		}
		a.AccessToken = strings.TrimPrefix(auth, "Bearer ")
		return a, nil
	}
	csrf, _ := r.Cookie(csrfCookie)
	if session == nil || session.Value == "" || csrf == nil || csrf.Value == "" {
		return a, fault(rpc.CodeUnauthenticated)
	}
	if mutation {
		if !g.origins[r.Header.Get("Origin")] || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(csrf.Value)) != 1 {
			return a, fault(rpc.CodePermissionDenied)
		}
	}
	a.Session = identity.UserSession{Secret: session.Value, CSRF: csrf.Value}
	a.RequireCSRF = mutation
	return a, nil
}
func (g *Gate) rate(client, kind string, max int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	key := kind + ":" + client
	b := g.limits[key]
	if b.start.IsZero() || now.Sub(b.start) >= time.Minute {
		if len(g.limits) >= 10000 {
			for k, v := range g.limits {
				if now.Sub(v.start) >= time.Minute {
					delete(g.limits, k)
				}
			}
			if len(g.limits) >= 10000 {
				return false
			}
		}
		b = bucket{start: now}
	}
	b.count++
	g.limits[key] = b
	return b.count <= max
}
func (g *Gate) trusted(ip netip.Addr) bool {
	for _, p := range g.cfg.TrustedProxies {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
func (g *Gate) peer(r *http.Request) (string, bool, error) {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return "", false, e
	}
	ip, e := netip.ParseAddr(host)
	if e != nil {
		return "", false, e
	}
	secure := r.TLS != nil
	if g.trusted(ip) {
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			if proto != "https" && proto != "http" {
				return "", false, contract.ErrInvalid
			}
			secure = proto == "https"
		}
		chain := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		for i := len(chain) - 1; i >= 0 && g.trusted(ip); i-- {
			if strings.TrimSpace(chain[i]) == "" {
				continue
			}
			next, e := netip.ParseAddr(strings.TrimSpace(chain[i]))
			if e != nil {
				return "", false, e
			}
			ip = next
		}
	}
	return ip.String(), secure, nil
}
func (g *Gate) cors(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin != "" {
		if !g.origins[origin] {
			return false
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Add("Vary", "Origin")
	}
	if r.Method == "OPTIONS" {
		if origin == "" {
			return false
		}
		method := r.Header.Get("Access-Control-Request-Method")
		if method != "GET" && method != "POST" && method != "PUT" && method != "PATCH" && method != "DELETE" {
			return false
		}
		for _, h := range strings.Split(r.Header.Get("Access-Control-Request-Headers"), ",") {
			switch strings.ToLower(strings.TrimSpace(h)) {
			case "", "content-type", "authorization", "x-csrf-token", "idempotency-key", "x-request-id", "traceparent", "x-request-deadline":
			default:
				return false
			}
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token, Idempotency-Key, X-Request-ID, Traceparent, X-Request-Deadline")
	}
	return true
}
