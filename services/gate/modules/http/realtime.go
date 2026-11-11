package gate

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/services/core/modules/identity"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
)

const realtimePath = "/api/v1/arc/realtime"

var realtimeUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type realtimeCommand struct {
	Op             string `json:"op"`
	RequestID      string `json:"request_id,omitempty"`
	Channel        string `json:"channel,omitempty"`
	WorkspaceID    string `json:"workspace_id,omitempty"`
	RootID         string `json:"acl_root_id,omitempty"`
	SubscriptionID string `json:"subscription_id,omitempty"`
}

type liveSubscription struct {
	channel   string
	workspace string
	root      string
}

type realtimeClient struct {
	gate    *Gate
	hub     *realtimeHub
	socket  *websocket.Conn
	ctx     context.Context
	cancel  context.CancelFunc
	auth    identity.Authentication
	userID  string
	sessionID string
	mu      sync.Mutex
	subs    map[string]liveSubscription
	queue   chan queuedInvalidation
	commands chan realtimeCommand
}

func (c *realtimeClient) stop() { c.cancel() }

func (c *realtimeClient) enqueue(event invalidation) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, s := range c.subs {
		if event.channel != s.channel ||
			(event.channel == "task" && (s.workspace != event.workspace || s.root != event.root)) ||
			(event.channel == "inbox" && event.recipient != c.userID) {
			continue
		}
		select {
		case c.queue <- queuedInvalidation{subscriptionID: id, event: event}:
		default:
			c.stop()
		}
	}
}

func (g *Gate) StartRealtime() error {
	if g.hub == nil {
		return nil
	}
	return g.hub.start()
}

func (g *Gate) StopRealtime() {
	if g.hub != nil {
		g.hub.stop()
	}
}

// Browser credentials are exclusively Secure/HttpOnly cookies. The CSRF value
// appears only in the offered protocol and is never selected or echoed.
func (g *Gate) realtimeWS(w http.ResponseWriter, r *http.Request, requestID, clientIP string) {
	if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.URL.RawPath != "" ||
		r.Header.Get("Authorization") != "" || r.Header.Get("Origin") == "" ||
		!g.origins[r.Header.Get("Origin")] {
		writeError(w, requestID, fault(rpc.CodePermissionDenied))
		return
	}
	if g.hub == nil || !g.hub.connected(r.Context()) {
		writeError(w, requestID, fault(rpc.CodeUnavailable))
		return
	}
	if !g.rate(clientIP, "ws", 20) {
		writeError(w, requestID, fault(rpc.CodeRateLimited))
		return
	}
	csrf, err := r.Cookie(csrfCookie)
	if err != nil || csrf.Value == "" {
		writeError(w, requestID, fault(rpc.CodeUnauthenticated))
		return
	}
	protocols := websocket.Subprotocols(r)
	expected := "csrf." + base64.RawURLEncoding.EncodeToString([]byte(csrf.Value))
	valid := len(protocols) == 2
	if valid {
		seenVersion, seenCSRF := false, false
		for _, proto := range protocols {
			switch {
			case proto == "arc.realtime.v1":
				seenVersion = true
			case subtle.ConstantTimeCompare([]byte(proto), []byte(expected)) == 1:
				seenCSRF = true
			}
		}
		valid = seenVersion && seenCSRF
	}
	if !valid {
		writeError(w, requestID, fault(rpc.CodePermissionDenied))
		return
	}
	auth, err := g.external(r, false)
	if err != nil || auth.AccessToken != "" || auth.Session.Secret == "" {
		writeError(w, requestID, fault(rpc.CodeUnauthenticated))
		return
	}
	auth.RequireCSRF = true
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	session, err := g.cfg.Backend.Authenticate(ctx, auth)
	cancel()
	if err != nil || session.UserID == "" || session.ID == "" {
		writeError(w, requestID, fault(rpc.CodeUnauthenticated))
		return
	}
	upgrader := websocket.Upgrader{
		ReadBufferSize: 1024, WriteBufferSize: 1024,
		Subprotocols: []string{"arc.realtime.v1"},
		EnableCompression: false,
		CheckOrigin: func(req *http.Request) bool { return g.origins[req.Header.Get("Origin")] },
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	liveCtx, liveCancel := context.WithCancel(r.Context())
	c := &realtimeClient{
		gate: g, hub: g.hub, socket: conn, ctx: liveCtx, cancel: liveCancel,
		auth: auth, userID: session.UserID, sessionID: session.ID,
		subs: map[string]liveSubscription{}, queue: make(chan queuedInvalidation, 32),
		commands: make(chan realtimeCommand, 8),
	}
	if !g.hub.add(c) {
		c.stop()
	}
	defer func() {
		c.stop()
		g.hub.remove(c)
		_ = conn.Close()
	}()
	go c.read()
	c.write()
}

func (c *realtimeClient) read() {
	defer c.stop()
	c.socket.SetReadLimit(8 << 10)
	_ = c.socket.SetReadDeadline(time.Now().Add(90 * time.Second))
	c.socket.SetPongHandler(func(string) error {
		return c.socket.SetReadDeadline(time.Now().Add(90 * time.Second))
	})
	for {
		kind, raw, err := c.socket.ReadMessage()
		if err != nil || kind != websocket.TextMessage {
			return
		}
		var command realtimeCommand
		if contract.Strict(raw, &command) != nil {
			return
		}
		select {
		case c.commands <- command:
		case <-c.ctx.Done():
			return
		default:
			return
		}
	}
}

func (c *realtimeClient) verifySession(ctx context.Context) error {
	s, err := c.gate.cfg.Backend.Authenticate(ctx, c.auth)
	if err != nil || s.UserID != c.userID || s.ID != c.sessionID || !s.ExpiresAt.After(time.Now()) {
		return errors.New("session unavailable")
	}
	return nil
}

// Task's own approved list query is the authorization oracle: it checks the
// live workspace/root binding and action=task.read inside Task, not in Gate.
func (c *realtimeClient) verifyTask(ctx context.Context, scope liveSubscription) error {
	snapshot := c.gate.routes.current.Load()
	if snapshot == nil {
		return errors.New("routes unavailable")
	}
	for _, en := range snapshot.entries {
		if en.op.ID != taskv1.WorkList.ID {
			continue
		}
		req := taskv1.WorkListRequest{CatalogPage: taskv1.CatalogPage{
			Scope: taskv1.Scope{WorkspaceID: scope.workspace, RootID: scope.root},
			Limit: 1,
		}}
		raw, err := json.Marshal(req)
		if err != nil || en.compiled.Validate(en.op.RequestSchema, raw) != nil {
			return errors.New("Task contract unavailable")
		}
		token, err := c.gate.cfg.Backend.Exchange(ctx, identity.UserExchange{
			Session: c.auth.Session,
			Target: identity.Target{Audience: "task/v1", Operation: en.op.ID, WorkspaceID: scope.workspace},
		})
		if err != nil {
			return err
		}
		_, err = c.gate.cfg.Backend.Invoke(ctx, en.compiled, en.op, raw, token.Token, "")
		return err
	}
	return errors.New("Task route unavailable")
}

func (c *realtimeClient) check(ctx context.Context, scope liveSubscription) error {
	if err := c.verifySession(ctx); err != nil {
		return err
	}
	if scope.channel == "task" {
		return c.verifyTask(ctx, scope)
	}
	return nil
}

func (c *realtimeClient) handle(q realtimeCommand) any {
	if q.Op == "ping" && q.Channel == "" && q.WorkspaceID == "" && q.RootID == "" && q.SubscriptionID == "" {
		return map[string]any{"type": "pong", "request_id": q.RequestID}
	}
	if !requestIDPattern.MatchString(q.RequestID) {
		return map[string]any{"type": "error", "code": "invalid_request"}
	}
	if q.Op == "unsubscribe" && q.SubscriptionID != "" &&
		q.Channel == "" && q.WorkspaceID == "" && q.RootID == "" {
		c.mu.Lock()
		_, ok := c.subs[q.SubscriptionID]
		delete(c.subs, q.SubscriptionID)
		c.mu.Unlock()
		if !ok {
			return map[string]any{"type": "error", "request_id": q.RequestID, "code": "unavailable"}
		}
		return map[string]any{"type": "unsubscribed", "request_id": q.RequestID}
	}
	if q.Op != "subscribe" || q.SubscriptionID != "" {
		return map[string]any{"type": "error", "request_id": q.RequestID, "code": "invalid_request"}
	}
	scope := liveSubscription{channel: q.Channel, workspace: q.WorkspaceID, root: q.RootID}
	switch q.Channel {
	case "inbox":
		if q.WorkspaceID != "" || q.RootID != "" {
			return map[string]any{"type": "error", "request_id": q.RequestID, "code": "invalid_request"}
		}
	case "task":
		if !realtimeUUID.MatchString(q.WorkspaceID) || !realtimeUUID.MatchString(q.RootID) {
			return map[string]any{"type": "error", "request_id": q.RequestID, "code": "invalid_request"}
		}
	default:
		return map[string]any{"type": "error", "request_id": q.RequestID, "code": "invalid_request"}
	}
	c.mu.Lock()
	full := len(c.subs) >= 8
	for _, active := range c.subs {
		if active == scope {
			full = true
		}
	}
	c.mu.Unlock()
	if full {
		return map[string]any{"type": "error", "request_id": q.RequestID, "code": "limit"}
	}
	ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	err := c.check(ctx, scope)
	cancel()
	if err != nil {
		return map[string]any{"type": "error", "request_id": q.RequestID, "code": "denied"}
	}
	id := NewID()
	c.mu.Lock()
	c.subs[id] = scope
	c.mu.Unlock()
	return map[string]any{"type": "subscribed", "request_id": q.RequestID, "subscription_id": id}
}

func (c *realtimeClient) send(value any) error {
	if err := c.socket.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	return c.socket.WriteJSON(value)
}

func (c *realtimeClient) write() {
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()
	for {
		if !c.hub.connected(c.ctx) {
			return
		}
		select {
		case <-c.ctx.Done():
			return
		case cmd := <-c.commands:
			if err := c.send(c.handle(cmd)); err != nil {
				return
			}
		case queued := <-c.queue:
			c.mu.Lock()
			scope, exists := c.subs[queued.subscriptionID]
			c.mu.Unlock()
			if !exists {
				continue
			}
			ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
			err := c.check(ctx, scope)
			cancel()
			if err != nil {
				return
			}
			msg := map[string]any{
				"type": "invalidate", "subscription_id": queued.subscriptionID,
				"entity_kind": queued.event.kind,
			}
			if queued.event.id != "" {
				msg["entity_id"] = queued.event.id
			}
			if queued.event.revision > 0 {
				msg["revision"] = queued.event.revision
			}
			if err := c.send(msg); err != nil {
				return
			}
		case <-heartbeat.C:
			ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
			err := c.verifySession(ctx)
			cancel()
			if err != nil || !c.hub.connected(c.ctx) {
				return
			}
			if err := c.socket.WriteControl(websocket.PingMessage, []byte("arc"), time.Now().Add(15*time.Second)); err != nil {
				return
			}
		}
	}
}

