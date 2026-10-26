package fabric

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"fmt"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/micro"
	"github.com/pavlith/arc/pkgs"
	"github.com/pavlith/arc/pkgs/contract"
	"github.com/pavlith/arc/pkgs/rpc"
	"github.com/pavlith/arc/pkgs/security"
	"strings"
)

const RegisterSubject = "ctl.arc.fabric.register"
const ReadySubject = "ctl.arc.fabric.ready"
const EventPermitSubject = "ctl.arc.fabric.event_permit"
const CheckSubject = "ctl.arc.fabric.check"

type controlRequest struct {
	Subscription *EventSubscription `json:"subscription,omitempty"`
	RequestID    string             `json:"request_id"`
	Assertion    string             `json:"assertion"`
	Proof        security.Proof     `json:"proof"`
	Registration pkgs.Registration  `json:"registration"`
}
type controlResponse struct {
	Subject   string     `json:"subject"`
	ExpiresAt time.Time  `json:"expires_at"`
	Signature []byte     `json:"signature"`
	RequestID string     `json:"request_id"`
	Error     *rpc.Error `json:"error,omitempty"`
}
type probe struct {
	Challenge    string            `json:"challenge"`
	Registration pkgs.Registration `json:"registration"`
	MicroID      string            `json:"micro_id,omitempty"`
	Signature    []byte            `json:"signature,omitempty"`
}

func randomID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}
func probeBytes(p probe) []byte {
	p.Signature = nil
	b, _ := json.Marshal(p)
	b, _ = security.CanonicalJSON(b)
	return b
}
func probeSubject(r pkgs.Registration) string { return "ctl.arc.fabric.probe." + r.Instance }

// BindControl binds only the three exact control subjects. It does not trust NATS headers.
func (c *Core) BindControl(nc *nats.Conn) (func(), error) {
	if e := c.ready(); e != nil {
		return nil, e
	}
	if len(c.SnapshotKey) != 64 {
		return nil, security.ErrUnavailable
	}
	subs := []*nats.Subscription{}
	closeAll := func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	}
	for _, subject := range []string{RegisterSubject, ReadySubject, CheckSubject, EventPermitSubject} {
		sub, e := nc.Subscribe(subject, func(msg *nats.Msg) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var q controlRequest
			var err error
			if contract.Strict(msg.Data, &q) != nil || q.RequestID == "" {
				err = contract.ErrInvalid
			} else {
				err = c.control(ctx, nc, msg.Subject, msg.Data, q)
			}
			res := controlResponse{RequestID: q.RequestID, Subject: msg.Subject, ExpiresAt: time.Now().UTC().Add(5 * time.Second)}
			if err != nil {
				if err == contract.ErrInvalid {
					res.Error = &rpc.Error{Code: rpc.CodeValidation, Message: "invalid fabric request"}
				} else {
					res.Error = rpc.SecurityError(err).(*rpc.Error)
				}
			}
			res.Signature = ed25519.Sign(c.SnapshotKey, controlResponseBytes(res))
			raw, _ := json.Marshal(res)
			_ = msg.Respond(raw)
		})
		if e != nil {
			closeAll()
			return nil, e
		}
		subs = append(subs, sub)
	}
	if e := nc.FlushTimeout(3 * time.Second); e != nil {
		closeAll()
		return nil, e
	}
	return closeAll, nil
}
func (c *Core) control(ctx context.Context, nc *nats.Conn, subject string, raw []byte, q controlRequest) error {
	cl, e := c.Identity.Verifier().AssertionFor(ctx, q.Assertion, subject)
	if e != nil {
		return e
	}
	cl.Caller = cl.Issuer
	if e = c.Identity.Verifier().Proof(ctx, subject, raw, cl, q.Proof); e != nil {
		return e
	}
	r := q.Registration
	if r.Instance == "" || len(r.Instance) > 128 {
		return contract.ErrInvalid
	}
	for _, ch := range r.Instance {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
			return contract.ErrInvalid
		}
	}
	m, e := c.active(ctx, cl.Caller, r.Digest)
	if e != nil {
		return e
	}
	if r.Service != m.Manifest.Service.Name || r.Build != m.Manifest.Service.BuildVersion {
		return security.ErrDenied
	}
	switch subject {
	case RegisterSubject:
		res, e := c.DB.ExecContext(ctx, `INSERT INTO fabric.instances(instance_id,service_account_id,digest,build_version,lease_until) VALUES($1,$2,$3,$4,now()+interval '30 seconds') ON CONFLICT(instance_id) DO UPDATE SET ready=false,lease_until=excluded.lease_until,observed_at=now() WHERE fabric.instances.service_account_id=excluded.service_account_id AND fabric.instances.digest=excluded.digest AND fabric.instances.build_version=excluded.build_version`, r.Instance, cl.Caller, r.Digest, r.Build)
		if e != nil {
			return security.ErrUnavailable
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return security.ErrDenied
		}
		return nil
	case ReadySubject:
		// Probe an instance-specific endpoint, bind challenge to identity/digest, then
		// independently inspect Micro's declared business endpoints (not its identity).
		p := probe{Challenge: randomID(), Registration: r}
		wire, _ := json.Marshal(p)
		msg, e := nc.RequestWithContext(ctx, probeSubject(r), wire)
		if e != nil {
			return security.ErrUnavailable
		}
		var response probe
		if contract.Strict(msg.Data, &response) != nil || response.Challenge != p.Challenge || response.Registration != r {
			return security.ErrUnauthenticated
		}
		key, e := c.Identity.CallerKey(ctx, cl.Caller, cl.Confirmation.Kid)
		if e != nil {
			return e
		}
		if !ed25519.Verify(key.Public, probeBytes(response), response.Signature) {
			return security.ErrUnauthenticated
		}
		if response.MicroID == "" || strings.ContainsAny(response.MicroID, ".*> \r\n\t") {
			return security.ErrUnauthenticated
		}
		infoMsg, e := nc.RequestWithContext(ctx, "$SRV.INFO."+r.Service+"."+response.MicroID, nil)
		if e != nil {
			return security.ErrUnavailable
		}
		var info micro.Info
		if json.Unmarshal(infoMsg.Data, &info) != nil || info.ID != response.MicroID || info.Name != r.Service || info.Version != r.Build || info.Metadata["contract_digest"] != r.Digest || info.Metadata["instance_id"] != r.Instance || len(info.Endpoints) != len(m.Manifest.Operations) {
			return security.ErrDenied
		}
		endpoints := map[string]bool{}
		for _, ep := range info.Endpoints {
			if ep.QueueGroup != fmt.Sprintf("q.%s.v%d", r.Service, m.Manifest.Service.APIMajor) {
				return security.ErrDenied
			}
			endpoints[ep.Subject] = true
		}
		for _, op := range m.Manifest.Operations {
			if !endpoints[op.Subject] {
				return security.ErrDenied
			}
		}
		return c.touch(ctx, cl.Caller, r, true)
	case EventPermitSubject:
		if q.Subscription == nil {
			return security.ErrDenied
		}
		if e = c.touch(ctx, cl.Caller, r, false); e != nil {
			return e
		}
		var installRaw []byte
		if e = c.DB.QueryRowContext(ctx, `SELECT installation FROM fabric.contracts WHERE digest=$1 AND revoked_at IS NULL`, r.Digest).Scan(&installRaw); e != nil {
			return security.ErrUnavailable
		}
		var install Installation
		if contract.Strict(installRaw, &install) != nil {
			return security.ErrDenied
		}
		found := false
		for _, sub := range install.Subscriptions {
			if sub == *q.Subscription {
				found = true
			}
		}
		if !found {
			return security.ErrDenied
		}
		provider, e := c.active(ctx, q.Subscription.Provider, q.Subscription.Digest)
		if e != nil {
			return e
		}
		for _, ev := range provider.Manifest.Events {
			if ev.Subject == q.Subscription.Subject {
				return nil
			}
		}
		return security.ErrDenied
	case CheckSubject:
		return c.touch(ctx, cl.Caller, r, false)
	}
	return security.ErrDenied
}
func (c *Core) touch(ctx context.Context, account string, r pkgs.Registration, ready bool) error {
	res, e := c.DB.ExecContext(ctx, `UPDATE fabric.instances SET ready=true,lease_until=now()+interval '30 seconds',observed_at=now() WHERE instance_id=$1 AND service_account_id::text=$2 AND digest=$3 AND build_version=$4 AND lease_until>now() AND ($5 OR ready)`, r.Instance, account, r.Digest, r.Build, ready)
	if e != nil {
		return security.ErrUnavailable
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return security.ErrDenied
	}
	return nil
}

type Client struct {
	CoreKey  ed25519.PublicKey
	Account  string
	Kid      string
	Key      ed25519.PrivateKey
	NC       *nats.Conn
	mu       sync.Mutex
	probes   map[string]*nats.Subscription
	evidence map[string]pkgs.ReadyEvidence
}

func (c *Client) invoke(ctx context.Context, subject string, r pkgs.Registration) error {
	return c.invokeSubscription(ctx, subject, r, nil)
}
func (c *Client) EventPermit(ctx context.Context, r pkgs.Registration, sub EventSubscription) error {
	return c.invokeSubscription(ctx, EventPermitSubject, r, &sub)
}
func (c *Client) invokeSubscription(ctx context.Context, subject string, r pkgs.Registration, subscription *EventSubscription) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if c.NC == nil || len(c.Key) != 64 || len(c.CoreKey) != 32 {
		return security.ErrUnavailable
	}
	now := time.Now().UTC()
	cl := security.Claims{Issuer: c.Account, Subject: c.Account, Audience: subject, IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Add(25 * time.Second).Unix(), JTI: randomID(), Confirmation: security.Confirmation{Kid: c.Kid}}
	assertion, e := security.Sign(c.Key, c.Kid, cl)
	if e != nil {
		return e
	}
	q := controlRequest{RequestID: randomID(), Assertion: assertion, Registration: r, Subscription: subscription}
	raw, _ := json.Marshal(q)
	q.Proof, e = security.SignProof(c.Key, subject, raw, cl.JTI, security.Proof{Kid: c.Kid, Timestamp: now.Format(time.RFC3339Nano), Nonce: randomID()})
	if e != nil {
		return e
	}
	raw, _ = json.Marshal(q)
	msg, e := c.NC.RequestWithContext(ctx, subject, raw)
	if e != nil {
		return security.ErrUnavailable
	}
	var res controlResponse
	if contract.Strict(msg.Data, &res) != nil || res.RequestID != q.RequestID || res.Subject != subject || !res.ExpiresAt.After(time.Now()) || res.ExpiresAt.After(time.Now().Add(10*time.Second)) || !ed25519.Verify(c.CoreKey, controlResponseBytes(res), res.Signature) {
		return security.ErrUnauthenticated
	}
	if res.Error != nil {
		switch res.Error.Code {
		case rpc.CodeUnauthenticated:
			return security.ErrUnauthenticated
		case rpc.CodePermissionDenied:
			return security.ErrDenied
		default:
			return security.ErrUnavailable
		}
	}
	return nil
}
func (c *Client) Register(ctx context.Context, nc *nats.Conn, r pkgs.Registration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.NC == nil {
		c.NC = nc
	}
	if c.NC != nc {
		return security.ErrDenied
	}
	if e := c.invoke(ctx, RegisterSubject, r); e != nil {
		return e
	}
	if c.probes == nil {
		c.probes = map[string]*nats.Subscription{}
	}
	if c.probes[r.Instance] != nil {
		return nil
	}
	sub, e := nc.Subscribe(probeSubject(r), func(msg *nats.Msg) {
		var p probe
		if contract.Strict(msg.Data, &p) != nil || p.Registration != r || len(p.Challenge) != 32 {
			return
		}
		c.mu.Lock()
		p.MicroID = c.evidence[r.Instance].MicroID
		c.mu.Unlock()
		p.Signature = ed25519.Sign(c.Key, probeBytes(p))
		raw, _ := json.Marshal(p)
		_ = msg.Respond(raw)
	})
	if e != nil {
		return e
	}
	c.probes[r.Instance] = sub
	return nc.FlushWithContext(ctx)
}
func (c *Client) Ready(ctx context.Context, r pkgs.Registration, e pkgs.ReadyEvidence) error {
	c.mu.Lock()
	if c.evidence == nil {
		c.evidence = map[string]pkgs.ReadyEvidence{}
	}
	c.evidence[r.Instance] = e
	c.mu.Unlock()
	return c.invoke(ctx, ReadySubject, r)
}
func (c *Client) Check(ctx context.Context, r pkgs.Registration) error {
	return c.invoke(ctx, CheckSubject, r)
}

var _ pkgs.Registry = (*Client)(nil)

func controlResponseBytes(r controlResponse) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	raw, _ = security.CanonicalJSON(raw)
	return raw
}
