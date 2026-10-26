package access

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/pavlith/arc/pkgs/security"
	"github.com/pavlith/arc/services/core/modules/identity"
)

// Approved is a Core-pinned, offline-signed M0 approval. It is not a registration
// request or a Fabric implementation. No approval/key is accepted from RPC data.
type Approved struct {
	Payload   json.RawMessage
	Signature []byte
}
type TypeSpec struct {
	Type             string   `json:"type"`
	Provider         string   `json:"provider_service"`
	Actions          []string `json:"actions"`
	ShareAction      string   `json:"share_action"`
	CreateAction     string   `json:"create_action"`
	DeleteAction     string   `json:"delete_action"`
	AllowInheritance bool     `json:"allow_inheritance"`
}
type Rule struct {
	Caller            string              `json:"caller"`
	Audience          string              `json:"audience"`
	Operation         string              `json:"operation"`
	ActorKinds        []string            `json:"actor_kinds"`
	Actions           []string            `json:"actions"`
	DownstreamFrom    []string            `json:"downstream_from,omitempty"`
	DownstreamActions map[string][]string `json:"downstream_actions,omitempty"`
}
type Deployment struct {
	Definition string `json:"service_definition"`
	Instance   string `json:"deployment"`
}

type Approval struct {
	ContractDigests map[string]string   `json:"contract_digests,omitempty"`
	Deployments     []Deployment        `json:"deployments"`
	Types           []TypeSpec          `json:"types"`
	Rules           []Rule              `json:"rules"`
	AgentScopes     map[string][]string `json:"agent_scopes"`
	AdminUsers      []string            `json:"admin_users"`
}
type Contracts struct {
	types       map[string]TypeSpec
	digests     map[string]string
	rules       []Rule
	agentScopes map[string][]string
	admins      []string
	deployments []Deployment
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func NewContracts(key ed25519.PublicKey, approvals []Approved) (*Contracts, error) {
	if len(key) != 32 || len(approvals) == 0 {
		return nil, security.ErrUnavailable
	}
	c := &Contracts{types: map[string]TypeSpec{}, digests: map[string]string{}, agentScopes: map[string][]string{}}
	for _, signed := range approvals {
		raw, e := security.CanonicalJSON(signed.Payload)
		if e != nil || !ed25519.Verify(key, raw, signed.Signature) {
			return nil, security.ErrUnauthenticated
		}
		var a Approval
		if json.Unmarshal(raw, &a) != nil {
			return nil, security.ErrDenied
		}
		sum := sha256.Sum256(raw)
		digest := hex.EncodeToString(sum[:])
		for _, t := range a.Types {
			if !validUUID(t.Provider) || !namespaced(t.Type) || c.types[t.Type].Type != "" || len(t.Actions) == 0 || !contains(t.Actions, "access.grants.manage") || !contains(t.Actions, t.ShareAction) || !contains(t.Actions, t.CreateAction) || !contains(t.Actions, t.DeleteAction) {
				return nil, security.ErrDenied
			}
			seen := map[string]bool{}
			for _, act := range t.Actions {
				if !namespaced(act) || seen[act] {
					return nil, security.ErrDenied
				}
				seen[act] = true
			}
			c.types[t.Type] = t
			c.digests[t.Type] = digest
			if bound, ok := a.ContractDigests[t.Type]; ok {
				if len(bound) != 64 {
					return nil, security.ErrDenied
				}
				if _, e := hex.DecodeString(bound); e != nil {
					return nil, security.ErrDenied
				}
				c.digests[t.Type] = bound
			}
		}
		for _, r := range a.Rules {
			if !validUUID(r.Caller) || r.Audience == "" || !namespaced(r.Operation) || len(r.ActorKinds) == 0 || strings.ContainsAny(r.Audience, "*>") {
				return nil, security.ErrDenied
			}
			for _, k := range r.ActorKinds {
				if k != "user" && k != "agent" && k != "service" && k != "bootstrap" {
					return nil, security.ErrDenied
				}
			}
			for _, act := range r.Actions {
				if !namespaced(act) {
					return nil, security.ErrDenied
				}
			}
			for _, existing := range c.rules {
				if existing.Caller == r.Caller && existing.Audience == r.Audience && existing.Operation == r.Operation {
					for _, kind := range r.ActorKinds {
						if contains(existing.ActorKinds, kind) {
							return nil, security.ErrDenied
						}
					}
				}
			}
			for _, source := range r.DownstreamFrom {
				pair := strings.Split(source, ":")
				if len(pair) != 2 || pair[0] == "" || strings.ContainsAny(pair[0], "*> \n\t\r") || !namespaced(pair[1]) {
					return nil, security.ErrDenied
				}
			}
			for source, actions := range r.DownstreamActions {
				if !contains(r.DownstreamFrom, source) {
					return nil, security.ErrDenied
				}
				for _, action := range actions {
					if !contains(r.Actions, action) {
						return nil, security.ErrDenied
					}
				}
			}
			if len(r.Actions) > 0 {
				for _, source := range r.DownstreamFrom {
					if _, ok := r.DownstreamActions[source]; !ok {
						return nil, security.ErrDenied
					}
				}
			}
			c.rules = append(c.rules, r)
		}
		for scope, actions := range a.AgentScopes {
			if scope == "" || c.agentScopes[scope] != nil {
				return nil, security.ErrDenied
			}
			for _, act := range actions {
				if !namespaced(act) {
					return nil, security.ErrDenied
				}
			}
			c.agentScopes[scope] = actions
		}
		for _, d := range a.Deployments {
			if d.Definition == "" || d.Instance == "" || strings.ContainsAny(d.Definition+d.Instance, "*>\n\r\t") {
				return nil, security.ErrDenied
			}
			c.deployments = append(c.deployments, d)
		}
		for _, id := range a.AdminUsers {
			if !validUUID(id) {
				return nil, security.ErrDenied
			}
			c.admins = append(c.admins, id)
		}
	}
	return c, nil
}
func namespaced(s string) bool {
	if !strings.Contains(s, ".") || strings.ContainsAny(s, "*> \t\n\r") {
		return false
	}
	for _, p := range strings.Split(s, ".") {
		if p == "" {
			return false
		}
		for _, r := range p {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
				return false
			}
		}
	}
	return true
}
func (c *Contracts) Type(name, provider, digest string) (TypeSpec, error) {
	if c == nil {
		return TypeSpec{}, security.ErrUnavailable
	}
	t, ok := c.types[name]
	if !ok || t.Provider != provider || c.digests[name] != digest {
		return TypeSpec{}, security.ErrDenied
	}
	t.Actions = append([]string(nil), t.Actions...)
	return t, nil
}
func (c *Contracts) rule(caller, actor, aud, op string) (Rule, error) {
	if c == nil {
		return Rule{}, security.ErrUnavailable
	}
	kind := "bootstrap"
	if actor != "" {
		p := strings.Split(actor, ":")
		if len(p) != 2 || !validUUID(p[1]) {
			return Rule{}, security.ErrDenied
		}
		kind = p[0]
	}
	for _, r := range c.rules {
		if r.Caller == caller && r.Audience == aud && r.Operation == op && contains(r.ActorKinds, kind) {
			return r, nil
		}
	}
	return Rule{}, security.ErrDenied
}
func (c *Contracts) action(cl security.Claims, action string) bool {
	r, e := c.rule(cl.Caller, cl.Subject, cl.Audience, cl.Operation)
	if e != nil || !contains(r.Actions, action) {
		return false
	}
	if cl.SourceAudience != "" || cl.SourceOperation != "" {
		return contains(r.DownstreamActions[cl.SourceAudience+":"+cl.SourceOperation], action)
	}
	return true
}

// Authorize implements the Identity policy boundary without calling Identity or
// Access.Check. Resource rights for delegation are evaluated in a DB snapshot.
func (c *Core) Authorize(ctx context.Context, a identity.Authorization) error {
	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return e
		}
		return next.Authorize(ctx, a)
	}
	if e := c.ready(); e != nil {
		return e
	}
	if a.NeedsApproval {
		return security.ErrDenied
	}
	if a.Caller == "" {
		user := strings.TrimPrefix(a.Actor, "user:")
		if !strings.HasPrefix(a.Actor, "user:") {
			return security.ErrDenied
		}
		if a.Operation == "identity.v1.delegations.create" {
			if len(a.Resources) == 0 || len(a.Actions) == 0 {
				return security.ErrDenied
			}
			return c.userScope(ctx, user, a.Resources, a.Actions)
		}
		if contains(c.Contracts.admins, user) {
			if a.Operation == "deployment.approved" {
				if len(a.Resources) != 1 {
					return security.ErrDenied
				}
				for _, d := range c.Contracts.deployments {
					if a.Audience == d.Definition && a.Resources[0] == d.Instance {
						return nil
					}
				}
				return security.ErrDenied
			}
			if a.Operation == "identity.v1.agents.register" {
				if len(a.Resources) != 1 || c.Contracts.agentScopes[a.Resources[0]] == nil {
					return security.ErrDenied
				}
				return nil
			}
			switch a.Operation {
			case "identity.v1.service_accounts.register", "identity.v1.service_accounts.disable", "identity.v1.service_keys.rotate", "identity.v1.keys.revoke", "identity.v1.users.status":
				return nil
			}
		}
		return security.ErrDenied
	}
	r, e := c.Contracts.rule(a.Caller, a.Actor, a.Audience, a.Operation)
	if e != nil {
		return e
	}
	if a.Incoming != nil && (!contains(r.DownstreamFrom, a.Incoming.Audience+":"+a.Incoming.Operation) || a.Actor != a.Incoming.Subject || a.WorkspaceID != a.Incoming.WorkspaceID || a.DelegationID != a.Incoming.DelegationID) {
		return security.ErrDenied
	}
	if len(a.Resources) > 0 || len(a.Actions) > 0 {
		if len(a.Resources) == 0 || len(a.Actions) == 0 || !strings.HasPrefix(a.Actor, "user:") {
			return security.ErrDenied
		}
		for _, action := range a.Actions {
			if !contains(r.Actions, action) {
				return security.ErrDenied
			}
		}
		return c.userScope(ctx, strings.TrimPrefix(a.Actor, "user:"), a.Resources, a.Actions)
	}
	return nil
}
