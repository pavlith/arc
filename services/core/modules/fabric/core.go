// Package fabric owns approved contracts; Micro announcements are never identity.
package fabric

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/identity"
	"gorm.io/gorm"
)

type EventSubscription struct {
	Provider string `json:"provider"`
	Digest   string `json:"digest"`
	Subject  string `json:"subject"`
	Durable  string `json:"durable"`
}

type Installation struct {
	Subscriptions []EventSubscription `json:"subscriptions,omitempty"`
	Publisher     string              `json:"publisher"`
	Account       string              `json:"service_account"`
	Deployment    string              `json:"deployment"`
	Artifact      contract.Artifact   `json:"artifact"`
	Subjects      []string            `json:"subjects"`
	Policy        access.Approved     `json:"policy"`
}
type SignedInstallation struct {
	Payload   json.RawMessage `json:"payload"`
	Signature []byte          `json:"signature"`
}
type Core struct {
	GormDB      *gorm.DB
	Identity    *identity.Core
	ApprovalKey ed25519.PublicKey
	// Bootstrap contains only locally pinned Identity/control policy, never business types.
	Bootstrap     []access.Approved
	SnapshotKey   ed25519.PrivateKey
	SnapshotKid   string
	RouteTrustKey ed25519.PrivateKey
	RoutesChanged func()
}

func (c *Core) ready() error {
	return c.readyGORM()
}
func has(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func (c *Core) verify(s SignedInstallation) (Installation, *contract.Compiled, error) {
	var i Installation
	raw, e := security.CanonicalJSON(s.Payload)
	if e != nil || !ed25519.Verify(c.ApprovalKey, raw, s.Signature) {
		return i, nil, security.ErrUnauthenticated
	}
	if contract.Strict(raw, &i) != nil || i.Publisher == "" || i.Account == "" || i.Deployment == "" {
		return i, nil, contract.ErrInvalid
	}
	compiled, e := contract.Compile(i.Artifact)
	if e != nil {
		return i, nil, e
	}
	policy, e := access.NewContracts(c.ApprovalKey, []access.Approved{i.Policy})
	if e != nil {
		return i, nil, e
	}
	var a access.Approval
	if contract.Strict(i.Policy.Payload, &a) != nil {
		return i, nil, contract.ErrInvalid
	}
	if len(a.ContractDigests) != len(compiled.Manifest.Resources) {
		return i, nil, security.ErrDenied
	}
	if len(a.AdminUsers) > 0 || len(a.AgentScopes) > 0 || len(a.Deployments) > 0 || len(a.Types) != len(compiled.Manifest.Resources) {
		return i, nil, security.ErrDenied
	}
	declared := map[string]bool{}
	for _, r := range compiled.Manifest.Resources {
		typ, e := policy.Type(r.Type, i.Account, compiled.Digest)
		if e != nil || !reflect.DeepEqual(typ.Actions, r.Actions) || typ.ShareAction != r.ShareAction || typ.CreateAction != r.CreateAction || typ.DeleteAction != r.DeleteAction || typ.AllowInheritance != r.AllowInheritance {
			return i, nil, security.ErrDenied
		}
		for _, act := range r.Actions {
			declared[act] = true
		}
	}
	if len(i.Subjects) != len(compiled.Manifest.Operations) {
		return i, nil, security.ErrDenied
	}
	seen := map[string]bool{}
	for _, s := range i.Subjects {
		if seen[s] {
			return i, nil, security.ErrDenied
		}
		seen[s] = true
	}
	audience := fmt.Sprintf("%s/v%d", compiled.Manifest.Service.Name, compiled.Manifest.Service.APIMajor)
	for _, o := range compiled.Manifest.Operations {
		if !seen[o.Subject] {
			return i, nil, security.ErrDenied
		}
	}
	for _, r := range a.Rules {
		// Own-service callers are explicit; downstream Access rules bind exact source operations.
		if r.Audience == audience {
			o, e := compiled.Operation(r.Operation)
			if e != nil || len(r.Actions) != 1 || r.Actions[0] != o.Auth.Action {
				return i, nil, security.ErrDenied
			}
		} else if r.Audience == "access/v1" && r.Caller == i.Account {
			if !has([]string{"access.v1.check", "access.v1.check_many", "access.v1.list_accessible_roots", "access.v1.resources.reserve", "access.v1.resources.activate", "access.v1.resources.abort", "access.v1.resources.begin_delete", "access.v1.resources.finalize_delete", "access.v1.resource_types.register", "access.v1.grants.add", "access.v1.grants.revoke"}, r.Operation) {
				return i, nil, security.ErrDenied
			}
			if len(r.DownstreamFrom) == 0 {
				return i, nil, security.ErrDenied
			}
			for _, src := range r.DownstreamFrom {
				found := false
				for _, o := range compiled.Manifest.Operations {
					if src == audience+":"+o.ID {
						found = true
						for _, act := range r.DownstreamActions[src] {
							if act != o.Auth.Action && !(o.Auth.Mode == "resource" && o.Auth.Action == "access.grants.manage" && has(typesActions(compiled, o.Auth.ResourceType), act)) {
								return i, nil, security.ErrDenied
							}
						}
					}
				}
				if !found {
					return i, nil, security.ErrDenied
				}
			}
		} else {
			return i, nil, security.ErrDenied
		}
		for _, act := range r.Actions {
			if !declared[act] {
				return i, nil, security.ErrDenied
			}
		}
	}
	for _, sub := range i.Subscriptions {
		if sub.Provider == "" || len(sub.Digest) != 64 || sub.Subject == "" || sub.Durable == "" || strings.ContainsAny(sub.Durable, ".*> /\\") || !regexp.MustCompile(`^evt\.[a-z][a-z0-9_-]*\.[a-z][a-z0-9_-]*\.[a-z][a-z0-9_-]*\.v[1-9][0-9]*$`).MatchString(sub.Subject) {
			return i, nil, contract.ErrInvalid
		}
	}
	return i, compiled, nil
}

// Approve is an in-process installer boundary requiring a pinned operator signature.
// It atomically installs Access resource types and the immutable service contract.
func (c *Core) Approve(ctx context.Context, s SignedInstallation) (string, error) {
	return c.approveGORM(ctx, s)
}
func (c *Core) LoadAccess(ctx context.Context) (*access.Contracts, error) {
	return c.loadAccessGORM(ctx)
}

// Revocation is an operator-signed command; no user or service can revoke contracts.
type Revocation struct {
	Digest string `json:"digest"`
	Revoke bool   `json:"revoke"`
}

func (c *Core) Revoke(ctx context.Context, raw []byte, sig []byte) error {
	return c.revokeGORM(ctx, raw, sig)
}
func (c *Core) active(ctx context.Context, account, digest string) (*contract.Compiled, error) {
	return c.activeGORM(ctx, account, digest)
}

var _ access.ContractSource = (*Core)(nil)

func typesActions(m *contract.Compiled, typ string) []string {
	for _, r := range m.Manifest.Resources {
		if r.Type == typ {
			return r.Actions
		}
	}
	return nil
}
