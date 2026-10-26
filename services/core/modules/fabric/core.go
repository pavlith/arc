// Package fabric owns approved contracts; Micro announcements are never identity.
package fabric

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/pavlith/arc/pkgs/contract"
	"github.com/pavlith/arc/pkgs/security"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/identity"
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
	DB          *sql.DB
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
	if c == nil || c.DB == nil || c.Identity == nil || c.Identity.DB != c.DB || len(c.ApprovalKey) != 32 {
		return security.ErrUnavailable
	}
	return nil
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
	if e := c.ready(); e != nil {
		return "", e
	}
	i, m, e := c.verify(s)
	if e != nil {
		return "", e
	}
	t, e := c.DB.BeginTx(ctx, nil)
	if e != nil {
		return "", security.ErrUnavailable
	}
	defer t.Rollback()
	var rev int64
	if e = t.QueryRowContext(ctx, `SELECT revision FROM fabric.route_state WHERE singleton FOR UPDATE`).Scan(&rev); e != nil {
		return "", security.ErrUnavailable
	}
	var definition, deployment string
	if e = t.QueryRowContext(ctx, `SELECT service_definition,deployment FROM identity.service_accounts WHERE id::text=$1 AND disabled_at IS NULL`, i.Account).Scan(&definition, &deployment); e != nil {
		return "", security.ErrDenied
	}
	if definition != m.Manifest.Service.Name || deployment != i.Deployment {
		return "", security.ErrDenied
	}
	_, e = t.ExecContext(ctx, `INSERT INTO fabric.definitions(name,publisher) VALUES($1,$2) ON CONFLICT DO NOTHING`, definition, i.Publisher)
	if e != nil {
		return "", security.ErrUnavailable
	}
	var publisher string
	if e = t.QueryRowContext(ctx, `SELECT publisher FROM fabric.definitions WHERE name=$1`, definition).Scan(&publisher); e != nil || publisher != i.Publisher {
		return "", security.ErrDenied
	}
	var old []byte
	var revoked sql.NullTime
	e = t.QueryRowContext(ctx, `SELECT installation,revoked_at FROM fabric.contracts WHERE digest=$1`, m.Digest).Scan(&old, &revoked)
	if e == nil {
		oldCanonical, oldErr := security.CanonicalJSON(old)
		newCanonical, newErr := security.CanonicalJSON(s.Payload)
		if oldErr != nil || newErr != nil || string(oldCanonical) != string(newCanonical) || revoked.Valid {
			return "", identity.ErrConflict
		}
		return m.Digest, nil
	}
	if e != sql.ErrNoRows {
		return "", security.ErrUnavailable
	}
	var currentDigest string
	e = t.QueryRowContext(ctx, `SELECT digest FROM fabric.contracts WHERE service_name=$1 AND api_major=$2 AND revoked_at IS NULL`, definition, m.Manifest.Service.APIMajor).Scan(&currentDigest)
	if e == nil {
		return "", identity.ErrConflict
	}
	if e != sql.ErrNoRows {
		return "", security.ErrUnavailable
	}
	var previous SignedInstallation
	e = t.QueryRowContext(ctx, `SELECT installation,signature FROM fabric.contracts WHERE service_name=$1 AND api_major=$2 ORDER BY approved_at DESC LIMIT 1`, definition, m.Manifest.Service.APIMajor).Scan(&previous.Payload, &previous.Signature)
	if e == nil {
		prior, _, err := c.verify(previous)
		if err != nil || !contract.Compatible(prior.Artifact, i.Artifact) {
			return "", contract.ErrInvalid
		}
	} else if e != sql.ErrNoRows {
		return "", security.ErrUnavailable
	}
	// Reject catalog ambiguities before publishing a new approval.
	candidates := append([]access.Approved(nil), c.Bootstrap...)
	rows, err := t.QueryContext(ctx, `SELECT installation,signature FROM fabric.contracts WHERE revoked_at IS NULL`)
	if err != nil {
		return "", security.ErrUnavailable
	}
	for rows.Next() {
		var prior SignedInstallation
		if rows.Scan(&prior.Payload, &prior.Signature) != nil {
			rows.Close()
			return "", security.ErrUnavailable
		}
		installed, _, err := c.verify(prior)
		if err != nil {
			rows.Close()
			return "", err
		}
		candidates = append(candidates, installed.Policy)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", security.ErrUnavailable
	}
	candidates = append(candidates, i.Policy)
	if _, err = access.NewContracts(c.ApprovalKey, candidates); err != nil {
		return "", security.ErrDenied
	}
	artifact, _ := json.Marshal(i.Artifact)
	_, e = t.ExecContext(ctx, `INSERT INTO fabric.contracts(digest,service_name,api_major,artifact,installation,signature) VALUES($1,$2,$3,$4,$5,$6)`, m.Digest, definition, m.Manifest.Service.APIMajor, artifact, s.Payload, s.Signature)
	if e != nil {
		return "", security.ErrUnavailable
	}
	_, e = t.ExecContext(ctx, `INSERT INTO fabric.deployments(service_account_id,digest,subjects) VALUES($1,$2,$3)`, i.Account, m.Digest, i.Subjects)
	if e != nil {
		return "", security.ErrUnavailable
	}
	var policyRev int64
	if e = t.QueryRowContext(ctx, `UPDATE access.policy_state SET revision=revision+1 WHERE singleton RETURNING revision`).Scan(&policyRev); e != nil {
		return "", security.ErrUnavailable
	}
	for _, r := range m.Manifest.Resources {
		var p string
		e = t.QueryRowContext(ctx, `SELECT provider_service FROM access.resource_types WHERE type=$1`, r.Type).Scan(&p)
		if e == nil {
			var oldActions []byte
			var share, create, del string
			var inherit bool
			if e = t.QueryRowContext(ctx, `SELECT array_to_json(actions),share_action,create_action,delete_action,allow_inheritance FROM access.resource_types WHERE type=$1`, r.Type).Scan(&oldActions, &share, &create, &del, &inherit); e != nil {
				return "", security.ErrUnavailable
			}
			var acts []string
			if json.Unmarshal(oldActions, &acts) != nil {
				return "", security.ErrUnavailable
			}
			if p != i.Account || !reflect.DeepEqual(acts, r.Actions) || share != r.ShareAction || create != r.CreateAction || del != r.DeleteAction || inherit != r.AllowInheritance {
				return "", security.ErrDenied
			}
			if _, e = t.ExecContext(ctx, `UPDATE access.resource_types SET contract_digest=$2 WHERE type=$1`, r.Type, m.Digest); e != nil {
				return "", security.ErrUnavailable
			}
			continue
		}
		if e != sql.ErrNoRows {
			return "", security.ErrUnavailable
		}
		_, e = t.ExecContext(ctx, `INSERT INTO access.resource_types(type,provider_service,contract_digest,actions,share_action,create_action,delete_action,allow_inheritance) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, r.Type, i.Account, m.Digest, r.Actions, r.ShareAction, r.CreateAction, r.DeleteAction, r.AllowInheritance)
		if e != nil {
			return "", security.ErrUnavailable
		}
	}
	_, e = t.ExecContext(ctx, `INSERT INTO access.policy_audit(actor,caller,operation,policy_revision,change_kind,change) VALUES($1,$2,'fabric.approve',$3,'contract_approved',jsonb_build_object('digest',$4::text))`, "operator:"+publisher, i.Account, policyRev, m.Digest)
	if e != nil {
		return "", security.ErrUnavailable
	}
	if _, e = t.ExecContext(ctx, `UPDATE fabric.route_state SET revision=revision+1 WHERE singleton`); e != nil {
		return "", security.ErrUnavailable
	}
	if e = t.Commit(); e != nil {
		return "", security.ErrUnavailable
	}
	if c.RoutesChanged != nil {
		c.RoutesChanged()
	}
	return m.Digest, nil
}
func (c *Core) LoadAccess(ctx context.Context) (*access.Contracts, error) {
	if e := c.ready(); e != nil {
		return nil, e
	}
	for _, signed := range c.Bootstrap {
		var bootstrap access.Approval
		if contract.Strict(signed.Payload, &bootstrap) != nil || len(bootstrap.Types) != 0 {
			return nil, security.ErrDenied
		}
		for _, rule := range bootstrap.Rules {
			if rule.Audience != "identity/v1" && !(rule.Audience == "fabric/v1" && rule.Operation == "fabric.v1.routes") {
				return nil, security.ErrDenied
			}
		}
	}
	approvals := append([]access.Approved(nil), c.Bootstrap...)
	rows, e := c.DB.QueryContext(ctx, `SELECT installation,signature FROM fabric.contracts WHERE revoked_at IS NULL ORDER BY digest`)
	if e != nil {
		return nil, security.ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var s SignedInstallation
		if e = rows.Scan(&s.Payload, &s.Signature); e != nil {
			return nil, security.ErrUnavailable
		}
		i, _, e := c.verify(s)
		if e != nil {
			return nil, e
		}
		approvals = append(approvals, i.Policy)
	}
	if e = rows.Err(); e != nil {
		return nil, security.ErrUnavailable
	}
	return access.NewContracts(c.ApprovalKey, approvals)
}

// Revocation is an operator-signed command; no user or service can revoke contracts.
type Revocation struct {
	Digest string `json:"digest"`
	Revoke bool   `json:"revoke"`
}

func (c *Core) Revoke(ctx context.Context, raw []byte, sig []byte) error {
	if e := c.ready(); e != nil {
		return e
	}
	canonical, e := security.CanonicalJSON(raw)
	if e != nil || !ed25519.Verify(c.ApprovalKey, canonical, sig) {
		return security.ErrUnauthenticated
	}
	var q Revocation
	if contract.Strict(raw, &q) != nil || !q.Revoke {
		return contract.ErrInvalid
	}
	t, e := c.DB.BeginTx(ctx, nil)
	if e != nil {
		return security.ErrUnavailable
	}
	defer t.Rollback()
	if _, e = t.ExecContext(ctx, `SELECT revision FROM fabric.route_state WHERE singleton FOR UPDATE`); e != nil {
		return security.ErrUnavailable
	}
	var account string
	e = t.QueryRowContext(ctx, `UPDATE fabric.contracts SET revoked_at=now() WHERE digest=$1 AND revoked_at IS NULL RETURNING installation->>'service_account'`, q.Digest).Scan(&account)
	if e == sql.ErrNoRows {
		return nil
	}
	if e != nil {
		return security.ErrUnavailable
	}
	var rev int64
	if e = t.QueryRowContext(ctx, `UPDATE access.policy_state SET revision=revision+1 WHERE singleton RETURNING revision`).Scan(&rev); e != nil {
		return security.ErrUnavailable
	}
	if _, e = t.ExecContext(ctx, `INSERT INTO access.policy_audit(actor,caller,operation,policy_revision,change_kind,change) VALUES('operator', $1,'fabric.revoke',$2,'contract_revoked',jsonb_build_object('digest',$3::text))`, account, rev, q.Digest); e != nil {
		return security.ErrUnavailable
	}
	if _, e = t.ExecContext(ctx, `UPDATE fabric.route_state SET revision=revision+1 WHERE singleton`); e != nil {
		return security.ErrUnavailable
	}
	if e = t.Commit(); e != nil {
		return e
	}
	if c.RoutesChanged != nil {
		c.RoutesChanged()
	}
	return nil
}
func (c *Core) active(ctx context.Context, account, digest string) (*contract.Compiled, error) {
	if e := c.ready(); e != nil {
		return nil, e
	}
	var s SignedInstallation
	e := c.DB.QueryRowContext(ctx, `SELECT c.installation,c.signature FROM fabric.contracts c JOIN fabric.deployments d ON d.digest=c.digest JOIN identity.service_accounts a ON a.id=d.service_account_id WHERE c.digest=$1 AND d.service_account_id::text=$2 AND c.revoked_at IS NULL AND a.disabled_at IS NULL`, digest, account).Scan(&s.Payload, &s.Signature)
	if e == sql.ErrNoRows {
		return nil, security.ErrDenied
	}
	if e != nil {
		return nil, security.ErrUnavailable
	}
	i, m, e := c.verify(s)
	if e != nil {
		return nil, e
	}
	if i.Account != account {
		return nil, security.ErrDenied
	}
	return m, nil
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
