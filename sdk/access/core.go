// Package access is the Core-owned resource registry and allow-only ACL module.
package access

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/identity"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
)

var ErrDenied = security.ErrDenied
var ErrUnavailable = security.ErrUnavailable
var ErrConflict = errors.New("access conflict")
var ErrValidation = errors.New("invalid access request")

type DomainOwner interface {
	Confirm(context.Context, string, string, string, string) error
}
type Core struct {
	DB        *sql.DB
	Identity  *identity.Core
	Contracts *Contracts
	Domain    DomainOwner
	Now       func() time.Time
}

func (c *Core) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}
func (c *Core) ready() error {
	if c == nil || c.DB == nil || c.Identity == nil || c.Identity.DB != c.DB || c.Contracts == nil {
		return ErrUnavailable
	}
	return nil
}
func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
		} else if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
func uuid() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}
func (c *Core) claims(ctx context.Context, op string) (security.Claims, error) {
	if e := c.ready(); e != nil {
		return security.Claims{}, e
	}
	cl, ok := rpc.VerifiedClaims(ctx)
	if !ok || cl.Audience != "access/v1" || cl.Operation != "access.v1."+op {
		return security.Claims{}, security.ErrUnauthenticated
	}
	rule, e := c.Contracts.rule(cl.Caller, cl.Subject, cl.Audience, cl.Operation)
	if e != nil {
		return security.Claims{}, e
	}
	if cl.SourceAudience != "" || cl.SourceOperation != "" {
		if !contains(rule.DownstreamFrom, cl.SourceAudience+":"+cl.SourceOperation) {
			return security.Claims{}, ErrDenied
		}
	}
	return cl, nil
}

type Resource struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Provider    string `json:"provider_service"`
	OwnerKind   string `json:"owner_kind"`
	OwnerID     string `json:"owner_id"`
	WorkspaceID string `json:"workspace_id,omitempty"`
	ParentID    string `json:"acl_parent_id,omitempty"`
	InheritACL  bool   `json:"inherit_acl"`
	State       string `json:"state"`
	Revision    int64  `json:"policy_revision"`
}
type RegisterRequest struct {
	Type           string `json:"type"`
	ContractDigest string `json:"contract_digest"`
}
type ReserveRequest struct {
	Type        string `json:"type"`
	OwnerKind   string `json:"owner_kind"`
	OwnerID     string `json:"owner_id"`
	WorkspaceID string `json:"workspace_id,omitempty"`
	ParentID    string `json:"acl_parent_id,omitempty"`
	InheritACL  bool   `json:"inherit_acl"`
}
type LifecycleRequest struct {
	ResourceID string `json:"resource_id"`
	Receipt    string `json:"receipt,omitempty"`
}
type CheckRequest struct {
	ResourceID string `json:"resource_id"`
	Action     string `json:"action"`
}
type Decision struct {
	Allowed  bool  `json:"allowed"`
	Revision int64 `json:"policy_revision"`
}
type CheckManyRequest struct {
	Checks []CheckRequest `json:"checks"`
}
type CheckManyResult struct {
	Decisions []Decision `json:"decisions"`
	Revision  int64      `json:"policy_revision"`
}
type ListRequest struct {
	OwnerKind   string `json:"owner_kind,omitempty"`
	OwnerID     string `json:"owner_id,omitempty"`
	WorkspaceID string `json:"workspace_id,omitempty"`
	Type        string `json:"type,omitempty"`
	Action      string `json:"action"`
	Limit       int    `json:"limit"`
	Cursor      string `json:"cursor,omitempty"`
}
type ListResult struct {
	Resources  []Resource `json:"resources"`
	NextCursor string     `json:"next_cursor,omitempty"`
	Revision   int64      `json:"policy_revision"`
}
type GrantRequest struct {
	ResourceID    string     `json:"resource_id"`
	PrincipalKind string     `json:"principal_kind"`
	PrincipalID   string     `json:"principal_id"`
	Action        string     `json:"action"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}
type Grant struct {
	ID string `json:"id"`
	GrantRequest
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}
type RevokeRequest struct {
	GrantID string `json:"grant_id"`
}
type MutationResult struct {
	ResourceID string `json:"resource_id,omitempty"`
	GrantID    string `json:"grant_id,omitempty"`
	State      string `json:"state,omitempty"`
	Revision   int64  `json:"policy_revision"`
}

func readResource(ctx context.Context, t *sql.Tx, id string) (Resource, error) {
	var r Resource
	e := t.QueryRowContext(ctx, `SELECT id,type,provider_service,owner_kind,owner_id,COALESCE(workspace_id::text,''),COALESCE(acl_parent_id::text,''),inherit_acl,state,policy_revision FROM access.resources WHERE id::text=$1`, id).Scan(&r.ID, &r.Type, &r.Provider, &r.OwnerKind, &r.OwnerID, &r.WorkspaceID, &r.ParentID, &r.InheritACL, &r.State, &r.Revision)
	return r, e
}
func (c *Core) readType(ctx context.Context, t *sql.Tx, name string) (TypeSpec, error) {
	var provider, digest string
	if e := t.QueryRowContext(ctx, `SELECT provider_service,contract_digest FROM access.resource_types WHERE type=$1`, name).Scan(&provider, &digest); e != nil {
		return TypeSpec{}, e
	}
	return c.Contracts.Type(name, provider, digest)
}

func (c *Core) snapshot(ctx context.Context, fn func(*sql.Tx, int64) error) error {
	if e := c.ready(); e != nil {
		return e
	}
	t, e := c.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if e != nil {
		return ErrUnavailable
	}
	defer t.Rollback()
	var rev int64
	if e = t.QueryRowContext(ctx, `SELECT revision FROM access.policy_state WHERE singleton`).Scan(&rev); e != nil {
		return ErrUnavailable
	}
	if e = fn(t, rev); e != nil {
		return normalize(e)
	}
	if e = t.Commit(); e != nil {
		return normalize(e)
	}
	return nil
}
func normalize(e error) error {
	if e == nil {
		return nil
	}
	if errors.Is(e, ErrDenied) || errors.Is(e, ErrConflict) || errors.Is(e, ErrValidation) || errors.Is(e, security.ErrUnauthenticated) || errors.Is(e, ErrUnavailable) {
		return e
	}
	return ErrUnavailable
}
func (c *Core) mutation(ctx context.Context, op string, payload any, fn func(*sql.Tx, security.Claims, int64) (MutationResult, error)) (MutationResult, error) {
	var out MutationResult
	cl, e := c.claims(ctx, op)
	if e != nil {
		return out, e
	}
	meta, ok := rpc.Metadata(ctx)
	if !ok || meta.IdempotencyKey == "" || len(meta.IdempotencyKey) > 128 {
		return out, ErrValidation
	}
	raw, e := json.Marshal(payload)
	if e != nil {
		return out, ErrValidation
	}
	raw, e = security.CanonicalJSON(raw)
	if e != nil {
		return out, ErrValidation
	}
	digest := sha256.Sum256(raw)
	t, e := c.DB.BeginTx(ctx, nil)
	if e != nil {
		return out, ErrUnavailable
	}
	defer t.Rollback()
	// One short policy write lock orders lifecycle/grant mutations and revisions.
	var rev int64
	if e = t.QueryRowContext(ctx, `SELECT revision FROM access.policy_state WHERE singleton FOR UPDATE`).Scan(&rev); e != nil {
		return out, ErrUnavailable
	}
	if e = c.live(ctx, t, cl); e != nil {
		return out, normalize(e)
	}
	var stored, result []byte
	e = t.QueryRowContext(ctx, `SELECT request_hash,result FROM access.operations WHERE actor=$1 AND caller=$2 AND operation=$3 AND idempotency_key=$4`, cl.Subject, cl.Caller, op, meta.IdempotencyKey).Scan(&stored, &result)
	if e == nil {
		if hex.EncodeToString(stored) != hex.EncodeToString(digest[:]) {
			return out, ErrConflict
		}
		if json.Unmarshal(result, &out) != nil {
			return out, ErrUnavailable
		}
		return out, nil
	}
	if e != sql.ErrNoRows {
		return out, ErrUnavailable
	}
	out, e = fn(t, cl, rev+1)
	if e != nil {
		return out, normalize(e)
	}
	_, e = t.ExecContext(ctx, `UPDATE access.policy_state SET revision=$1 WHERE singleton`, rev+1)
	if e != nil {
		return out, ErrUnavailable
	}
	out.Revision = rev + 1
	result, e = json.Marshal(out)
	if e != nil {
		return out, ErrUnavailable
	}
	_, e = t.ExecContext(ctx, `INSERT INTO access.operations(actor,caller,operation,idempotency_key,request_hash,resource_id,state,result) VALUES($1,$2,$3,$4,$5,NULLIF($6,'')::uuid,'completed',$7)`, cl.Subject, cl.Caller, op, meta.IdempotencyKey, digest[:], out.ResourceID, result)
	if e != nil {
		return out, ErrUnavailable
	}
	change := op
	if op == "grants.add" {
		if g, ok := payload.(GrantRequest); ok {
			self := g.PrincipalKind+":"+g.PrincipalID == cl.Subject || g.PrincipalKind == "user" && g.PrincipalID == cl.OnBehalfOf
			if !self && g.PrincipalKind == "role" && (g.PrincipalID == "owner" || g.PrincipalID == "admin") {
				user := strings.TrimPrefix(cl.Subject, "user:")
				if cl.OnBehalfOf != "" {
					user = cl.OnBehalfOf
				}
				var role string
				if user != "" && t.QueryRowContext(ctx, `SELECT role FROM identity.memberships WHERE workspace_id=(SELECT workspace_id FROM access.resources WHERE id=$1) AND user_id::text=$2 AND revoked_at IS NULL`, g.ResourceID, user).Scan(&role) == nil {
					self = role == g.PrincipalID
				}
			}
			if !self && g.PrincipalKind == "group" {
				user := actorUser(cl)
				if user != "" {
					if err := t.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity.group_members WHERE group_id::text=$1 AND user_id::text=$2)`, g.PrincipalID, user).Scan(&self); err != nil {
						return out, ErrUnavailable
					}
				}
			}
			if self {
				change = "self_grant"
			}
		}
	}
	details := map[string]any{"state": out.State}
	switch q := payload.(type) {
	case GrantRequest:
		details["grant"] = q
	case RegisterRequest:
		details["type"], details["contract_digest"] = q.Type, q.ContractDigest
	}
	changeJSON, e := json.Marshal(details)
	if e != nil {
		return out, ErrUnavailable
	}
	_, e = t.ExecContext(ctx, `INSERT INTO access.policy_audit(actor,caller,on_behalf_of,operation,resource_id,policy_revision,change_kind,grant_id,change) VALUES($1,$2,NULLIF($3,'')::uuid,$4,NULLIF($5,'')::uuid,$6,$7,NULLIF($8,'')::uuid,$9)`, cl.Subject, cl.Caller, cl.OnBehalfOf, op, out.ResourceID, rev+1, change, out.GrantID, changeJSON)
	if e != nil {
		return out, ErrUnavailable
	}
	if e = t.Commit(); e != nil {
		return out, ErrUnavailable
	}
	return out, nil
}
func actorUser(cl security.Claims) string {
	if cl.OnBehalfOf != "" {
		return cl.OnBehalfOf
	}
	if strings.HasPrefix(cl.Subject, "user:") {
		return strings.TrimPrefix(cl.Subject, "user:")
	}
	return ""
}
