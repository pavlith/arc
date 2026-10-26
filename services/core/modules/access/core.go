// Package access is the Core-owned resource registry and allow-only ACL module.
package access

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/identity"
	"gorm.io/gorm"
)

var ErrDenied = security.ErrDenied
var ErrUnavailable = security.ErrUnavailable
var ErrConflict = errors.New("access conflict")
var ErrValidation = errors.New("invalid access request")

type DomainOwner interface {
	Confirm(context.Context, string, string, string, string) error
}

// ContractSource provides a fresh, fail-closed approved catalog per request.
type ContractSource interface {
	LoadAccess(context.Context) (*Contracts, error)
}
type Core struct {
	ContractSource ContractSource

	GormDB    *gorm.DB
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
	if c == nil || c.Identity == nil || (c.Contracts == nil && c.ContractSource == nil) {
		return ErrUnavailable
	}
	if c.GormDB == nil || c.Identity.GormDB != c.GormDB {
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

func normalize(e error) error {
	if e == nil {
		return nil
	}
	if errors.Is(e, ErrDenied) || errors.Is(e, ErrConflict) || errors.Is(e, ErrValidation) || errors.Is(e, security.ErrUnauthenticated) || errors.Is(e, ErrUnavailable) {
		return e
	}
	return ErrUnavailable
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

func (c *Core) resolveContracts(ctx context.Context) (*Core, error) {
	if e := c.ready(); e != nil {
		return nil, e
	}
	contracts, e := c.ContractSource.LoadAccess(ctx)
	if e != nil || contracts == nil {
		return nil, ErrUnavailable
	}
	next := *c
	next.Contracts = contracts
	next.ContractSource = nil
	return &next, nil
}
