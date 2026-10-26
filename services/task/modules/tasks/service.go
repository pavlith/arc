// Package tasks implements only the M0 workspace Tasks proof service.
package tasks

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/module"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/identity"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
	"gorm.io/gorm"
)

type Service struct {
	GormDB   *gorm.DB
	Identity identity.Client
	Contract *contract.Compiled
	Check    func(context.Context, string, string) error
}

func NewID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func unavailable(e error) error {
	if e == nil {
		return nil
	}
	return rpc.SecurityError(security.ErrUnavailable)
}
func (s *Service) ID() string { return "task" }

// Register binds every approved Tasks v1 operation; protected resource checks
// happen before command replay, including on idempotent retries.
func (s *Service) Register(r *module.Registry) error {
	if s == nil || s.GormDB == nil || s.Contract == nil || s.Check == nil {
		return security.ErrUnavailable
	}
	policy := module.Policy{Resource: s.Authorize}

	store := events.Store{DB: s.GormDB}
	if err := module.BindCommand(r, taskv1.Create, policy, store, s.createGORM); err != nil {
		return err
	}
	if err := module.BindCommand(r, taskv1.Admin, policy, store, s.grantsGORM); err != nil {
		return err
	}

	if err := module.BindQuery(r, taskv1.Get, policy, s.get); err != nil {
		return err
	}
	return module.BindQuery(r, taskv1.List, policy, s.list)
}

// Authorize verifies the actual task/root/workspace relation before Access.Check.
// This runs before Command replay, so revocation also denies cached results.
func (s *Service) Authorize(ctx context.Context, root, action string) error {
	return s.authorizeGORM(ctx, root, action)
}

func (s *Service) get(ctx context.Context, q GetRequest) (Task, error) {
	return s.getGORM(ctx, q)
}
func (s *Service) list(ctx context.Context, q ListRequest) (ListResponse, error) {
	return s.listGORM(ctx, q)
}

// PrepareRoot commits the domain binding before issuing its activation receipt.
// Caller must first reserve the root through the approved Access lifecycle.
func (s *Service) PrepareRoot(ctx context.Context, q Scope, key ed25519.PrivateKey, kid, provider string) (string, error) {
	return s.prepareRootGORM(ctx, q, key, kid, provider)
}
func (s *Service) ActivateRoot(ctx context.Context, q Scope) error {
	return s.activateRootGORM(ctx, q)
}

// GrantCommand is an internal provisioning operation; HTTP exposure is disabled.

func (s *Service) grantsAccess(ctx context.Context, q GrantCommand) (access.MutationResult, error) {
	op := "grants.add"
	if q.GrantID != "" {
		op = "grants.revoke"
	}
	client := s.Identity
	meta, _ := rpc.Metadata(ctx)
	client.IdempotencyKey = "task.grants:" + meta.IdempotencyKey
	ctx, e := InvocationContext(ctx, client, identity.Target{Audience: "access/v1", Operation: "access.v1." + op})
	if e != nil {
		return access.MutationResult{}, e
	}
	ac := &access.Client{RPC: client.RPC}
	if q.GrantID != "" {
		return ac.RevokeGrant(ctx, access.RevokeRequest{GrantID: q.GrantID})
	}
	return ac.AddGrant(ctx, access.GrantRequest{ResourceID: q.RootID, PrincipalKind: q.PrincipalKind, PrincipalID: q.PrincipalID, Action: q.Action})
}
