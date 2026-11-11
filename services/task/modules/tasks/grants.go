package tasks

import (
	"context"

	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/identity"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
)

func (s *Service) listGrants(ctx context.Context, q taskv1.GrantsRequest) (taskv1.GrantsResult, error) {
	ctx, err := InvocationContext(ctx, s.Identity, identity.Target{Audience: "access/v1", Operation: "access.v1.grants.list"})
	if err != nil {
		return taskv1.GrantsResult{}, err
	}
	result, err := (&access.Client{RPC: s.Identity.RPC}).ListGrants(ctx, access.ListGrantsRequest{
		ResourceID: q.RootID, Cursor: q.Cursor, Limit: q.Limit,
	})
	if err != nil {
		return taskv1.GrantsResult{}, err
	}
	if result.ResourceID != q.RootID {
		return taskv1.GrantsResult{}, security.ErrUnavailable
	}
	out := taskv1.GrantsResult{ResourceID: result.ResourceID, Grants: []taskv1.RootGrant{}, NextCursor: result.NextCursor, Revision: result.Revision}
	for _, grant := range result.Grants {
		if grant.ResourceID != q.RootID {
			return taskv1.GrantsResult{}, security.ErrUnavailable
		}
		out.Grants = append(out.Grants, taskv1.RootGrant{
			ID: grant.ID, PrincipalKind: grant.PrincipalKind, PrincipalID: grant.PrincipalID,
			Action: grant.Action, ExpiresAt: grant.ExpiresAt,
		})
	}
	return out, nil
}
