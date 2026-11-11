package access

import (
	"context"
	"time"

	"gorm.io/gorm"
)

// ValidateUsers checks references using live workspace membership and permission,
// without returning profile data or trusting a foreign owner's user database.
func (c *Core) ValidateUsers(ctx context.Context, q ValidateUsersRequest) (ValidateUsersResult, error) {
	if c != nil && c.ContractSource != nil {
		next, err := c.resolveContracts(ctx)
		if err != nil {
			return ValidateUsersResult{}, err
		}
		return next.ValidateUsers(ctx, q)
	}
	cl, err := c.claims(ctx, "principals.validate_users")
	if err != nil {
		return ValidateUsersResult{}, err
	}
	if !validUUID(q.ResourceID) || !namespaced(q.ActorAction) || !namespaced(q.UserAction) || len(q.UserIDs) > 100 {
		return ValidateUsersResult{}, ErrValidation
	}
	seen := map[string]bool{}
	for _, id := range q.UserIDs {
		if !validUUID(id) || seen[id] {
			return ValidateUsersResult{}, ErrValidation
		}
		seen[id] = true
	}
	fixed := *c
	at := c.now()
	fixed.Now = func() time.Time { return at }
	err = fixed.snapshotGORM(ctx, func(tx *gorm.DB, _ int64) error {
		if err := fixed.liveGORM(tx, cl); err != nil {
			return err
		}
		allowed, err := fixed.evaluateGORM(tx, cl, CheckRequest{ResourceID: q.ResourceID, Action: q.ActorAction})
		if err != nil {
			return err
		}
		if !allowed {
			return ErrDenied
		}
		resource, err := readResourceGORM(tx, q.ResourceID)
		if err != nil {
			return err
		}
		spec, err := fixed.readTypeGORM(tx, resource.Type)
		if err != nil {
			return err
		}
		if !contains(spec.Actions, q.UserAction) {
			return ErrDenied
		}
		parents, valid, err := chainGORM(tx, resource)
		if err != nil {
			return err
		}
		if !valid {
			return ErrDenied
		}
		for _, id := range q.UserIDs {
			if err := fixed.principalGORM(tx, resource, "user", id); err != nil {
				return err
			}
			ok, err := fixed.userPermissionGORM(tx, id, resource, parents, q.UserAction)
			if err != nil {
				return err
			}
			if !ok {
				return ErrDenied
			}
		}
		return nil
	})
	if err != nil {
		return ValidateUsersResult{}, err
	}
	return ValidateUsersResult{Valid: true}, nil
}
