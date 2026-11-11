package identity

import (
	"context"
	"encoding/json"

	"github.com/pavlith/arc/sdk/resource"
)

// avatarRef accepts only a short-lived Files owner/session-bound attestation.
// Serving the referenced image always performs fresh Files authorization.
func (c *Core) avatarRef(ctx context.Context, user Session, receipt string) (*resource.Ref, error) {
	if receipt == "" {
		return nil, nil
	}
	env, err := resource.ParseAvatar(receipt)
	if err != nil {
		return nil, ErrDenied
	}
	claim := env.Claim
	if claim.UserID != user.UserID || claim.SessionID != user.ID {
		return nil, ErrDenied
	}
	var provider bool
	if err := c.db(ctx).Raw("SELECT EXISTS(SELECT 1 FROM identity_service_accounts WHERE id=? AND service_definition='files' AND disabled_at IS NULL)", claim.Provider).Row().Scan(&provider); err != nil {
		return nil, ErrUnavailable
	}
	if !provider {
		return nil, ErrDenied
	}
	key, err := c.CallerKey(ctx, claim.Provider, claim.Kid)
	if err != nil || key.Revoked || c.now().Before(key.NotBefore) || !c.now().Before(key.ExpiresAt) {
		return nil, ErrDenied
	}
	if err := resource.VerifyAvatar(key.Public, env, c.now()); err != nil {
		return nil, ErrDenied
	}
	return &claim.Ref, nil
}
func avatarPath(raw *string) *string {
	if raw == nil {
		return nil
	}
	var ref resource.Ref
	if json.Unmarshal([]byte(*raw), &ref) != nil || !ref.Valid() || ref.Kind != "file" || ref.WorkspaceID != "" {
		return nil
	}
	path := "/api/v1/files/personal/roots/" + ref.RootID + "/files/" + ref.ID + "/image"
	return &path
}
