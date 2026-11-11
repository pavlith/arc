package identity

import (
	"context"
	"time"

	"github.com/pavlith/arc/sdk"
)

type AccountSession struct {
	Session
	CreatedAt time.Time `json:"created_at"`
	Channel   string    `json:"channel"`
}

type AccountSessionRevoke struct {
	ID string `json:"id"`
}

type AccountPasswordChange struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (c *Core) accountSessions(ctx context.Context, user string, q Page) ([]AccountSession, error) {
	if q.After != "" && !productID.MatchString(q.After) {
		return nil, productInvalid()
	}
	out := []AccountSession{}
	err := c.db(ctx).WithContext(ctx).Raw(`SELECT id,user_id,expires_at,created_at,auth_channel AS channel
		FROM identity_sessions WHERE user_id=? AND revoked_at IS NULL AND expires_at>?
		AND id>? ORDER BY id LIMIT 100`, user, c.now(), q.After).Scan(&out).Error
	if err != nil {
		return nil, ErrUnavailable
	}
	return out, nil
}

func (c *Core) bindAccount(s *sdk.Service) error {
	if err := bindProductRead(s, c, "account.sessions.list", c.accountSessions); err != nil {
		return err
	}
	if err := bindOperation(s, c, "product.account.sessions.revoke", true, func(ctx context.Context, req ProductRequest[AccountSessionRevoke]) (Empty, error) {
		user, err := c.user(ctx, req.Session)
		if err != nil {
			return Empty{}, err
		}
		if !productID.MatchString(req.Input.ID) {
			return Empty{}, productInvalid()
		}
		return runCommand(ctx, c, user, "identity.v1.product.account.sessions.revoke", nil, func(ctx context.Context) (Empty, error) {
			return Empty{}, c.RevokeSession(ctx, req.Session, req.Input.ID)
		})
	}); err != nil {
		return err
	}
	// Passwords and one-time authentication results never enter command replay
	// storage. A successful change revokes the initiating session as well.
	return bindOperation(s, c, "product.account.password.change", false, func(ctx context.Context, req ProductRequest[AccountPasswordChange]) (Empty, error) {
		return Empty{}, c.ChangePassword(ctx, req.Session, req.Input.CurrentPassword, req.Input.NewPassword)
	})
}
