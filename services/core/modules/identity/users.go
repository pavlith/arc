package identity

import (
	"context"
	"net/mail"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk"
)

type ManagedUser struct {
	Profile
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type UserPage struct {
	Page
	Email  string `json:"email,omitempty"`
	Status string `json:"status,omitempty"`
}

type UserStatusChange struct {
	UserID string `json:"user_id"`
	Status string `json:"status"`
}

func (c *Core) users(ctx context.Context, user string, q UserPage) ([]ManagedUser, error) {
	if err := c.allow(ctx, Authorization{Actor: "user:" + user, Audience: "identity/v1", Operation: "identity.v1.product.users.list"}); err != nil {
		return nil, err
	}
	q.Email = strings.ToLower(strings.TrimSpace(q.Email))
	if q.Email != "" {
		address, err := mail.ParseAddress(q.Email)
		if err != nil || address.Address != q.Email || len(q.Email) > 254 {
			return nil, productInvalid()
		}
	}
	if q.After != "" && !productID.MatchString(q.After) || q.Status != "" && q.Status != "active" && q.Status != "disabled" {
		return nil, productInvalid()
	}
	out := []ManagedUser{}
	err := c.db(ctx).WithContext(ctx).Raw(`SELECT id,email,status,created_at FROM identity_users
		WHERE id>? AND (?='' OR email=?) AND (?='' OR status=?) ORDER BY id LIMIT 100`,
		q.After, q.Email, q.Email, q.Status, q.Status).Scan(&out).Error
	if err != nil {
		return nil, ErrUnavailable
	}
	return out, nil
}

func (c *Core) bindUsers(s *sdk.Service) error {
	if err := bindProductRead(s, c, "users.list", c.users); err != nil {
		return err
	}
	const op = "identity.v1.product.users.status"
	return bindOperation(s, c, "product.users.status", true, func(ctx context.Context, req ProductRequest[UserStatusChange]) (Empty, error) {
		user, err := c.user(ctx, req.Session)
		if err != nil {
			return Empty{}, err
		}
		q := req.Input
		if !productID.MatchString(q.UserID) || q.Status != "active" && q.Status != "disabled" {
			return Empty{}, productInvalid()
		}
		return runCommand(ctx, c, user, op, func(ctx context.Context) error {
			return c.allow(ctx, Authorization{Actor: "user:" + user.UserID, Audience: "identity/v1", Operation: op})
		}, func(ctx context.Context) (Empty, error) {
			// The browser administration surface must not lock out its own operator.
			if q.UserID == user.UserID && q.Status == "disabled" {
				return Empty{}, ErrDenied
			}
			return Empty{}, c.SetUserDisabled(ctx, req.Session, q.UserID, q.Status == "disabled")
		})
	})
}
