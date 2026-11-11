package identity

import (
	"context"
	"errors"
	"strings"

	"github.com/pavlith/arc/sdk/database"
	"gorm.io/gorm"
)

type RegisterInvitedRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

type RegisterInvitedResult struct {
	UserID       string `json:"user_id"`
	WorkspaceID  string `json:"workspace_id"`
	RecoveryCode string `json:"recovery_code"`
}

// RegisterInvited creates credentials and consumes the invitation in one owner
// transaction. It returns the recovery code once; sign-in remains a separate step.
func (c *Core) RegisterInvited(ctx context.Context, q RegisterInvitedRequest) (RegisterInvitedResult, error) {
	var zero RegisterInvitedResult
	if err := c.rate(ctx, "register_invited:global"); err != nil {
		return zero, err
	}
	tokenHash, err := invitationHash(q.Token)
	if err != nil {
		return zero, ErrDenied
	}
	email := strings.ToLower(strings.TrimSpace(q.Email))
	if len(email) > 254 || !strings.Contains(email, "@") {
		return zero, ErrDenied
	}
	encoded, err := HashPassword(q.Password)
	if err != nil {
		return zero, err
	}
	uid, err := uuid()
	if err != nil {
		return zero, ErrUnavailable
	}
	recovery, err := secret()
	if err != nil {
		return zero, ErrUnavailable
	}
	var workspace string
	err = c.tx(ctx, func(tx *gorm.DB) error {
		// No account enumeration: invalid invitations and existing accounts have
		// the same public error. The write lock serializes concurrent redemption.
		res := tx.WithContext(ctx).Exec(`INSERT INTO identity_users(id,email) VALUES(?,?) ON CONFLICT(email) DO NOTHING`, uid, email)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return ErrDenied
		}
		if err := tx.WithContext(ctx).Exec(`INSERT INTO identity_password_credentials(user_id,password_hash,recovery_hash) VALUES(?,?,?)`, uid, encoded, hash(recovery)).Error; err != nil {
			return err
		}
		var err error
		workspace, err = c.acceptInvitation(database.TransactionContext(ctx, c.GormDB, tx), Session{UserID: uid}, tokenHash)
		if err != nil {
			if errors.Is(err, ErrUnavailable) {
				return err
			}
			return ErrDenied
		}
		return audit(ctx, tx, "user:"+uid, "users.register_invited", uid, "ok")
	})
	if err != nil {
		if errors.Is(err, ErrDenied) {
			if auditErr := audit(ctx, c.db(ctx), "anonymous", "users.register_invited", "", "denied"); auditErr != nil {
				return zero, ErrUnavailable
			}
			return zero, ErrDenied
		}
		return zero, ErrUnavailable
	}
	return RegisterInvitedResult{UserID: uid, WorkspaceID: workspace, RecoveryCode: recovery}, nil
}
