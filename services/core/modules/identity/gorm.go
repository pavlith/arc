package identity

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/models"
	"gorm.io/gorm"
)

// consumeGORM inserts a nonce once, including after the nonce has expired.
// A unique (namespace,nonce) key closes cross-process assertion replays.
func (c *Core) consumeGORM(ctx context.Context, namespace, nonce string, expires time.Time) error {
	if ctx == nil || c.GormDB == nil {
		return ErrUnavailable
	}
	if namespace == "" || nonce == "" || !expires.After(c.now()) {
		return ErrUnauthenticated
	}
	var inserted int64
	err := database.RetryBusy(ctx, func() error {
		r := database.FromContext(ctx, c.GormDB).WithContext(ctx).Exec(
			"INSERT INTO identity_assertion_nonces(namespace,nonce,expires_at) VALUES( ?,?,?) ON CONFLICT(namespace,nonce) DO NOTHING",
			namespace, nonce, expires,
		)
		inserted = r.RowsAffected
		return r.Error
	})
	if err != nil {
		return ErrUnavailable
	}
	if inserted != 1 {
		return ErrUnauthenticated
	}
	return nil
}

func (c *Core) signingKeyGORM(ctx context.Context, kid string) (security.Key, error) {
	k := security.Key{Kid: kid}
	if ctx == nil || c.GormDB == nil {
		return k, ErrUnavailable
	}
	var row models.IdentitySigningKey
	err := database.FromContext(ctx, c.GormDB).WithContext(ctx).Where("kid=?", kid).Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return k, ErrUnauthenticated
	}
	if err != nil {
		return k, ErrUnavailable
	}
	k.Public = ed25519.PublicKey(row.PublicKey)
	k.NotBefore, k.ExpiresAt, k.Revoked = row.NotBefore, row.ExpiresAt, row.RevokedAt != nil
	return k, nil
}

func (c *Core) callerKeyGORM(ctx context.Context, caller, kid string) (security.Key, error) {
	k := security.Key{Kid: kid}
	if ctx == nil || c.GormDB == nil {
		return k, ErrUnavailable
	}
	var revoked, disabled sql.NullTime
	err := database.FromContext(ctx, c.GormDB).WithContext(ctx).
		Table("identity_service_credentials AS k").
		Select("k.public_key,k.not_before,k.expires_at,k.revoked_at,a.disabled_at").
		Joins("JOIN identity_service_accounts AS a ON a.id=k.service_account_id").
		Where("a.id=? AND k.kid=?", caller, kid).
		Row().Scan(&k.Public, &k.NotBefore, &k.ExpiresAt, &revoked, &disabled)
	if err != nil {
		return k, keyError(err)
	}
	k.Revoked = revoked.Valid || disabled.Valid
	return k, nil
}

func (c *Core) publishSigningKeyGORM(ctx context.Context, expires time.Time) error {
	if ctx == nil || c.GormDB == nil || len(c.PrivateKey) != ed25519.PrivateKeySize ||
		c.SigningKid == "" || !expires.After(c.now()) {
		return ErrUnavailable
	}
	now := c.now()
	err := database.RetryBusy(ctx, func() error {
		return database.FromContext(ctx, c.GormDB).WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			err := tx.Create(&models.IdentitySigningKey{
				Kid: c.SigningKid, PublicKey: []byte(c.PrivateKey.Public().(ed25519.PublicKey)),
				NotBefore: now, ExpiresAt: expires,
			}).Error
			if err != nil {
				return err
			}
			return tx.Exec("INSERT INTO identity_audit(actor,operation,target,outcome) VALUES( ?,?,?,?)",
				"core", "signing_keys.publish", c.SigningKid, "ok").Error
		})
	})
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

func (c *Core) jwksGORM(ctx context.Context) (security.JWKS, error) {
	if ctx == nil || c.GormDB == nil {
		return security.JWKS{}, ErrUnavailable
	}
	now := c.now()
	var rows []models.IdentitySigningKey
	err := database.FromContext(ctx, c.GormDB).WithContext(ctx).
		Where("revoked_at IS NULL AND not_before<=? AND expires_at>?", now, now).
		Order("kid").Find(&rows).Error
	if err != nil {
		return security.JWKS{}, ErrUnavailable
	}
	keys := make([]security.Key, 0, len(rows))
	for _, row := range rows {
		keys = append(keys, security.Key{
			Kid: row.Kid, Public: ed25519.PublicKey(row.PublicKey),
			NotBefore: row.NotBefore, ExpiresAt: row.ExpiresAt,
		})
	}
	return security.PublicJWKS(keys, now), nil
}

func (c *Core) delegationGORM(ctx context.Context, id string) (Delegation, error) {
	var out Delegation
	if ctx == nil || c.GormDB == nil {
		return out, ErrUnavailable
	}
	var resources, actions string
	var revoked sql.NullTime
	err := database.FromContext(ctx, c.GormDB).WithContext(ctx).Raw(
		`SELECT id,grantor_user_id,grantee_kind,grantee_id,resource_ids,actions,
		expires_at,revoked_at,consent_method FROM identity_delegations WHERE id=?`, id,
	).Row().Scan(&out.ID, &out.Grantor, &out.GranteeKind, &out.GranteeID,
		&resources, &actions, &out.ExpiresAt, &revoked, &out.ConsentMethod)
	if err != nil {
		return out, keyError(err)
	}
	if json.Unmarshal([]byte(resources), &out.Resources) != nil ||
		json.Unmarshal([]byte(actions), &out.Actions) != nil {
		return Delegation{}, ErrUnavailable
	}
	if revoked.Valid {
		out.RevokedAt = &revoked.Time
	}
	return out, nil
}

func (c *Core) checkDelegationGORM(ctx context.Context, cl security.Claims) error {
	d, err := c.delegationGORM(ctx, cl.DelegationID)
	if err != nil {
		return err
	}
	if d.RevokedAt != nil || !d.ExpiresAt.After(c.now()) ||
		cl.Subject != d.GranteeKind+":"+d.GranteeID || cl.OnBehalfOf != d.Grantor {
		return ErrDenied
	}
	var active bool
	err = database.FromContext(ctx, c.GormDB).WithContext(ctx).Raw(
		"SELECT EXISTS(SELECT 1 FROM identity_users WHERE id=? AND status='active')", d.Grantor,
	).Row().Scan(&active)
	if err != nil {
		return ErrUnavailable
	}
	if !active {
		return ErrDenied
	}
	return c.allow(ctx, Authorization{
		Caller: cl.Caller, Actor: "user:" + d.Grantor,
		Operation: cl.Operation, Audience: cl.Audience,
		WorkspaceID: cl.WorkspaceID, DelegationID: d.ID,
		Resources: d.Resources, Actions: d.Actions,
	})
}

func (c *Core) checkInvocationGORM(ctx context.Context, cl security.Claims) error {
	if ctx == nil || c.GormDB == nil {
		return ErrUnavailable
	}
	var query string
	var args []any
	switch {
	case strings.HasPrefix(cl.Subject, "user:"):
		if cl.SessionID == "" || cl.DelegationID != "" {
			return ErrUnauthenticated
		}
		query = `SELECT EXISTS(
			SELECT 1 FROM identity_sessions s JOIN identity_users u ON u.id=s.user_id
			WHERE s.id=? AND u.id=? AND s.revoked_at IS NULL
			AND s.expires_at>? AND u.status='active')`
		args = []any{cl.SessionID, strings.TrimPrefix(cl.Subject, "user:"), c.now()}
	case strings.HasPrefix(cl.Subject, "service:"):
		query = "SELECT EXISTS(SELECT 1 FROM identity_service_accounts WHERE id=? AND disabled_at IS NULL)"
		args = []any{strings.TrimPrefix(cl.Subject, "service:")}
	case strings.HasPrefix(cl.Subject, "agent:"):
		query = "SELECT EXISTS(SELECT 1 FROM identity_agent_identities WHERE id=? AND disabled_at IS NULL)"
		args = []any{strings.TrimPrefix(cl.Subject, "agent:")}
	default:
		return ErrUnauthenticated
	}
	var active bool
	if err := database.FromContext(ctx, c.GormDB).WithContext(ctx).Raw(query, args...).Row().Scan(&active); err != nil {
		return ErrUnavailable
	}
	if !active {
		return ErrUnauthenticated
	}
	if cl.DelegationID != "" {
		if err := c.checkDelegationGORM(ctx, cl); err != nil {
			return err
		}
	}
	if cl.WorkspaceID != "" {
		user := strings.TrimPrefix(cl.Subject, "user:")
		if cl.OnBehalfOf != "" {
			user = cl.OnBehalfOf
		}
		if strings.HasPrefix(cl.Subject, "user:") || cl.OnBehalfOf != "" {
			var member bool
			err := database.FromContext(ctx, c.GormDB).WithContext(ctx).Raw(
				`SELECT EXISTS(SELECT 1 FROM identity_memberships
				WHERE workspace_id=? AND user_id=? AND revoked_at IS NULL)`, cl.WorkspaceID, user,
			).Row().Scan(&member)
			if err != nil {
				return ErrUnavailable
			}
			if !member {
				return ErrDenied
			}
		}
	}
	if cl.Audience == "gate" && cl.Operation == "" {
		return nil
	}
	return c.allow(ctx, Authorization{
		Caller: cl.Caller, Actor: cl.Subject, Audience: cl.Audience,
		Operation: cl.Operation, WorkspaceID: cl.WorkspaceID, DelegationID: cl.DelegationID,
	})
}
