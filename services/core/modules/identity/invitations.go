package identity

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk"
	"gorm.io/gorm"
)

type InvitationCreate struct {
	WorkspaceInput
	Email string `json:"email"`
	Role  string `json:"role"`
	Token string `json:"token"`
}

type InvitationRevoke struct {
	WorkspaceInput
	ID string `json:"id"`
}

type InvitationAccept struct {
	Token string `json:"token"`
}

type Invitation struct {
	ID          string    `json:"id"`
	WorkspaceID string    `json:"workspace_id"`
	Email       string    `json:"email"`
	Role        string    `json:"role"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// InvitationDetails never includes the bearer token or its stored hash.
type InvitationDetails struct {
	Invitation
	IssuerID   string     `json:"issuer_id"`
	Status     string     `json:"status"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

func (c *Core) invitations(ctx context.Context, user string, q WorkspacePage) ([]InvitationDetails, error) {
	if _, err := c.productRole(ctx, q.WorkspaceID, user, true); err != nil {
		return nil, err
	}
	if q.After != "" && !productID.MatchString(q.After) {
		return nil, productInvalid()
	}
	out := []InvitationDetails{}
	err := c.db(ctx).WithContext(ctx).Raw(`SELECT i.id,i.workspace_id,i.email,i.role,i.expires_at,
		i.issuer_id,i.consumed_at,i.revoked_at,
		CASE WHEN i.consumed_at IS NOT NULL THEN 'accepted'
		WHEN i.revoked_at IS NOT NULL THEN 'revoked'
		WHEN i.expires_at<=? THEN 'expired'
		WHEN u.status<>'active' OR u.id IS NULL OR m.revoked_at IS NOT NULL
		OR m.role NOT IN ('owner','admin') OR m.user_id IS NULL THEN 'invalidated'
		ELSE 'pending' END AS status
		FROM identity_workspace_invitations i
		LEFT JOIN identity_users u ON u.id=i.issuer_id
		LEFT JOIN identity_memberships m ON m.workspace_id=i.workspace_id AND m.user_id=i.issuer_id
		WHERE i.workspace_id=? AND i.id>? ORDER BY i.id LIMIT 100`, c.now(), q.WorkspaceID, q.After).Scan(&out).Error
	if err != nil {
		return nil, ErrUnavailable
	}
	return out, nil
}

func invitationHash(token string) ([]byte, error) {
	if len(token) != base64.RawURLEncoding.EncodedLen(32) {
		return nil, productInvalid()
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != 32 {
		return nil, productInvalid()
	}
	return hash(token), nil
}

func (c *Core) createInvitation(ctx context.Context, user Session, req ProductRequest[InvitationCreate]) (Invitation, error) {
	q := req.Input
	email := strings.ToLower(strings.TrimSpace(q.Email))
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || len(email) > 254 || q.Role != "member" && q.Role != "guest" {
		return Invitation{}, productInvalid()
	}
	tokenHash, err := invitationHash(q.Token)
	if err != nil {
		return Invitation{}, err
	}
	id, err := uuid()
	if err != nil {
		return Invitation{}, ErrUnavailable
	}
	out := Invitation{ID: id, WorkspaceID: q.WorkspaceID, Email: email, Role: q.Role, ExpiresAt: c.now().Add(48 * time.Hour)}
	db := c.db(ctx).WithContext(ctx)
	insert := db.Exec(`INSERT INTO identity_workspace_invitations(id,workspace_id,issuer_id,email,role,token_hash,expires_at)
		VALUES(?,?,?,?,?,?,?) ON CONFLICT(token_hash) DO NOTHING`, id, q.WorkspaceID, user.UserID, email, q.Role, tokenHash, out.ExpiresAt)
	if insert.Error != nil {
		return Invitation{}, ErrUnavailable
	}
	if insert.RowsAffected != 1 {
		return Invitation{}, ErrConflict
	}
	return out, audit(ctx, db, "user:"+user.UserID, "invitations.create", id, "ok")
}

func (c *Core) revokeInvitation(ctx context.Context, user Session, req ProductRequest[InvitationRevoke]) (Empty, error) {
	q := req.Input
	if !productID.MatchString(q.ID) {
		return Empty{}, productInvalid()
	}
	db := c.db(ctx).WithContext(ctx)
	res := db.Exec(`UPDATE identity_workspace_invitations SET revoked_at=?
		WHERE id=? AND workspace_id=? AND consumed_at IS NULL AND revoked_at IS NULL`, c.now(), q.ID, q.WorkspaceID)
	if res.Error != nil {
		return Empty{}, ErrUnavailable
	}
	if res.RowsAffected != 1 {
		return Empty{}, productNotFound()
	}
	return Empty{}, audit(ctx, db, "user:"+user.UserID, "invitations.revoke", q.ID, "ok")
}

func (c *Core) revokeIssuedInvitations(ctx context.Context, tx *gorm.DB, workspace, issuer string) error {
	return tx.WithContext(ctx).Exec(`UPDATE identity_workspace_invitations SET revoked_at=?
		WHERE workspace_id=? AND issuer_id=? AND consumed_at IS NULL AND revoked_at IS NULL`, c.now(), workspace, issuer).Error
}

func (c *Core) acceptInvitation(ctx context.Context, user Session, tokenHash []byte) (string, error) {
	db := c.db(ctx).WithContext(ctx)
	var id, workspace, role string
	err := db.Raw(`SELECT i.id,i.workspace_id,i.role FROM identity_workspace_invitations i
		JOIN identity_workspaces w ON w.id=i.workspace_id AND w.archived_at IS NULL
		JOIN identity_users recipient ON recipient.id=? AND recipient.email=i.email AND recipient.status='active'
		JOIN identity_users issuer ON issuer.id=i.issuer_id AND issuer.status='active'
		JOIN identity_memberships m ON m.workspace_id=i.workspace_id AND m.user_id=i.issuer_id
		WHERE i.token_hash=? AND i.consumed_at IS NULL AND i.revoked_at IS NULL AND i.expires_at>?
		AND m.revoked_at IS NULL AND m.role IN ('owner','admin')`, user.UserID, tokenHash, c.now()).Row().Scan(&id, &workspace, &role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", productNotFound()
	}
	if err != nil {
		return "", ErrUnavailable
	}
	member := db.Exec(`INSERT INTO identity_memberships(workspace_id,user_id,role) VALUES(?,?,?)
		ON CONFLICT(workspace_id,user_id) DO UPDATE SET role=excluded.role,revoked_at=NULL
		WHERE identity_memberships.revoked_at IS NOT NULL`, workspace, user.UserID, role)
	if member.Error != nil {
		return "", ErrUnavailable
	}
	if member.RowsAffected != 1 {
		return "", ErrConflict
	}
	if err := db.Exec(`UPDATE identity_workspace_invitations SET consumed_at=? WHERE id=?`, c.now(), id).Error; err != nil {
		return "", ErrUnavailable
	}
	if err := db.Exec(`UPDATE identity_workspaces SET revision=revision+1 WHERE id=?`, workspace).Error; err != nil {
		return "", ErrUnavailable
	}
	return workspace, audit(ctx, db, "user:"+user.UserID, "invitations.accept", id, "ok")
}

func (c *Core) bindInvitationAccept(s *sdk.Service) error {
	const name = "product.invitations.accept"
	return bindOperation(s, c, name, true, func(ctx context.Context, req ProductRequest[InvitationAccept]) (Workspace, error) {
		user, err := c.user(ctx, req.Session)
		if err != nil {
			return Workspace{}, err
		}
		tokenHash, err := invitationHash(req.Input.Token)
		if err != nil {
			return Workspace{}, err
		}
		workspace, err := runCommand(ctx, c, user, "identity.v1."+name, nil, func(ctx context.Context) (string, error) {
			return c.acceptInvitation(ctx, user, tokenHash)
		})
		if err != nil {
			return Workspace{}, err
		}
		return c.workspace(ctx, user.UserID, WorkspaceInput{WorkspaceID: workspace})
	})
}
