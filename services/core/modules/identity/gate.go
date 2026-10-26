package identity

import (
	"context"
	"strings"
)

// Authentication contains external credentials, never an actor supplied by Gate.
type Authentication struct {
	Session     UserSession `json:"session"`
	AccessToken string      `json:"access_token,omitempty"`
	RequireCSRF bool        `json:"require_csrf"`
}

func (c *Core) Authenticate(ctx context.Context, a Authentication) (Session, error) {
	if a.AccessToken != "" {
		if a.Session.Secret != "" {
			return Session{}, ErrUnauthenticated
		}
		cl, e := c.Verifier().Access(ctx, a.AccessToken)
		if e != nil {
			return Session{}, e
		}
		var s Session
		e = c.DB.QueryRowContext(ctx, `SELECT id,user_id,expires_at FROM identity.sessions WHERE id::text=$1 AND user_id::text=$2`, cl.SessionID, strings.TrimPrefix(cl.Subject, "user:")).Scan(&s.ID, &s.UserID, &s.ExpiresAt)
		return s, keyError(e)
	}
	if a.RequireCSRF {
		return c.user(ctx, a.Session)
	}
	return c.Introspect(ctx, a.Session.Secret)
}
func (c *Core) LogoutAccess(ctx context.Context, token string) error {
	s, e := c.Authenticate(ctx, Authentication{AccessToken: token})
	if e != nil {
		return e
	}
	return c.revokeSession(ctx, s.UserID, s.ID)
}
func (c *Core) RefreshBrowser(ctx context.Context, session UserSession, token string) (LoginResult, error) {
	if session.Secret != "" {
		s, e := c.user(ctx, session)
		if e != nil {
			return LoginResult{}, e
		}
		var sid string
		e = c.DB.QueryRowContext(ctx, `SELECT f.session_id FROM identity.refresh_tokens t JOIN identity.refresh_families f ON f.id=t.family_id WHERE t.token_hash=$1`, hash(token)).Scan(&sid)
		if e != nil {
			return LoginResult{}, keyError(e)
		}
		if sid != s.ID {
			return LoginResult{}, ErrUnauthenticated
		}
	}
	return c.Refresh(ctx, token)
}
