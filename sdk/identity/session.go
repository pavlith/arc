package identity

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/security"
	"golang.org/x/crypto/argon2"
)

func HashPassword(password string) (string, error) {
	if len(password) < 12 || len(password) > 1024 {
		return "", ErrDenied
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return "", e
	}
	sum := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	b := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=2$%s$%s", b.EncodeToString(salt), b.EncodeToString(sum)), nil
}
func CheckPassword(encoded, password string) bool {
	if len(password) > 1024 {
		return false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" || parts[3] != "m=65536,t=3,p=2" {
		return false
	}
	b := base64.RawStdEncoding
	salt, e := b.DecodeString(parts[4])
	if e != nil || len(salt) != 16 {
		return false
	}
	want, e := b.DecodeString(parts[5])
	if e != nil || len(want) != 32 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}

type UserSession struct {
	Secret string `json:"secret"`
	CSRF   string `json:"csrf"`
}
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}
type LoginResult struct {
	Session     Session `json:"session"`
	Secret      string  `json:"secret"`
	CSRF        string  `json:"csrf"`
	Refresh     string  `json:"refresh"`
	AccessToken string  `json:"access_token"`
}

func SessionCookie(secret string, expires time.Time) *http.Cookie {
	return &http.Cookie{Name: "__Host-arc_session", Value: secret, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: expires}
}

// Gate must check origin on login too, and CSRF on every cookie-auth mutation.
func CheckBrowserMutation(origin, expected, csrf, expectedCSRF string) error {
	if expected == "" || origin != expected || csrf == "" || subtle.ConstantTimeCompare([]byte(csrf), []byte(expectedCSRF)) != 1 {
		return ErrDenied
	}
	return nil
}
func (c *Core) rate(ctx context.Context, bucket string) error {
	if e := c.ready(); e != nil {
		return e
	}
	var attempts int
	e := c.DB.QueryRowContext(ctx, `INSERT INTO identity.rate_limits(bucket,window_start,attempts) VALUES($1,$2,1) ON CONFLICT(bucket) DO UPDATE SET attempts=CASE WHEN identity.rate_limits.window_start<=$2-interval '1 minute' THEN 1 ELSE identity.rate_limits.attempts+1 END, window_start=CASE WHEN identity.rate_limits.window_start<=$2-interval '1 minute' THEN $2 ELSE identity.rate_limits.window_start END RETURNING attempts`, bucket, c.now()).Scan(&attempts)
	if e != nil {
		return ErrUnavailable
	}
	if attempts > 10 {
		return ErrRateLimited
	}
	return nil
}

// BootstrapUser is a local Core administration operation, never bound to an RPC.
func (c *Core) BootstrapUser(ctx context.Context, email, password string) (string, string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if !strings.Contains(email, "@") || len(email) > 254 {
		return "", "", ErrDenied
	}
	encoded, e := HashPassword(password)
	if e != nil {
		return "", "", e
	}
	id, e := uuid()
	if e != nil {
		return "", "", e
	}
	recovery, e := secret()
	if e != nil {
		return "", "", e
	}
	e = c.tx(ctx, func(t *sql.Tx) error {
		if _, e := t.ExecContext(ctx, `INSERT INTO identity.users(id,email) VALUES($1,$2)`, id, email); e != nil {
			return e
		}
		if _, e := t.ExecContext(ctx, `INSERT INTO identity.password_credentials(user_id,password_hash,recovery_hash) VALUES($1,$2,$3)`, id, encoded, hash(recovery)); e != nil {
			return e
		}
		return audit(ctx, t, "core", "users.create", id, "ok")
	})
	return id, recovery, e
}
func (c *Core) Login(ctx context.Context, email, password string) (LoginResult, error) {
	var out LoginResult
	email = strings.ToLower(strings.TrimSpace(email))
	if e := c.rate(ctx, "login:global"); e != nil {
		return out, e
	}
	if e := c.rate(ctx, "login:"+base64.RawURLEncoding.EncodeToString(hash(email))); e != nil {
		return out, e
	}
	var uid, encoded string
	e := c.DB.QueryRowContext(ctx, `SELECT u.id,p.password_hash FROM identity.users u JOIN identity.password_credentials p ON p.user_id=u.id WHERE u.email=$1 AND u.status='active'`, email).Scan(&uid, &encoded)
	if e != nil && e != sql.ErrNoRows {
		return out, ErrUnavailable
	}
	// Unknown users still pay the same Argon2 cost.
	if e == sql.ErrNoRows {
		encoded = "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	}
	if !CheckPassword(encoded, password) || uid == "" {
		if e := audit(ctx, c.DB, "anonymous", "sessions.login", "", "denied"); e != nil {
			return out, e
		}
		return out, ErrUnauthenticated
	}
	out.Secret, e = secret()
	if e != nil {
		return out, e
	}
	out.CSRF, e = secret()
	if e != nil {
		return out, e
	}
	out.Refresh, e = secret()
	if e != nil {
		return out, e
	}
	out.Session.ID, e = uuid()
	if e != nil {
		return out, e
	}
	family, e := uuid()
	if e != nil {
		return out, e
	}
	out.Session.UserID = uid
	out.Session.ExpiresAt = c.now().Add(24 * time.Hour)
	out.AccessToken, e = c.access(out.Session)
	if e != nil {
		return LoginResult{}, e
	}
	e = c.tx(ctx, func(t *sql.Tx) error {
		// Lock password row so concurrent recovery cannot leave a new live session.
		var liveHash string
		if e := t.QueryRowContext(ctx, `SELECT p.password_hash FROM identity.password_credentials p JOIN identity.users u ON u.id=p.user_id WHERE p.user_id=$1 AND u.status='active' FOR UPDATE OF p,u`, uid).Scan(&liveHash); e != nil {
			return e
		}
		if liveHash != encoded {
			return ErrUnauthenticated
		}
		if _, e := t.ExecContext(ctx, `INSERT INTO identity.sessions(id,user_id,secret_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5)`, out.Session.ID, uid, hash(out.Secret), hash(out.CSRF), out.Session.ExpiresAt); e != nil {
			return e
		}
		if _, e := t.ExecContext(ctx, `INSERT INTO identity.refresh_families(id,session_id,expires_at) VALUES($1,$2,$3)`, family, out.Session.ID, out.Session.ExpiresAt); e != nil {
			return e
		}
		if _, e := t.ExecContext(ctx, `INSERT INTO identity.refresh_tokens(token_hash,family_id) VALUES($1,$2)`, hash(out.Refresh), family); e != nil {
			return e
		}
		return audit(ctx, t, "user:"+uid, "sessions.login", out.Session.ID, "ok")
	})
	if e != nil {
		return LoginResult{}, e
	}
	return out, nil
}
func (c *Core) access(s Session) (string, error) {
	j, e := uuid()
	if e != nil {
		return "", e
	}
	now := c.now().Unix()
	return security.Sign(c.PrivateKey, c.SigningKid, security.Claims{Issuer: "arc-core", Audience: "gate", Subject: "user:" + s.UserID, SessionID: s.ID, JTI: j, IssuedAt: now, NotBefore: now, ExpiresAt: now + 600})
}
func (c *Core) Introspect(ctx context.Context, sessionSecret string) (Session, error) {
	var s Session
	if e := c.ready(); e != nil {
		return s, e
	}
	if sessionSecret == "" {
		return s, ErrUnauthenticated
	}
	e := c.DB.QueryRowContext(ctx, `SELECT s.id,s.user_id,s.expires_at FROM identity.sessions s JOIN identity.users u ON u.id=s.user_id WHERE s.secret_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>$2 AND u.status='active'`, hash(sessionSecret), c.now()).Scan(&s.ID, &s.UserID, &s.ExpiresAt)
	return s, keyError(e)
}
func (c *Core) user(ctx context.Context, auth UserSession) (Session, error) {
	s, e := c.Introspect(ctx, auth.Secret)
	if e != nil {
		return s, e
	}
	var ok bool
	e = c.DB.QueryRowContext(ctx, `SELECT csrf_hash=$2 FROM identity.sessions WHERE id=$1`, s.ID, hash(auth.CSRF)).Scan(&ok)
	if e != nil {
		return s, ErrUnavailable
	}
	if auth.CSRF == "" || !ok {
		return s, ErrDenied
	}
	return s, nil
}
func (c *Core) Logout(ctx context.Context, auth UserSession) error {
	s, e := c.user(ctx, auth)
	if e != nil {
		return e
	}
	return c.revokeSession(ctx, s.UserID, s.ID)
}
func (c *Core) RevokeSession(ctx context.Context, auth UserSession, id string) error {
	s, e := c.user(ctx, auth)
	if e != nil {
		return e
	}
	return c.revokeSession(ctx, s.UserID, id)
}
func (c *Core) revokeSession(ctx context.Context, user, id string) error {
	return c.tx(ctx, func(t *sql.Tx) error {
		r, e := t.ExecContext(ctx, `UPDATE identity.sessions SET revoked_at=$3 WHERE id::text=$1 AND user_id::text=$2`, id, user, c.now())
		if e != nil {
			return e
		}
		n, _ := r.RowsAffected()
		if n != 1 {
			return ErrDenied
		}
		if _, e = t.ExecContext(ctx, `UPDATE identity.refresh_families SET revoked_at=$2 WHERE session_id::text=$1`, id, c.now()); e != nil {
			return e
		}
		return audit(ctx, t, "user:"+user, "sessions.revoke", id, "ok")
	})
}
func (c *Core) Refresh(ctx context.Context, token string) (LoginResult, error) {
	var out LoginResult
	if e := c.rate(ctx, "refresh:global"); e != nil {
		return out, e
	}
	next, e := secret()
	if e != nil {
		return out, e
	}
	reuse := false
	e = c.tx(ctx, func(t *sql.Tx) error {
		var family string
		var consumed, revoked, sessionRevoked sql.NullTime
		var expiry time.Time
		e := t.QueryRowContext(ctx, `SELECT f.id,f.session_id,s.user_id,s.expires_at,r.consumed_at,f.revoked_at,s.revoked_at,f.expires_at FROM identity.refresh_tokens r JOIN identity.refresh_families f ON f.id=r.family_id JOIN identity.sessions s ON s.id=f.session_id JOIN identity.users u ON u.id=s.user_id WHERE r.token_hash=$1 AND u.status='active' FOR UPDATE OF f,s,r`, hash(token)).Scan(&family, &out.Session.ID, &out.Session.UserID, &out.Session.ExpiresAt, &consumed, &revoked, &sessionRevoked, &expiry)
		if e != nil {
			return keyError(e)
		}
		if consumed.Valid {
			reuse = true
			if _, e = t.ExecContext(ctx, `UPDATE identity.refresh_families SET revoked_at=$2 WHERE id=$1`, family, c.now()); e != nil {
				return e
			}
			// Also revoke access/session state so existing tokens cannot survive reuse.
			if _, e = t.ExecContext(ctx, `UPDATE identity.sessions SET revoked_at=$2 WHERE id=$1`, out.Session.ID, c.now()); e != nil {
				return e
			}
			return audit(ctx, t, "user:"+out.Session.UserID, "refresh.reuse", family, "revoked")
		}
		if revoked.Valid || sessionRevoked.Valid || !expiry.After(c.now()) || !out.Session.ExpiresAt.After(c.now()) {
			return ErrUnauthenticated
		}
		if _, e = t.ExecContext(ctx, `UPDATE identity.refresh_tokens SET consumed_at=$2 WHERE token_hash=$1`, hash(token), c.now()); e != nil {
			return e
		}
		if _, e = t.ExecContext(ctx, `INSERT INTO identity.refresh_tokens(token_hash,family_id) VALUES($1,$2)`, hash(next), family); e != nil {
			return e
		}
		out.AccessToken, e = c.access(out.Session)
		if e != nil {
			return e
		}
		return audit(ctx, t, "user:"+out.Session.UserID, "sessions.refresh", family, "ok")
	})
	if e != nil {
		return LoginResult{}, e
	}
	if reuse {
		return LoginResult{}, ErrUnauthenticated
	}
	out.Refresh = next
	return out, nil
}

// Recover consumes an offline recovery code once and revokes every session in the same transaction.
func (c *Core) Recover(ctx context.Context, email, code, password string) (string, error) {
	if e := c.rate(ctx, "recovery:global"); e != nil {
		return "", e
	}
	encoded, e := HashPassword(password)
	if e != nil {
		return "", e
	}
	next, e := secret()
	if e != nil {
		return "", e
	}
	e = c.tx(ctx, func(t *sql.Tx) error {
		var uid string
		e := t.QueryRowContext(ctx, `SELECT p.user_id FROM identity.password_credentials p JOIN identity.users u ON u.id=p.user_id WHERE u.email=$1 AND p.recovery_hash=$2 AND u.status='active' FOR UPDATE OF p,u`, strings.ToLower(strings.TrimSpace(email)), hash(code)).Scan(&uid)
		if e != nil {
			return keyError(e)
		}
		if _, e = t.ExecContext(ctx, `UPDATE identity.password_credentials SET password_hash=$2,recovery_hash=$3,updated_at=$4 WHERE user_id=$1`, uid, encoded, hash(next), c.now()); e != nil {
			return e
		}
		if _, e = t.ExecContext(ctx, `UPDATE identity.sessions SET revoked_at=$2 WHERE user_id=$1`, uid, c.now()); e != nil {
			return e
		}
		if _, e = t.ExecContext(ctx, `UPDATE identity.refresh_families f SET revoked_at=$2 FROM identity.sessions s WHERE f.session_id=s.id AND s.user_id=$1`, uid, c.now()); e != nil {
			return e
		}
		return audit(ctx, t, "user:"+uid, "users.recover", uid, "ok")
	})
	if e != nil {
		return "", e
	}
	return next, nil
}

// ChangePassword verifies the current password and revokes all sessions, including
// the current one. Recovery codes can only be rotated by the recovery protocol.
func (c *Core) ChangePassword(ctx context.Context, auth UserSession, oldPassword, newPassword string) error {
	s, e := c.user(ctx, auth)
	if e != nil {
		return e
	}
	if e = c.rate(ctx, "password:"+s.UserID); e != nil {
		return e
	}
	encoded, e := HashPassword(newPassword)
	if e != nil {
		return e
	}
	return c.tx(ctx, func(t *sql.Tx) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		var oldHash string
		if e := t.QueryRowContext(ctx, `SELECT password_hash FROM identity.password_credentials WHERE user_id=$1 FOR UPDATE`, s.UserID).Scan(&oldHash); e != nil {
			return keyError(e)
		}
		if !CheckPassword(oldHash, oldPassword) {
			return ErrUnauthenticated
		}
		if _, e := t.ExecContext(ctx, `UPDATE identity.password_credentials SET password_hash=$2,updated_at=$3 WHERE user_id=$1`, s.UserID, encoded, c.now()); e != nil {
			return e
		}
		if _, e := t.ExecContext(ctx, `UPDATE identity.sessions SET revoked_at=$2 WHERE user_id=$1`, s.UserID, c.now()); e != nil {
			return e
		}
		if _, e := t.ExecContext(ctx, `UPDATE identity.refresh_families f SET revoked_at=$2 FROM identity.sessions s WHERE f.session_id=s.id AND s.user_id=$1`, s.UserID, c.now()); e != nil {
			return e
		}
		return audit(ctx, t, "user:"+s.UserID, "users.password_change", s.UserID, "ok")
	})
}
