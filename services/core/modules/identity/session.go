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

	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/security"
	"golang.org/x/crypto/argon2"
	"gorm.io/gorm"
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
func (c *Core) rate(ctx context.Context, bucket string) error { return c.rateLimit(ctx, bucket, 10) }
func (c *Core) rateLimit(ctx context.Context, bucket string, limit int) error {
	if e := c.ready(); e != nil {
		return e
	}
	var attempts int
	e := database.RetryBusy(ctx, func() error {
		return c.db(ctx).WithContext(ctx).Raw(`INSERT INTO identity_rate_limits(bucket,window_start,attempts)
 VALUES( ?,?,1) ON CONFLICT(bucket) DO UPDATE SET
 attempts=CASE WHEN identity_rate_limits.window_start<=? THEN 1 ELSE identity_rate_limits.attempts+1 END,
 window_start=CASE WHEN identity_rate_limits.window_start<=? THEN excluded.window_start ELSE identity_rate_limits.window_start END
 RETURNING attempts`, bucket, c.now(), c.now().Add(-time.Minute), c.now().Add(-time.Minute)).Row().Scan(&attempts)
	})
	if e != nil {
		return ErrUnavailable
	}
	if attempts > limit {
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
	e = c.tx(ctx, func(t *gorm.DB) error {
		if e := t.WithContext(ctx).Exec(`INSERT INTO identity_users(id,email) VALUES( ?,?)`, id, email).Error; e != nil {
			return e
		}
		if e := t.WithContext(ctx).Exec(`INSERT INTO identity_password_credentials(user_id,password_hash,recovery_hash) VALUES( ?,?,?)`, id, encoded, hash(recovery)).Error; e != nil {
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
	e := c.db(ctx).WithContext(ctx).Raw(`SELECT u.id,p.password_hash FROM identity_users u JOIN identity_password_credentials p ON p.user_id=u.id WHERE u.email=? AND u.status='active'`, email).Row().Scan(&uid, &encoded)
	if e != nil && e != sql.ErrNoRows {
		return out, ErrUnavailable
	}
	// Unknown users still pay the same Argon2 cost.
	if e == sql.ErrNoRows {
		encoded = "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	}
	if !CheckPassword(encoded, password) || uid == "" {
		if e := audit(ctx, c.db(ctx), "anonymous", "sessions.login", "", "denied"); e != nil {
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
	e = c.tx(ctx, func(t *gorm.DB) error {
		// Lock password row so concurrent recovery cannot leave a new live session.
		var liveHash string
		if e := t.WithContext(ctx).Raw(`SELECT p.password_hash FROM identity_password_credentials p JOIN identity_users u ON u.id=p.user_id WHERE p.user_id=? AND u.status='active'`, uid).Row().Scan(&liveHash); e != nil {
			return e
		}
		if liveHash != encoded {
			return ErrUnauthenticated
		}
		if e := t.WithContext(ctx).Exec(`INSERT INTO identity_sessions(id,user_id,secret_hash,csrf_hash,expires_at) VALUES( ?,?,?,?,?)`, out.Session.ID, uid, hash(out.Secret), hash(out.CSRF), out.Session.ExpiresAt).Error; e != nil {
			return e
		}
		if e := t.WithContext(ctx).Exec(`INSERT INTO identity_refresh_families(id,session_id,expires_at) VALUES( ?,?,?)`, family, out.Session.ID, out.Session.ExpiresAt).Error; e != nil {
			return e
		}
		if e := t.WithContext(ctx).Exec(`INSERT INTO identity_refresh_tokens(token_hash,family_id) VALUES( ?,?)`, hash(out.Refresh), family).Error; e != nil {
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
	e := c.db(ctx).WithContext(ctx).Raw(`SELECT s.id,s.user_id,s.expires_at FROM identity_sessions s JOIN identity_users u ON u.id=s.user_id WHERE s.secret_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND u.status='active'`, hash(sessionSecret), c.now()).Row().Scan(&s.ID, &s.UserID, &s.ExpiresAt)
	return s, keyError(e)
}
func (c *Core) user(ctx context.Context, auth UserSession) (Session, error) {
	s, e := c.Introspect(ctx, auth.Secret)
	if e != nil {
		return s, e
	}
	var ok bool
	e = c.db(ctx).WithContext(ctx).Raw(`SELECT csrf_hash=? FROM identity_sessions WHERE id=?`, hash(auth.CSRF), s.ID).Row().Scan(&ok)
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
	return c.tx(ctx, func(t *gorm.DB) error {
		r := t.WithContext(ctx).Exec(`UPDATE identity_sessions SET revoked_at=? WHERE id=? AND user_id=?`, c.now(), id, user)
		if r.Error != nil {
			return r.Error
		}
		n := r.RowsAffected
		if n != 1 {
			return ErrDenied
		}
		if e := t.WithContext(ctx).Exec(`UPDATE identity_refresh_families SET revoked_at=? WHERE session_id=?`, c.now(), id).Error; e != nil {
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
	e = c.tx(ctx, func(t *gorm.DB) error {
		var family string
		var consumed, revoked, sessionRevoked sql.NullTime
		var expiry time.Time
		e := t.WithContext(ctx).Raw(`SELECT f.id,f.session_id,s.user_id,s.expires_at,r.consumed_at,f.revoked_at,s.revoked_at,f.expires_at FROM identity_refresh_tokens r JOIN identity_refresh_families f ON f.id=r.family_id JOIN identity_sessions s ON s.id=f.session_id JOIN identity_users u ON u.id=s.user_id WHERE r.token_hash=? AND u.status='active'`, hash(token)).Row().Scan(&family, &out.Session.ID, &out.Session.UserID, &out.Session.ExpiresAt, &consumed, &revoked, &sessionRevoked, &expiry)
		if e != nil {
			return keyError(e)
		}
		if consumed.Valid {
			reuse = true
			if e = t.WithContext(ctx).Exec(`UPDATE identity_refresh_families SET revoked_at=? WHERE id=?`, c.now(), family).Error; e != nil {
				return e
			}
			// Also revoke access/session state so existing tokens cannot survive reuse.
			if e = t.WithContext(ctx).Exec(`UPDATE identity_sessions SET revoked_at=? WHERE id=?`, c.now(), out.Session.ID).Error; e != nil {
				return e
			}
			return audit(ctx, t, "user:"+out.Session.UserID, "refresh.reuse", family, "revoked")
		}
		if revoked.Valid || sessionRevoked.Valid || !expiry.After(c.now()) || !out.Session.ExpiresAt.After(c.now()) {
			return ErrUnauthenticated
		}
		if e = t.WithContext(ctx).Exec(`UPDATE identity_refresh_tokens SET consumed_at=? WHERE token_hash=?`, c.now(), hash(token)).Error; e != nil {
			return e
		}
		if e = t.WithContext(ctx).Exec(`INSERT INTO identity_refresh_tokens(token_hash,family_id) VALUES( ?,?)`, hash(next), family).Error; e != nil {
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
	e = c.tx(ctx, func(t *gorm.DB) error {
		var uid string
		e := t.WithContext(ctx).Raw(`SELECT p.user_id FROM identity_password_credentials p JOIN identity_users u ON u.id=p.user_id WHERE u.email=? AND p.recovery_hash=? AND u.status='active'`, strings.ToLower(strings.TrimSpace(email)), hash(code)).Row().Scan(&uid)
		if e != nil {
			return keyError(e)
		}
		if e = t.WithContext(ctx).Exec(`UPDATE identity_password_credentials SET password_hash=?,recovery_hash=?,updated_at=? WHERE user_id=?`, encoded, hash(next), c.now(), uid).Error; e != nil {
			return e
		}
		if e = t.WithContext(ctx).Exec(`UPDATE identity_sessions SET revoked_at=? WHERE user_id=?`, c.now(), uid).Error; e != nil {
			return e
		}
		if e = t.WithContext(ctx).Exec(`UPDATE identity_refresh_families SET revoked_at=? WHERE session_id IN (SELECT id FROM identity_sessions WHERE user_id=?)`, c.now(), uid).Error; e != nil {
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
	return c.tx(ctx, func(t *gorm.DB) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		var oldHash string
		if e := t.WithContext(ctx).Raw(`SELECT password_hash FROM identity_password_credentials WHERE user_id=?`, s.UserID).Row().Scan(&oldHash); e != nil {
			return keyError(e)
		}
		if !CheckPassword(oldHash, oldPassword) {
			return ErrUnauthenticated
		}
		if e := t.WithContext(ctx).Exec(`UPDATE identity_password_credentials SET password_hash=?,updated_at=? WHERE user_id=?`, encoded, c.now(), s.UserID).Error; e != nil {
			return e
		}
		if e := t.WithContext(ctx).Exec(`UPDATE identity_sessions SET revoked_at=? WHERE user_id=?`, c.now(), s.UserID).Error; e != nil {
			return e
		}
		if e := t.WithContext(ctx).Exec(`UPDATE identity_refresh_families SET revoked_at=? WHERE session_id IN (SELECT id FROM identity_sessions WHERE user_id=?)`, c.now(), s.UserID).Error; e != nil {
			return e
		}
		return audit(ctx, t, "user:"+s.UserID, "users.password_change", s.UserID, "ok")
	})
}
