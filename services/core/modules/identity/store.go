// Package identity is the Core-owned Identity module. It exposes no HTTP ingress.
package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pavlith/arc/pkgs/security"
)

var ErrUnauthenticated = security.ErrUnauthenticated
var ErrDenied = security.ErrDenied
var ErrUnavailable = security.ErrUnavailable
var ErrRateLimited = errors.New("rate limited")
var ErrConflict = errors.New("conflict")

// Authorization is evaluated by future Access/Fabric adapters against current
// grants and approved operation contracts. A missing adapter always denies work.
type Authorization struct {
	Caller, Actor, Audience, Operation, WorkspaceID, DelegationID string
	Resources, Actions                                            []string
	Incoming                                                      *security.Claims
	ExpiresAt                                                     time.Time
	NeedsApproval                                                 bool
}
type Policy interface {
	Authorize(context.Context, Authorization) error
}
type Core struct {
	DB         *sql.DB
	Policy     Policy
	PrivateKey ed25519.PrivateKey
	SigningKid string
	Now        func() time.Time
}

func (c *Core) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}
func (c *Core) ready() error {
	if c == nil || c.DB == nil {
		return ErrUnavailable
	}
	return nil
}
func (c *Core) allow(ctx context.Context, a Authorization) error {
	if c.Policy == nil {
		return ErrUnavailable
	}
	return c.Policy.Authorize(ctx, a)
}
func secret() (string, error) {
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
func uuid() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}
func hash(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

type executor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func audit(ctx context.Context, q executor, actor, op, target, outcome string) error {
	_, e := q.ExecContext(ctx, `INSERT INTO identity.audit(actor,operation,target,outcome) VALUES($1,$2,$3,$4)`, actor, op, target, outcome)
	return e
}
func (c *Core) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	if existing, ok := ctx.Value(transactionKey{}).(*sql.Tx); ok {
		return fn(existing)
	}
	if e := c.ready(); e != nil {
		return e
	}
	t, e := c.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer t.Rollback()
	if e = fn(t); e != nil {
		return e
	}
	return t.Commit()
}
func (c *Core) Consume(ctx context.Context, namespace, nonce string, expires time.Time) error {
	if e := c.ready(); e != nil {
		return e
	}
	if nonce == "" || namespace == "" || !expires.After(c.now()) {
		return ErrUnauthenticated
	}
	// Never overwrite a nonce, even if its token is expired. Cleanup is a separate maintenance operation.
	r, e := c.DB.ExecContext(ctx, `INSERT INTO identity.assertion_nonces(namespace,nonce,expires_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, namespace, nonce, expires)
	if e != nil {
		return ErrUnavailable
	}
	n, e := r.RowsAffected()
	if e != nil {
		return ErrUnavailable
	}
	if n != 1 {
		return ErrUnauthenticated
	}
	return nil
}
func (c *Core) SigningKey(ctx context.Context, kid string) (security.Key, error) {
	k := security.Key{Kid: kid}
	if e := c.ready(); e != nil {
		return k, e
	}
	var revoked sql.NullTime
	e := c.DB.QueryRowContext(ctx, `SELECT public_key,not_before,expires_at,revoked_at FROM identity.signing_key_metadata WHERE kid=$1`, kid).Scan(&k.Public, &k.NotBefore, &k.ExpiresAt, &revoked)
	k.Revoked = revoked.Valid
	return k, keyError(e)
}
func (c *Core) CallerKey(ctx context.Context, caller, kid string) (security.Key, error) {
	k := security.Key{Kid: kid}
	if e := c.ready(); e != nil {
		return k, e
	}
	var revoked, disabled sql.NullTime
	e := c.DB.QueryRowContext(ctx, `SELECT k.public_key,k.not_before,k.expires_at,k.revoked_at,a.disabled_at FROM identity.service_credentials k JOIN identity.service_accounts a ON a.id=k.service_account_id WHERE a.id::text=$1 AND k.kid=$2`, caller, kid).Scan(&k.Public, &k.NotBefore, &k.ExpiresAt, &revoked, &disabled)
	k.Revoked = revoked.Valid || disabled.Valid
	return k, keyError(e)
}
func keyError(e error) error {
	if errors.Is(e, sql.ErrNoRows) {
		return ErrUnauthenticated
	}
	if e != nil {
		return ErrUnavailable
	}
	return nil
}
func (c *Core) Verifier() security.Verifier {
	return security.Verifier{Keys: c, State: c, Nonces: c, Now: c.now}
}
func (c *Core) CheckInvocation(ctx context.Context, cl security.Claims) error {
	if e := c.ready(); e != nil {
		return e
	}
	if strings.HasPrefix(cl.Subject, "user:") {
		if cl.SessionID == "" || cl.DelegationID != "" {
			return ErrUnauthenticated
		}
		var ok bool
		e := c.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity.sessions s JOIN identity.users u ON u.id=s.user_id WHERE s.id::text=$1 AND u.id::text=$2 AND s.revoked_at IS NULL AND s.expires_at>$3 AND u.status='active')`, cl.SessionID, strings.TrimPrefix(cl.Subject, "user:"), c.now()).Scan(&ok)
		if e != nil {
			return ErrUnavailable
		}
		if !ok {
			return ErrUnauthenticated
		}
	} else if strings.HasPrefix(cl.Subject, "service:") {
		var ok bool
		e := c.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity.service_accounts WHERE id::text=$1 AND disabled_at IS NULL)`, strings.TrimPrefix(cl.Subject, "service:")).Scan(&ok)
		if e != nil {
			return ErrUnavailable
		}
		if !ok {
			return ErrUnauthenticated
		}
	} else if strings.HasPrefix(cl.Subject, "agent:") {
		var ok bool
		e := c.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity.agent_identities WHERE id::text=$1 AND disabled_at IS NULL)`, strings.TrimPrefix(cl.Subject, "agent:")).Scan(&ok)
		if e != nil {
			return ErrUnavailable
		}
		if !ok {
			return ErrUnauthenticated
		}
	} else {
		return ErrUnauthenticated
	}
	if cl.DelegationID != "" {
		if e := c.checkDelegation(ctx, cl); e != nil {
			return e
		}
	}
	if cl.WorkspaceID != "" {
		user := strings.TrimPrefix(cl.Subject, "user:")
		if cl.OnBehalfOf != "" {
			user = cl.OnBehalfOf
		}
		if strings.HasPrefix(cl.Subject, "user:") || cl.OnBehalfOf != "" {
			var ok bool
			e := c.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity.memberships WHERE workspace_id::text=$1 AND user_id::text=$2 AND revoked_at IS NULL)`, cl.WorkspaceID, user).Scan(&ok)
			if e != nil {
				return ErrUnavailable
			}
			if !ok {
				return ErrDenied
			}
		}
	}
	if cl.Audience == "gate" && cl.Operation == "" {
		return nil
	}
	return c.allow(ctx, Authorization{Caller: cl.Caller, Actor: cl.Subject, Audience: cl.Audience, Operation: cl.Operation, WorkspaceID: cl.WorkspaceID, DelegationID: cl.DelegationID})
}

// LoadSigningKey must only be called by the Core executable with a Core-only mount.
// Raw Ed25519 seed files must have no group/other permissions; no key enters SQL.
func LoadSigningKey(path string) (ed25519.PrivateKey, error) {
	st, e := os.Stat(path)
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, ErrDenied
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	if len(raw) != ed25519.SeedSize {
		return nil, ErrDenied
	}
	return ed25519.NewKeyFromSeed(raw), nil
}
func (c *Core) PublishSigningKey(ctx context.Context, expires time.Time) error {
	if len(c.PrivateKey) != 64 || c.SigningKid == "" || !expires.After(c.now()) {
		return ErrUnavailable
	}
	return c.tx(ctx, func(t *sql.Tx) error {
		_, e := t.ExecContext(ctx, `INSERT INTO identity.signing_key_metadata(kid,public_key,not_before,expires_at) VALUES($1,$2,$3,$4)`, c.SigningKid, []byte(c.PrivateKey.Public().(ed25519.PublicKey)), c.now(), expires)
		if e != nil {
			return e
		}
		return audit(ctx, t, "core", "signing_keys.publish", c.SigningKid, "ok")
	})
}
func (c *Core) JWKS(ctx context.Context) (security.JWKS, error) {
	if e := c.ready(); e != nil {
		return security.JWKS{}, e
	}
	rows, e := c.DB.QueryContext(ctx, `SELECT kid,public_key,not_before,expires_at FROM identity.signing_key_metadata WHERE revoked_at IS NULL AND not_before<=$1 AND expires_at>$1`, c.now())
	if e != nil {
		return security.JWKS{}, e
	}
	defer rows.Close()
	var keys []security.Key
	for rows.Next() {
		var k security.Key
		if e = rows.Scan(&k.Kid, &k.Public, &k.NotBefore, &k.ExpiresAt); e != nil {
			return security.JWKS{}, e
		}
		keys = append(keys, k)
	}
	if e = rows.Err(); e != nil {
		return security.JWKS{}, e
	}
	return security.PublicJWKS(keys, c.now()), nil
}
