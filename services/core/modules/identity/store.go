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
	"time"

	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/security"
	"gorm.io/gorm"
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
	GormDB     *gorm.DB
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
	if c == nil || c.GormDB == nil {
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

func audit(ctx context.Context, q *gorm.DB, actor, op, target, outcome string) error {
	e := q.WithContext(ctx).Exec(`INSERT INTO identity_audit(actor,operation,target,outcome) VALUES( ?,?,?,?)`, actor, op, target, outcome).Error
	return e
}
func (c *Core) tx(ctx context.Context, fn func(*gorm.DB) error) error {
	if e := c.ready(); e != nil {
		return e
	}
	if existing, ok := ctx.Value(transactionKey{}).(*gorm.DB); ok {
		return fn(existing)
	}
	return database.RetryBusy(ctx, func() error {
		return c.GormDB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			// Acquire the owner write lock before any authorization/read snapshot.
			if err := tx.Exec("UPDATE identity_users SET id=id WHERE 0").Error; err != nil {
				return err
			}
			return fn(tx)
		})
	})
}
func (c *Core) db(ctx context.Context) *gorm.DB { return database.FromContext(ctx, c.GormDB) }

func (c *Core) Consume(ctx context.Context, namespace, nonce string, expires time.Time) error {
	return c.consumeGORM(ctx, namespace, nonce, expires)
}
func (c *Core) SigningKey(ctx context.Context, kid string) (security.Key, error) {
	return c.signingKeyGORM(ctx, kid)
}
func (c *Core) CallerKey(ctx context.Context, caller, kid string) (security.Key, error) {
	return c.callerKeyGORM(ctx, caller, kid)
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
	return c.checkInvocationGORM(ctx, cl)
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
	return c.publishSigningKeyGORM(ctx, expires)
}
func (c *Core) JWKS(ctx context.Context) (security.JWKS, error) {
	return c.jwksGORM(ctx)
}
