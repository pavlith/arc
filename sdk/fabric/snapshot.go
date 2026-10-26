package fabric

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"sort"
	"time"

	"database/sql"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/security"
)

type Route struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	Service       string `json:"service"`
	Operation     string `json:"operation"`
	Subject       string `json:"subject"`
	Digest        string `json:"digest"`
	SuccessStatus int    `json:"success_status"`
}
type RouteSnapshot struct {
	Revision int64     `json:"revision"`
	IssuedAt time.Time `json:"issued_at"`
	Routes   []Route   `json:"routes"`
}
type SignedSnapshot struct {
	Payload   json.RawMessage `json:"payload"`
	Signature []byte          `json:"signature"`
}

func (c *Core) Routes(ctx context.Context) (SignedSnapshot, error) {
	if e := c.ready(); e != nil {
		return SignedSnapshot{}, e
	}
	if len(c.SnapshotKey) != 64 {
		return SignedSnapshot{}, security.ErrUnavailable
	}
	t, e := c.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if e != nil {
		return SignedSnapshot{}, security.ErrUnavailable
	}
	defer t.Rollback()
	snap := RouteSnapshot{IssuedAt: time.Now().UTC(), Routes: []Route{}}
	if e = t.QueryRowContext(ctx, `SELECT revision FROM fabric.route_state WHERE singleton`).Scan(&snap.Revision); e != nil {
		return SignedSnapshot{}, security.ErrUnavailable
	}
	rows, e := t.QueryContext(ctx, `SELECT installation,signature FROM fabric.contracts WHERE revoked_at IS NULL ORDER BY digest`)
	if e != nil {
		return SignedSnapshot{}, security.ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var s SignedInstallation
		if rows.Scan(&s.Payload, &s.Signature) != nil {
			return SignedSnapshot{}, security.ErrUnavailable
		}
		_, m, e := c.verify(s)
		if e != nil {
			return SignedSnapshot{}, e
		}
		for _, o := range m.Manifest.Operations {
			if o.HTTP.Expose {
				snap.Routes = append(snap.Routes, Route{o.HTTP.Method, o.HTTP.Path, m.Manifest.Service.Name, o.ID, o.Subject, m.Digest, o.HTTP.SuccessStatus})
			}
		}
	}
	if rows.Err() != nil {
		return SignedSnapshot{}, security.ErrUnavailable
	}
	rows.Close()
	sort.Slice(snap.Routes, func(i, j int) bool {
		return snap.Routes[i].Method+snap.Routes[i].Path < snap.Routes[j].Method+snap.Routes[j].Path
	})
	raw, _ := json.Marshal(snap)
	raw, e = security.CanonicalJSON(raw)
	if e != nil {
		return SignedSnapshot{}, e
	}
	if e = t.Commit(); e != nil {
		return SignedSnapshot{}, security.ErrUnavailable
	}
	return SignedSnapshot{raw, ed25519.Sign(c.SnapshotKey, raw)}, nil
}
func VerifySnapshot(key ed25519.PublicKey, s SignedSnapshot, minRevision int64) (RouteSnapshot, error) {
	var snap RouteSnapshot
	raw, e := security.CanonicalJSON(s.Payload)
	if len(key) != 32 || e != nil || !ed25519.Verify(key, raw, s.Signature) {
		return snap, security.ErrUnauthenticated
	}
	if contract.Strict(raw, &snap) != nil || snap.Revision < minRevision {
		return RouteSnapshot{}, security.ErrDenied
	}
	return snap, nil
}
