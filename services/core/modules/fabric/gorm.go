package fabric

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"sort"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/access"
	"gorm.io/gorm"
)

// readyGORM enforces a single Core owner database for Fabric and Identity.
// These references must not be independently configured to different SQLite files.
func (c *Core) readyGORM() error {
	if c == nil || c.GormDB == nil || c.Identity == nil ||
		c.Identity.GormDB != c.GormDB || len(c.ApprovalKey) != ed25519.PublicKeySize {
		return security.ErrUnavailable
	}
	return nil
}

func (c *Core) activeGORM(ctx context.Context, account, digest string) (*contract.Compiled, error) {
	if err := c.readyGORM(); err != nil {
		return nil, err
	}
	var signed SignedInstallation
	err := c.GormDB.WithContext(ctx).Raw(
		`SELECT c.installation,c.signature FROM fabric_contracts c
		JOIN fabric_deployments d ON d.digest=c.digest
		JOIN identity_service_accounts a ON a.id=d.service_account_id
		WHERE c.digest=? AND d.service_account_id=?
		AND c.revoked_at IS NULL AND a.disabled_at IS NULL`,
		digest, account,
	).Row().Scan(&signed.Payload, &signed.Signature)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, security.ErrDenied
	}
	if err != nil {
		return nil, security.ErrUnavailable
	}
	installation, manifest, err := c.verify(signed)
	if err != nil {
		return nil, err
	}
	if installation.Account != account {
		return nil, security.ErrDenied
	}
	return manifest, nil
}

func (c *Core) loadAccessGORM(ctx context.Context) (*access.Contracts, error) {
	if err := c.readyGORM(); err != nil {
		return nil, err
	}
	for _, signed := range c.Bootstrap {
		var policy access.Approval
		if contract.Strict(signed.Payload, &policy) != nil || len(policy.Types) != 0 {
			return nil, security.ErrDenied
		}
		for _, rule := range policy.Rules {
			if rule.Audience != "identity/v1" &&
				!(rule.Audience == "fabric/v1" && rule.Operation == "fabric.v1.routes") {
				return nil, security.ErrDenied
			}
		}
	}
	approved := append([]access.Approved(nil), c.Bootstrap...)
	rows, err := c.GormDB.WithContext(ctx).Raw(
		"SELECT installation,signature FROM fabric_contracts WHERE revoked_at IS NULL ORDER BY digest",
	).Rows()
	if err != nil {
		return nil, security.ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var signed SignedInstallation
		if err := rows.Scan(&signed.Payload, &signed.Signature); err != nil {
			return nil, security.ErrUnavailable
		}
		installation, _, err := c.verify(signed)
		if err != nil {
			return nil, err
		}
		approved = append(approved, installation.Policy)
	}
	if rows.Err() != nil {
		return nil, security.ErrUnavailable
	}
	return access.NewContracts(c.ApprovalKey, approved)
}

func (c *Core) routesGORM(ctx context.Context) (SignedSnapshot, error) {
	if err := c.readyGORM(); err != nil {
		return SignedSnapshot{}, err
	}
	if len(c.SnapshotKey) != ed25519.PrivateKeySize {
		return SignedSnapshot{}, security.ErrUnavailable
	}
	snap := RouteSnapshot{
		IssuedAt: time.Now().UTC(),
		Routes:   []Route{},
		Artifacts: map[string]contract.Artifact{},
	}
	// Read route-state revision and contracts from the same WAL read snapshot.
	err := c.GormDB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Raw("SELECT revision FROM fabric_route_state WHERE singleton=1").
			Row().Scan(&snap.Revision); err != nil {
			return err
		}
		rows, err := tx.Raw(
			"SELECT installation,signature FROM fabric_contracts WHERE revoked_at IS NULL ORDER BY digest",
		).Rows()
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var signed SignedInstallation
			if err := rows.Scan(&signed.Payload, &signed.Signature); err != nil {
				return err
			}
			installed, compiled, err := c.verify(signed)
			if err != nil {
				return err
			}
			for _, op := range compiled.Manifest.Operations {
				if !op.HTTP.Expose {
					continue
				}
				snap.Routes = append(snap.Routes, Route{
					Method: op.HTTP.Method, Path: op.HTTP.Path,
					Service: compiled.Manifest.Service.Name, Operation: op.ID,
					Subject: op.Subject, Digest: compiled.Digest,
					SuccessStatus: op.HTTP.SuccessStatus,
					APIMajor: compiled.Manifest.Service.APIMajor, Bindings: op.HTTP.Bindings,
				})
				snap.Artifacts[compiled.Digest] = installed.Artifact
			}
		}
		return rows.Err()
	})
	if err != nil {
		return SignedSnapshot{}, security.ErrUnavailable
	}
	sort.Slice(snap.Routes, func(i, j int) bool {
		return snap.Routes[i].Method+snap.Routes[i].Path <
			snap.Routes[j].Method+snap.Routes[j].Path
	})
	kid := c.SnapshotKid
	if kid == "" {
		kid = "fabric-snapshot-v1"
	} else {
		key, err := c.Identity.SigningKey(ctx, kid)
		if err != nil || key.Revoked || time.Now().Before(key.NotBefore) ||
			!time.Now().Before(key.ExpiresAt) ||
			!ed25519.PublicKey(c.SnapshotKey.Public().(ed25519.PublicKey)).Equal(key.Public) {
			return SignedSnapshot{}, security.ErrUnavailable
		}
	}
	return SignSnapshot(snap, kid, c.SnapshotKey)
}
