package fabric

import (
	"context"
	"time"

	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/security"
)

// registerInstanceGORM never trusts an instance announcement as identity.
// It only reclaims an existing instance ID if its owner, digest and build match.
func (c *Core) registerInstanceGORM(ctx context.Context, account string, reg sdk.Registration) error {
	if err := c.readyGORM(); err != nil {
		return err
	}
	now := time.Now().UTC()
	result := c.GormDB.WithContext(ctx).Exec(
		`INSERT INTO fabric_instances
		(instance_id,service_account_id,digest,build_version,ready,lease_until,observed_at)
		VALUES(?,?,?,?,0,?,?)
		ON CONFLICT(instance_id) DO UPDATE SET
		ready=0, lease_until=excluded.lease_until, observed_at=excluded.observed_at
		WHERE fabric_instances.service_account_id=excluded.service_account_id
		AND fabric_instances.digest=excluded.digest
		AND fabric_instances.build_version=excluded.build_version`,
		reg.Instance, account, reg.Digest, reg.Build, now.Add(30*time.Second), now,
	)
	if result.Error != nil {
		return security.ErrUnavailable
	}
	if result.RowsAffected != 1 {
		return security.ErrDenied
	}
	return nil
}

func (c *Core) touchGORM(ctx context.Context, account string, reg sdk.Registration, ready bool) error {
	if err := c.readyGORM(); err != nil {
		return err
	}
	now := time.Now().UTC()
	result := c.GormDB.WithContext(ctx).Exec(
		`UPDATE fabric_instances
		SET ready=1, lease_until=?, observed_at=?
		WHERE instance_id=? AND service_account_id=? AND digest=?
		AND build_version=? AND lease_until>? AND (? OR ready=1)`,
		now.Add(30*time.Second), now,
		reg.Instance, account, reg.Digest, reg.Build, now, ready,
	)
	if result.Error != nil {
		return security.ErrUnavailable
	}
	if result.RowsAffected != 1 {
		return security.ErrDenied
	}
	return nil
}

func (c *Core) installationGORM(ctx context.Context, digest string) ([]byte, error) {
	if err := c.readyGORM(); err != nil {
		return nil, err
	}
	var raw []byte
	err := c.GormDB.WithContext(ctx).Raw(
		"SELECT installation FROM fabric_contracts WHERE digest=? AND revoked_at IS NULL", digest,
	).Row().Scan(&raw)
	if err != nil {
		return nil, security.ErrUnavailable
	}
	return raw, nil
}
