package fabric

import (
	"context"
	"time"

	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/security"
)

type Instance struct {
	ID         string
	Account    string
	Digest     string
	Build      string
	LeaseUntil time.Time
}

// Discover returns leased, ready instances only. Contracts/routes do not disappear
// when instances are absent; calls with no responders still return UNAVAILABLE.
func (c *Core) Discover(ctx context.Context, service string, major int) ([]Instance, error) {
	if e := c.ready(); e != nil {
		return nil, e
	}
	rows, e := database.FromContext(ctx, c.GormDB).WithContext(ctx).Raw(`SELECT i.instance_id,i.service_account_id,i.digest,i.build_version,i.lease_until FROM fabric_instances i JOIN fabric_contracts c ON c.digest=i.digest JOIN identity_service_accounts a ON a.id=i.service_account_id WHERE c.service_name=? AND c.api_major=? AND c.revoked_at IS NULL AND a.disabled_at IS NULL AND i.ready AND i.lease_until>? ORDER BY i.instance_id`, service, major, time.Now().UTC()).Rows()
	if e != nil {
		return nil, security.ErrUnavailable
	}
	defer rows.Close()
	out := []Instance{}
	for rows.Next() {
		var i Instance
		if rows.Scan(&i.ID, &i.Account, &i.Digest, &i.Build, &i.LeaseUntil) != nil {
			return nil, security.ErrUnavailable
		}
		out = append(out, i)
	}
	if rows.Err() != nil {
		return nil, security.ErrUnavailable
	}
	return out, nil
}
