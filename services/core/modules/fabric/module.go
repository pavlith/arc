package fabric

import (
	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/security"
)

// Fabric owns approval, signed route snapshots, ready leases and event permits.
func (c *Core) ID() string { return "fabric" }
func (c *Core) Bind(s *sdk.Service) (func(), error) {
	if s == nil || s.Connection() == nil {
		return nil, security.ErrUnavailable
	}
	if err := c.BindRoutes(s); err != nil {
		return nil, err
	}
	return c.BindControl(s.Connection())
}
