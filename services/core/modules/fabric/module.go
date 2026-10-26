package fabric

import (
	"github.com/pavlith/arc/pkgs"
	"github.com/pavlith/arc/pkgs/security"
)

// Fabric owns approval, signed route snapshots, ready leases and event permits.
func (c *Core) ID() string { return "fabric" }
func (c *Core) Bind(s *pkgs.Service) (func(), error) {
	if s == nil || s.Connection() == nil {
		return nil, security.ErrUnavailable
	}
	if err := c.BindRoutes(s); err != nil {
		return nil, err
	}
	return c.BindControl(s.Connection())
}
