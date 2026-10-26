package identity

import "github.com/pavlith/arc/sdk"

// ID is the stable in-process module identity, not a service-account identity.
func (c *Core) ID() string { return "identity" }
func (c *Core) Bind(s *sdk.Service) (func(), error) {
	return nil, c.BindInternal(s)
}
