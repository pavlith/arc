package access

import "github.com/pavlith/arc/sdk"

func (c *Core) ID() string { return "access" }
func (c *Core) Bind(s *sdk.Service) (func(), error) {
	return nil, c.BindInternal(s)
}
