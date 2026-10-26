package access

import "github.com/pavlith/arc/pkgs"

func (c *Core) ID() string { return "access" }
func (c *Core) Bind(s *pkgs.Service) (func(), error) {
    return nil, c.BindInternal(s)
}
