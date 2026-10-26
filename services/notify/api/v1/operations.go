package v1

import "github.com/pavlith/arc/pkgs/module"

type Empty struct{}

var HealthQuery = module.Query[Empty, Empty]{ID: Health}
