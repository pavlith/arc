package v1

import "github.com/pavlith/arc/sdk/module"

type Empty struct{}

var HealthQuery = module.Query[Empty, Empty]{ID: Health}
