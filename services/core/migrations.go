package core

import "embed"

// Migrations contains the complete Core-owned bootstrap, Identity, ACL, Fabric,
// and Runtime schemas. Migration ordering is explicit and never run on import.
//go:embed migrations/*.up.sql
var Migrations embed.FS
