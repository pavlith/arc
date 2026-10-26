package notify

import "embed"

// Migrations are applied by the service's owner-specific migrator role.
//
//go:embed migrations/*.up.sql
var Migrations embed.FS
