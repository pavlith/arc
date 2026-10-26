package notify

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/pavlith/arc/services/notify/migrations"
)

// Migrations returns the owner's explicit ordered schema migrations.
func Migrations() []*gormigrate.Migration { return migrations.SQLite() }
