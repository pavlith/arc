package files

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/pavlith/arc/services/files/migrations"
)

func Migrations() []*gormigrate.Migration { return migrations.SQLite() }
