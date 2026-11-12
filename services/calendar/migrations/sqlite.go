// Package migrations owns the current calendar SQLite schema.
// Old upgrade chains are intentionally not replayed by this fresh baseline.
package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// SQLite is executed only by the separate owner migrator before traffic.
func SQLite() []*gormigrate.Migration {
	return []*gormigrate.Migration{{
		ID: "000001_calendar_baseline",
		Migrate: func(tx *gorm.DB) error {
			for _, sql := range baselineSchema {
				if err := tx.Exec(sql).Error; err != nil {
					return err
				}
			}
			return nil
		},
	}, {
		ID: "000002_calendar_occurrences",
		Migrate: func(tx *gorm.DB) error {
			for _, sql := range occurrenceSchema {
				if err := tx.Exec(sql).Error; err != nil {
					return err
				}
			}
			return nil
		},
	}, {
		ID: "000003_calendar_objects",
		Migrate: func(tx *gorm.DB) error {
			for _, sql := range objectSchema {
				if err := tx.Exec(sql).Error; err != nil {
					return err
				}
			}
			return nil
		},
	}, {
		ID: "000004_calendar_sync",
		Migrate: func(tx *gorm.DB) error {
			for _, sql := range syncSchema {
				if err := tx.Exec(sql).Error; err != nil {
					return err
				}
			}
			return nil
		},
	}}
}

// Final table definitions, indexes, triggers and required static seed rows.
var baselineSchema = []string{
	`CREATE TABLE roots(acl_root_id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,owner_id TEXT NOT NULL DEFAULT '',state TEXT NOT NULL CHECK(state IN ('prepared','active')),name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 256),timezone TEXT NOT NULL,revision INTEGER NOT NULL CHECK(revision>0),UNIQUE(acl_root_id,workspace_id),CHECK((workspace_id='' AND owner_id<>'') OR (workspace_id<>'' AND owner_id='')))`,
	`CREATE TABLE calendar_events(id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,title TEXT NOT NULL CHECK(length(trim(title)) BETWEEN 1 AND 256),description TEXT NOT NULL,timezone TEXT NOT NULL,all_day INTEGER NOT NULL CHECK(all_day IN (0,1)),start TEXT NOT NULL,end TEXT NOT NULL,start_at DATETIME NOT NULL,end_at DATETIME NOT NULL CHECK(end_at>start_at),busy INTEGER NOT NULL CHECK(busy IN (0,1)),revision INTEGER NOT NULL CHECK(revision>0),created_at DATETIME NOT NULL,updated_at DATETIME NOT NULL,deleted_at DATETIME,FOREIGN KEY(acl_root_id,workspace_id) REFERENCES roots(acl_root_id,workspace_id))`,
	`CREATE TABLE audit(id INTEGER PRIMARY KEY AUTOINCREMENT,workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,entity_id TEXT NOT NULL,actor TEXT NOT NULL,operation TEXT NOT NULL,revision INTEGER NOT NULL,created_at DATETIME NOT NULL)`,
	`CREATE TABLE command_results(actor TEXT NOT NULL,operation TEXT NOT NULL,idempotency_key TEXT NOT NULL,request_hash BLOB NOT NULL CHECK(length(request_hash)=32),result BLOB,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(actor,operation,idempotency_key))`,
	`CREATE TABLE outbox(event_id TEXT PRIMARY KEY,subject TEXT NOT NULL CHECK(subject='evt.calendar.catalog.changed.v1'),envelope BLOB NOT NULL,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,published_at DATETIME)`,
	`CREATE INDEX calendar_outbox_pending ON outbox(created_at,event_id) WHERE published_at IS NULL`,
	`CREATE INDEX calendar_event_range ON calendar_events(workspace_id,acl_root_id,start_at,end_at,id) WHERE deleted_at IS NULL`,
}

// Existing single events become one effective occurrence; tombstones stay hidden.
var occurrenceSchema = []string{
	`ALTER TABLE calendar_events ADD COLUMN r_rule TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE calendar_events ADD COLUMN exceptions TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(exceptions))`,
	`CREATE UNIQUE INDEX calendar_event_binding ON calendar_events(id,workspace_id,acl_root_id)`,
	`CREATE TABLE event_occurrences(id INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT NOT NULL,workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,recurrence_id TEXT NOT NULL,start TEXT NOT NULL,end TEXT NOT NULL,start_at DATETIME NOT NULL,end_at DATETIME NOT NULL CHECK(end_at>start_at),busy INTEGER NOT NULL CHECK(busy IN (0,1)),UNIQUE(event_id,recurrence_id),FOREIGN KEY(event_id,workspace_id,acl_root_id) REFERENCES calendar_events(id,workspace_id,acl_root_id))`,
	`INSERT INTO event_occurrences(event_id,workspace_id,acl_root_id,recurrence_id,start,end,start_at,end_at,busy) SELECT id,workspace_id,acl_root_id,start,start,end,start_at,end_at,busy FROM calendar_events WHERE deleted_at IS NULL`,
	`CREATE INDEX calendar_occurrence_range ON event_occurrences(workspace_id,acl_root_id,start_at,end_at,id)`,
}

var objectSchema = []string{
	`ALTER TABLE calendar_events ADD COLUMN uid TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE calendar_events ADD COLUMN i_cal_raw TEXT NOT NULL DEFAULT ''`,
	`UPDATE calendar_events SET uid=id || '@arc'`,
	`CREATE UNIQUE INDEX calendar_uid_binding ON calendar_events(workspace_id,acl_root_id,uid)`,
}

// Existing roots require the explicit owner sync bootstrap before token issuance.
var syncSchema = []string{
	`ALTER TABLE roots ADD COLUMN sync_epoch TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE roots ADD COLUMN sync_revision INTEGER NOT NULL DEFAULT 0 CHECK(sync_revision>=0)`,
	`ALTER TABLE roots ADD COLUMN sync_floor INTEGER NOT NULL DEFAULT 0 CHECK(sync_floor>=0 AND sync_floor<=sync_revision)`,
	`ALTER TABLE roots ADD COLUMN sync_ready INTEGER NOT NULL DEFAULT 0 CHECK(sync_ready IN (0,1))`,
	`CREATE TABLE sync_items(workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,event_id TEXT NOT NULL,sequence INTEGER NOT NULL CHECK(sequence>=0),entry TEXT NOT NULL CHECK(json_valid(entry)),PRIMARY KEY(workspace_id,acl_root_id,event_id),FOREIGN KEY(event_id,workspace_id,acl_root_id) REFERENCES calendar_events(id,workspace_id,acl_root_id))`,
	`CREATE TABLE sync_changes(workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,sequence INTEGER NOT NULL CHECK(sequence>0),event_id TEXT NOT NULL,previous TEXT CHECK(previous IS NULL OR json_valid(previous)),entry TEXT NOT NULL CHECK(json_valid(entry)),PRIMARY KEY(workspace_id,acl_root_id,sequence),FOREIGN KEY(event_id,workspace_id,acl_root_id) REFERENCES calendar_events(id,workspace_id,acl_root_id))`,
	`CREATE INDEX calendar_sync_history ON sync_changes(workspace_id,acl_root_id,event_id,sequence)`,
}
