// Package migrations owns the current task SQLite schema.
// Old upgrade chains are intentionally not replayed by this fresh baseline.
package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// SQLite is executed only by the separate owner migrator before traffic.
func SQLite() []*gormigrate.Migration {
	return []*gormigrate.Migration{{
		ID: "000001_baseline",
		Migrate: func(tx *gorm.DB) error {
			for _, sql := range baselineSchema {
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
	`CREATE TABLE audit (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					task_id TEXT NOT NULL REFERENCES tasks(id),
					actor TEXT NOT NULL, operation TEXT NOT NULL, request_id TEXT NOT NULL,
					traceparent TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
				)`,
	`CREATE TABLE command_results (
					actor TEXT NOT NULL, operation TEXT NOT NULL, idempotency_key TEXT NOT NULL,
					request_hash BLOB NOT NULL CHECK(length(request_hash)=32),
					result BLOB, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
					PRIMARY KEY(actor,operation,idempotency_key)
				)`,
	`CREATE TABLE labels(id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,
				name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 128),color TEXT NOT NULL DEFAULT '',
				revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),created_at DATETIME NOT NULL,updated_at DATETIME NOT NULL,archived_at DATETIME,
				UNIQUE(id,workspace_id,acl_root_id),FOREIGN KEY(acl_root_id,workspace_id) REFERENCES roots(acl_root_id,workspace_id))`,
	`CREATE TABLE outbox (
				event_id TEXT PRIMARY KEY,
				subject TEXT NOT NULL CHECK(subject IN ('evt.task.task.created.v1','evt.task.catalog.changed.v1')),
				envelope BLOB NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, published_at DATETIME)`,
	`CREATE TABLE product_audit (
				id INTEGER PRIMARY KEY AUTOINCREMENT, workspace_id TEXT NOT NULL, acl_root_id TEXT NOT NULL,
				entity_kind TEXT NOT NULL, entity_id TEXT NOT NULL, actor TEXT NOT NULL,
				operation TEXT NOT NULL, revision INTEGER NOT NULL,
				request_id TEXT NOT NULL, traceparent TEXT NOT NULL, created_at DATETIME NOT NULL, fields_changed TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(fields_changed)))`,
	`CREATE TABLE projects (
				id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,team_id TEXT,
				name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 128),description TEXT NOT NULL DEFAULT '',color TEXT NOT NULL DEFAULT '',
				status TEXT NOT NULL CHECK(status IN ('planned','active','paused','completed','cancelled')),start_date DATETIME,due_date DATETIME,
				revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),created_at DATETIME NOT NULL,updated_at DATETIME NOT NULL,archived_at DATETIME,
				UNIQUE(id,workspace_id,acl_root_id),FOREIGN KEY(acl_root_id,workspace_id) REFERENCES roots(acl_root_id,workspace_id),
				FOREIGN KEY(team_id,workspace_id,acl_root_id) REFERENCES teams(id,workspace_id,acl_root_id))`,
	`CREATE TABLE roots (
					acl_root_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL,
					state TEXT NOT NULL CHECK(state IN ('prepared','active')),
					UNIQUE(acl_root_id,workspace_id)
				)`,
	`CREATE TABLE saved_views(id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,owner_id TEXT NOT NULL,
			name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 128),description TEXT NOT NULL DEFAULT '',
			filters TEXT NOT NULL CHECK(json_valid(filters)),is_shared BOOLEAN NOT NULL DEFAULT 0,
			revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),created_at DATETIME NOT NULL,updated_at DATETIME NOT NULL,archived_at DATETIME,
			FOREIGN KEY(acl_root_id,workspace_id) REFERENCES roots(acl_root_id,workspace_id))`,
	`CREATE TABLE task_assignees(task_id TEXT NOT NULL REFERENCES task_details(task_id),user_id TEXT NOT NULL,PRIMARY KEY(task_id,user_id))`,
	`CREATE TABLE task_attachments (
 task_id TEXT NOT NULL REFERENCES tasks(id),workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,
 file_root_id TEXT NOT NULL,file_id TEXT NOT NULL,
 PRIMARY KEY(task_id,file_root_id,file_id),
 FOREIGN KEY(acl_root_id,workspace_id) REFERENCES roots(acl_root_id,workspace_id))`,
	`CREATE TABLE task_comments(id TEXT PRIMARY KEY,task_id TEXT NOT NULL,workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,
			parent_id TEXT,author_id TEXT NOT NULL,body TEXT NOT NULL CHECK(length(trim(body)) BETWEEN 1 AND 15000),
			resolved BOOLEAN NOT NULL DEFAULT 0,revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),created_at DATETIME NOT NULL,updated_at DATETIME NOT NULL,archived_at DATETIME,
			UNIQUE(id,task_id,workspace_id,acl_root_id),FOREIGN KEY(task_id,workspace_id,acl_root_id) REFERENCES tasks(id,workspace_id,acl_root_id),
			FOREIGN KEY(parent_id,task_id,workspace_id,acl_root_id) REFERENCES task_comments(id,task_id,workspace_id,acl_root_id))`,
	`CREATE TABLE task_details (
				task_id TEXT PRIMARY KEY REFERENCES tasks(id),workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,
				team_id TEXT NOT NULL,status_id TEXT NOT NULL,identifier TEXT NOT NULL,
				description TEXT NOT NULL DEFAULT '',priority INTEGER NOT NULL DEFAULT 0 CHECK(priority BETWEEN 0 AND 4),
				due_date DATETIME,sort_order INTEGER NOT NULL DEFAULT 0 CHECK(sort_order>=0),
				revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),archived_at DATETIME, project_id TEXT REFERENCES projects(id),
				UNIQUE(workspace_id,identifier),
				FOREIGN KEY(task_id,workspace_id,acl_root_id) REFERENCES tasks(id,workspace_id,acl_root_id),
				FOREIGN KEY(team_id,workspace_id,acl_root_id) REFERENCES teams(id,workspace_id,acl_root_id),
				FOREIGN KEY(status_id,team_id,workspace_id,acl_root_id) REFERENCES workflow_statuses(id,team_id,workspace_id,acl_root_id))`,
	`CREATE TABLE task_labels(task_id TEXT NOT NULL,workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,label_id TEXT NOT NULL,
				PRIMARY KEY(task_id,label_id),FOREIGN KEY(task_id,workspace_id,acl_root_id) REFERENCES task_details(task_id,workspace_id,acl_root_id),
				FOREIGN KEY(label_id,workspace_id,acl_root_id) REFERENCES labels(id,workspace_id,acl_root_id))`,
	`CREATE TABLE task_links(source_id TEXT NOT NULL,target_id TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('related','blocks','duplicate_of')),workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,
 PRIMARY KEY(source_id,target_id,kind),CHECK(source_id<>target_id),CHECK(kind<>'related' OR source_id<target_id),
 FOREIGN KEY(source_id,workspace_id,acl_root_id) REFERENCES tasks(id,workspace_id,acl_root_id),
 FOREIGN KEY(target_id,workspace_id,acl_root_id) REFERENCES tasks(id,workspace_id,acl_root_id))`,
	`CREATE TABLE task_parents(task_id TEXT PRIMARY KEY, parent_id TEXT NOT NULL, workspace_id TEXT NOT NULL, acl_root_id TEXT NOT NULL,
    CHECK(task_id<>parent_id),
    FOREIGN KEY(task_id,workspace_id,acl_root_id) REFERENCES tasks(id,workspace_id,acl_root_id),
    FOREIGN KEY(parent_id,workspace_id,acl_root_id) REFERENCES tasks(id,workspace_id,acl_root_id))`,
	`CREATE TABLE tasks (
					id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, acl_root_id TEXT NOT NULL,
					title TEXT NOT NULL CHECK(length(trim(title)) BETWEEN 1 AND 300),
					status TEXT NOT NULL DEFAULT 'open' CHECK(status='open'),
					created_by TEXT NOT NULL, created_at DATETIME NOT NULL,
					updated_at DATETIME NOT NULL,
					FOREIGN KEY(acl_root_id,workspace_id) REFERENCES roots(acl_root_id,workspace_id),
					CHECK(updated_at >= created_at)
				)`,
	`CREATE TABLE team_members(team_id TEXT NOT NULL,workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,user_id TEXT NOT NULL,created_at DATETIME NOT NULL,
				PRIMARY KEY(team_id,user_id),FOREIGN KEY(team_id,workspace_id,acl_root_id) REFERENCES teams(id,workspace_id,acl_root_id))`,
	`CREATE TABLE teams (
				id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, acl_root_id TEXT NOT NULL,
				name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 128),
				key TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', color TEXT NOT NULL DEFAULT '',
				revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),
				created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, archived_at DATETIME, sequence INTEGER NOT NULL DEFAULT 0 CHECK(sequence>=0),
				UNIQUE(workspace_id,key), UNIQUE(id,workspace_id,acl_root_id),
				FOREIGN KEY(acl_root_id,workspace_id) REFERENCES roots(acl_root_id,workspace_id))`,
	`CREATE TABLE work_templates (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, acl_root_id TEXT NOT NULL, team_id TEXT NOT NULL, name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 128), definition TEXT NOT NULL CHECK(json_valid(definition) AND json_type(definition)='object'), revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0), created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, archived_at DATETIME, FOREIGN KEY(team_id,workspace_id,acl_root_id) REFERENCES teams(id,workspace_id,acl_root_id), FOREIGN KEY(acl_root_id,workspace_id) REFERENCES roots(acl_root_id,workspace_id))`,
	`CREATE TABLE workflow_statuses (
				id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, acl_root_id TEXT NOT NULL, team_id TEXT NOT NULL,
				name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 128),
				category TEXT NOT NULL CHECK(category IN ('backlog','todo','in_progress','in_review','done','cancelled')),
				color TEXT NOT NULL DEFAULT '', position INTEGER NOT NULL DEFAULT 0 CHECK(position>=0),
				is_default BOOLEAN NOT NULL DEFAULT 0, revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),
				created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, archived_at DATETIME,
				UNIQUE(id,team_id,workspace_id,acl_root_id),
				FOREIGN KEY(team_id,workspace_id,acl_root_id) REFERENCES teams(id,workspace_id,acl_root_id))`,
	`CREATE INDEX labels_root ON labels(workspace_id,acl_root_id,id)`,
	`CREATE INDEX product_task_history ON product_audit(workspace_id,acl_root_id,entity_kind,entity_id,id)`,
	`CREATE INDEX projects_root ON projects(workspace_id,acl_root_id,id)`,
	`CREATE INDEX saved_views_scope ON saved_views(workspace_id,acl_root_id,id)`,
	`CREATE INDEX task_assignees_user ON task_assignees(user_id,task_id)`,
	`CREATE INDEX task_comments_scope ON task_comments(task_id,id)`,
	`CREATE INDEX task_details_root ON task_details(workspace_id,acl_root_id,task_id)`,
	`CREATE UNIQUE INDEX task_details_scope ON task_details(task_id,workspace_id,acl_root_id)`,
	`CREATE UNIQUE INDEX task_duplicate_target ON task_links(source_id) WHERE kind='duplicate_of'`,
	`CREATE INDEX task_labels_filter ON task_labels(label_id,task_id)`,
	`CREATE INDEX task_links_target ON task_links(target_id,source_id)`,
	`CREATE INDEX task_parent_children ON task_parents(parent_id,task_id)`,
	`CREATE INDEX task_pending_outbox ON outbox(created_at,event_id) WHERE published_at IS NULL`,
	`CREATE UNIQUE INDEX task_scope_unique ON tasks(id,workspace_id,acl_root_id)`,
	`CREATE INDEX task_workspace_user ON tasks(workspace_id,acl_root_id,created_by,created_at,id)`,
	`CREATE INDEX teams_root ON teams(workspace_id,acl_root_id,id)`,
	`CREATE INDEX work_templates_scope ON work_templates(workspace_id,acl_root_id,id)`,
	`CREATE UNIQUE INDEX workflow_one_default ON workflow_statuses(team_id) WHERE is_default=1 AND archived_at IS NULL`,
	`CREATE INDEX workflow_team ON workflow_statuses(team_id,position,id)`,
	`CREATE TRIGGER task_project_insert BEFORE INSERT ON task_details WHEN NEW.project_id IS NOT NULL AND NOT EXISTS(
				SELECT 1 FROM projects p WHERE p.id=NEW.project_id AND p.workspace_id=NEW.workspace_id AND p.acl_root_id=NEW.acl_root_id AND (p.team_id IS NULL OR p.team_id=NEW.team_id)) BEGIN SELECT RAISE(ABORT,'project scope mismatch'); END`,
	`CREATE TRIGGER task_project_update BEFORE UPDATE OF project_id,team_id,workspace_id,acl_root_id ON task_details WHEN NEW.project_id IS NOT NULL AND NOT EXISTS(
				SELECT 1 FROM projects p WHERE p.id=NEW.project_id AND p.workspace_id=NEW.workspace_id AND p.acl_root_id=NEW.acl_root_id AND (p.team_id IS NULL OR p.team_id=NEW.team_id)) BEGIN SELECT RAISE(ABORT,'project scope mismatch'); END`,
}
