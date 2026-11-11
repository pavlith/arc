package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func attachments() *gormigrate.Migration {
	return &gormigrate.Migration{ID: "000009_attachments", Migrate: func(tx *gorm.DB) error {
		return tx.Exec(`CREATE TABLE task_attachments (
 task_id TEXT NOT NULL REFERENCES tasks(id),workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,
 file_root_id TEXT NOT NULL,file_id TEXT NOT NULL,
 PRIMARY KEY(task_id,file_root_id,file_id),
 FOREIGN KEY(acl_root_id,workspace_id) REFERENCES roots(acl_root_id,workspace_id))`).Error
	}}
}
