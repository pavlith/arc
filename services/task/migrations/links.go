package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func links() *gormigrate.Migration {
	return &gormigrate.Migration{ID: "000007_links", Migrate: func(tx *gorm.DB) error {
		for _, q := range []string{
			`CREATE TABLE task_links(source_id TEXT NOT NULL,target_id TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('related','blocks','duplicate_of')),workspace_id TEXT NOT NULL,acl_root_id TEXT NOT NULL,
 PRIMARY KEY(source_id,target_id,kind),CHECK(source_id<>target_id),CHECK(kind<>'related' OR source_id<target_id),
 FOREIGN KEY(source_id,workspace_id,acl_root_id) REFERENCES tasks(id,workspace_id,acl_root_id),
 FOREIGN KEY(target_id,workspace_id,acl_root_id) REFERENCES tasks(id,workspace_id,acl_root_id))`,
			`CREATE INDEX task_links_target ON task_links(target_id,source_id)`,
			`CREATE UNIQUE INDEX task_duplicate_target ON task_links(source_id) WHERE kind='duplicate_of'`,
		} {
			if err := tx.Exec(q).Error; err != nil {
				return err
			}
		}
		return nil
	}}
}
