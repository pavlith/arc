// Package models defines Core's SQLite persistence records, not API DTOs.
package models

import "time"

// DesiredDeployment is the Runtime module's SQLite owner-local record.
// The schema is versioned by services/core/migrations, not AutoMigrate.
type DesiredDeployment struct {
 ID string `gorm:"column:id;primaryKey"`
 ServiceName string `gorm:"column:service_name;not null"`
 Spec string `gorm:"column:spec;not null"`
 Replicas int `gorm:"column:replicas;not null"`
 Revision int64 `gorm:"column:revision;not null"`
 UpdatedAt time.Time `gorm:"column:updated_at;not null"`
}

func (DesiredDeployment) TableName() string { return "runtime_desired_deployments" }
