package runtime

import (
 "context"
 "database/sql"
 "errors"
 "fmt"
 "time"

 "github.com/pavlith/arc/sdk/database"
 "github.com/pavlith/arc/sdk/security"
 "github.com/pavlith/arc/services/core/models"
 "gorm.io/gorm"
 "gorm.io/gorm/clause"
)

// putGORM performs the entire compare-and-swap in one SQLite write transaction.
// The unique primary key and revision predicate coordinate across processes.
func (m *Module) putGORM(ctx context.Context, want Desired, expected int64) (Desired, error) {
 err := database.RetryBusy(ctx, func() error {
  return m.GormDB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
   if expected == 0 {
    row := models.DesiredDeployment{
     ID: want.ID, ServiceName: want.ServiceName, Spec: string(want.Spec),
     Replicas: want.Replicas, Revision: 1, UpdatedAt: time.Now().UTC(),
    }
    result := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
    if result.Error != nil { return result.Error }
    if result.RowsAffected != 1 { return ErrConflict }
    want.Revision = 1
    return nil
   }
   result := tx.Model(&models.DesiredDeployment{}).
    Where("id=? AND revision=?", want.ID, expected).
    Updates(map[string]any{
     "service_name": want.ServiceName, "spec": string(want.Spec),
     "replicas": want.Replicas, "revision": gorm.Expr("revision+1"),
     "updated_at": time.Now().UTC(),
    })
   if result.Error != nil { return result.Error }
   if result.RowsAffected != 1 { return ErrConflict }
   want.Revision = expected+1
   return nil
  })
 })
 if err != nil {
  if errors.Is(err, ErrConflict) { return Desired{}, ErrConflict }
  return Desired{}, fmt.Errorf("runtime: persist desired state: %w", security.ErrUnavailable)
 }
 return want, nil
}

func (m *Module) getGORM(ctx context.Context, id string) (Desired, error) {
 var row models.DesiredDeployment
 if err := m.GormDB.WithContext(ctx).Where("id=?", id).Take(&row).Error; err != nil {
  if errors.Is(err, gorm.ErrRecordNotFound) { return Desired{}, sql.ErrNoRows }
  return Desired{}, security.ErrUnavailable
 }
 return Desired{
  ID: row.ID, ServiceName: row.ServiceName, Spec: []byte(row.Spec),
  Replicas: row.Replicas, Revision: row.Revision,
 }, nil
}
