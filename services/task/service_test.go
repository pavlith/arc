package task_test

import (
	"strings"
	"testing"

	"github.com/pavlith/arc/pkgs/contract"
	"github.com/pavlith/arc/services/task"
	tasksv1 "github.com/pavlith/arc/services/task/api/v1"
)

func TestTaskApprovedArtifactAndTypedBindings(t *testing.T) {
	c, err := contract.Compile(tasksv1.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	if c.Manifest.Service.Name != "tasks" || c.Manifest.Service.APIMajor != 1 {
		t.Fatal("unexpected Tasks Fabric identity", c.Manifest.Service)
	}
	if len(c.Manifest.Operations) != 4 || len(c.Manifest.Events) != 1 {
		t.Fatal("changed M0-06 operation/event boundary")
	}
	for _, op := range []string{tasksv1.Create.ID, tasksv1.Get.ID, tasksv1.List.ID, tasksv1.Admin.ID} {
		if _, err := c.Operation(op); err != nil {
			t.Fatal(err)
		}
	}
	if c.Manifest.Events[0].Subject != tasksv1.CreatedSubject {
		t.Fatal("event subject changed")
	}
}
func TestTaskNewFailsClosedWithoutCredentials(t *testing.T) {
	if _, err := task.New(task.Config{}); err == nil {
		t.Fatal("empty dependencies accepted")
	}
}
func TestTaskMigrationsOwnedLocally(t *testing.T) {
	b, err := task.Migrations.ReadFile("migrations/000001_tasks.up.sql")
	if err != nil || len(b) == 0 {
		t.Fatal("missing service-local migration", err)
	}
	if strings.Contains(string(b), "CREATE TABLE notifications.") {
		t.Fatal("cross-owner schema migration")
	}
}
