package task_test

import (
	"testing"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/services/task"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
)

func TestTaskApprovedArtifactAndTypedBindings(t *testing.T) {
	c, err := contract.Compile(taskv1.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	if c.Manifest.Service.Name != "task" || c.Manifest.Service.APIMajor != 1 {
		t.Fatal("unexpected Tasks Fabric identity", c.Manifest.Service)
	}
	if len(c.Manifest.Operations) != 4 || len(c.Manifest.Events) != 1 {
		t.Fatal("changed M0-06 operation/event boundary")
	}
	for _, op := range []string{taskv1.Create.ID, taskv1.Get.ID, taskv1.List.ID, taskv1.Admin.ID} {
		if _, err := c.Operation(op); err != nil {
			t.Fatal(err)
		}
	}
	if c.Manifest.Events[0].Subject != taskv1.CreatedSubject {
		t.Fatal("event subject changed")
	}
}
func TestTaskNewFailsClosedWithoutCredentials(t *testing.T) {
	if _, err := task.New(task.Config{}); err == nil {
		t.Fatal("empty dependencies accepted")
	}
}
func TestTaskMigrationsOwnedLocally(t *testing.T) {
	if len(task.Migrations()) == 0 {
		t.Fatal("missing owner migrations")
	}
}
