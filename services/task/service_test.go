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
	operations := []string{taskv1.Create.ID, taskv1.Get.ID, taskv1.List.ID, taskv1.Edit.ID, taskv1.Admin.ID, taskv1.ListGrants.ID,
		taskv1.TeamCreate.ID, taskv1.TeamUpdate.ID, taskv1.TeamArchive.ID, taskv1.TeamGet.ID, taskv1.TeamList.ID,
		taskv1.StatusCreate.ID, taskv1.StatusUpdate.ID, taskv1.StatusDelete.ID, taskv1.StatusList.ID}
	operations = append(operations, taskv1.WorkCreate.ID, taskv1.WorkUpdate.ID, taskv1.WorkArchive.ID, taskv1.WorkGet.ID, taskv1.WorkList.ID)
	if len(c.Manifest.Operations) != len(operations) || len(c.Manifest.Events) != 2 {
		t.Fatal("unexpected Task operation or event")
	}
	for _, op := range operations {
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
