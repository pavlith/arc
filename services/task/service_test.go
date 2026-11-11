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
	operations := []string{taskv1.Admin.ID, taskv1.ListGrants.ID,
		taskv1.TeamCreate.ID, taskv1.TeamUpdate.ID, taskv1.TeamArchive.ID, taskv1.TeamGet.ID, taskv1.TeamList.ID,
		taskv1.StatusCreate.ID, taskv1.StatusUpdate.ID, taskv1.StatusDelete.ID, taskv1.StatusList.ID}
	operations = append(operations, taskv1.WorkBulkUpdate.ID, taskv1.WorkLinkChange.ID, taskv1.WorkLinks.ID, taskv1.WorkSetParent.ID, taskv1.WorkCreate.ID, taskv1.WorkUpdate.ID, taskv1.WorkArchive.ID, taskv1.WorkGet.ID, taskv1.WorkList.ID)
	operations = append(operations, taskv1.ProjectCreate.ID, taskv1.ProjectUpdate.ID, taskv1.ProjectArchive.ID, taskv1.ProjectGet.ID, taskv1.ProjectList.ID,
		taskv1.LabelCreate.ID, taskv1.LabelUpdate.ID, taskv1.LabelArchive.ID, taskv1.LabelGet.ID, taskv1.LabelList.ID,
		taskv1.TeamMemberAdd.ID, taskv1.TeamMemberRemove.ID, taskv1.TeamMemberList.ID)
	operations = append(operations, taskv1.TemplateCreate.ID, taskv1.TemplateUpdate.ID, taskv1.TemplateArchive.ID, taskv1.TemplateGet.ID, taskv1.TemplateList.ID, taskv1.TemplateUse.ID, taskv1.WorkTriage.ID)
	operations = append(operations, taskv1.CommentCreate.ID, taskv1.CommentUpdate.ID, taskv1.CommentResolve.ID, taskv1.CommentArchive.ID, taskv1.CommentList.ID, taskv1.WorkHistory.ID,
		taskv1.ViewCreate.ID, taskv1.ViewUpdate.ID, taskv1.ViewArchive.ID, taskv1.ViewGet.ID, taskv1.ViewList.ID)
	operations = append(operations, taskv1.AttachmentChangeOp.ID, taskv1.AttachmentListOp.ID, taskv1.ReferencePreviewOp.ID)
	if len(c.Manifest.Operations) != len(operations) || len(c.Manifest.Events) != 2 {
		t.Fatal("unexpected Task operation or event")
	}
	for _, op := range operations {
		if _, err := c.Operation(op); err != nil {
			t.Fatal(err)
		}
	}
	for _, retired := range []string{"task.task.create", "task.tasks.get", "task.tasks.edit", "task.tasks.list"} {
		if _, err := c.Operation(retired); err == nil {
			t.Fatal("retired proof operation remains approved:", retired)
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
