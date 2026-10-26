package notify_test

import (
	"testing"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/services/notify"
	notifyv1 "github.com/pavlith/arc/services/notify/api/v1"
)

func TestNotifyApprovedArtifact(t *testing.T) {
	compiled, err := contract.Compile(notifyv1.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Manifest.Service.Name != "notify" ||
		compiled.Manifest.Service.APIMajor != 1 || len(compiled.Manifest.Operations) != 1 {
		t.Fatal("Notifications contract diverged from M0-06")
	}
	if _, err := compiled.Operation(notifyv1.HealthQuery.ID); err != nil {
		t.Fatal(err)
	}
}
func TestNotifyNewFailsClosed(t *testing.T) {
	if _, err := notify.New(notify.Config{}); err == nil {
		t.Fatal("empty dependencies accepted")
	}
}
func TestNotifyMigrationsOwnedLocally(t *testing.T) {
	if len(notify.Migrations()) == 0 {
		t.Fatal("missing owner migrations")
	}
}
