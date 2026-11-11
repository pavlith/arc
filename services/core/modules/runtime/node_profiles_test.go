package runtime_test

import (
	"context"
	"database/sql"
	"errors"
		"testing"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/runtime"
)

func managedNodeProfile() agent.NodeProfile {
	return agent.NodeProfile{
		ID: "standard", Revision: 1, Ubuntu: []string{"24.04", "26.04"},
		Packages: []agent.PackagePin{{Name: "curl", Version: "8.5.0-2ubuntu10.6"}},
		Docker: true,
		Updates: agent.UpdatePolicy{Security: "unattended", Packages: "manual", Reboot: "manual"},
	}
}

func TestNodeProfileImmutableAdminRevisionAndRevocation(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	p := managedNodeProfile()
	if err := f.control.ApproveNodeProfile(ctx, "node-one", p); err != nil {
		t.Fatal(err)
	}
	if err := f.control.ApproveNodeProfile(ctx, "node-one", p); err != nil {
		t.Fatalf("identical retry was not idempotent: %v", err)
	}
	if countRows(t, f.db, "runtime_node_profiles") != 1 {
		t.Fatal("duplicate profile row persisted")
	}
	got, err := f.control.NodeProfile(ctx, "node-one", p.ID, p.Revision)
	if err != nil || got.NodeID != "node-one" || got.Digest != agent.NodeProfileDigest(p) || got.Revoked ||
		got.Profile.Revision != p.Revision {
		t.Fatalf("approved profile read failed: %+v %v", got, err)
	}
	changed := p
	changed.Docker = false
	if err := f.control.ApproveNodeProfile(ctx, "node-one", changed); !errors.Is(err, runtime.ErrConflict) {
		t.Fatalf("same revision changed profile: %v", err)
	}
	skipped := p
	skipped.Revision = 3
	if err := f.control.ApproveNodeProfile(ctx, "node-one", skipped); !errors.Is(err, runtime.ErrConflict) {
		t.Fatalf("skipped revision: %v", err)
	}
	next := p
	next.Revision = 2
	next.LXD = true
	if err := f.control.ApproveNodeProfile(ctx, "node-one", next); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Exec("UPDATE runtime_node_profiles SET spec='{}' WHERE node_id=? AND id=? AND revision=1", "node-one", p.ID).Error; err == nil {
		t.Fatal("profile contents mutated directly in SQLite")
	}
	if err := f.db.Exec("DELETE FROM runtime_node_profiles WHERE node_id=? AND id=? AND revision=1", "node-one", p.ID).Error; err == nil {
		t.Fatal("profile history deleted directly in SQLite")
	}
	if err := f.control.RevokeNodeProfile(ctx, "node-one", p.ID, 1); err != nil {
		t.Fatal(err)
	}
	revoked, err := f.control.NodeProfile(ctx, "node-one", p.ID, 1)
	if err != nil || !revoked.Revoked {
		t.Fatalf("revocation did not persist: %+v %v", revoked, err)
	}
	if err := f.control.RevokeNodeProfile(ctx, "node-one", p.ID, 1); err != nil {
		t.Fatalf("idempotent revocation: %v", err)
	}
	if err := f.control.ApproveNodeProfile(ctx, "node-one", p); !errors.Is(err, runtime.ErrConflict) {
		t.Fatalf("revoked revision reactivated: %v", err)
	}
	if err := f.db.Exec("UPDATE runtime_node_profiles SET revoked=0 WHERE node_id=? AND id=? AND revision=1", "node-one", p.ID).Error; err == nil {
		t.Fatal("SQLite allowed revocation rollback")
	}
	if countRows(t, f.db, "runtime_node_profiles") != 2 {
		t.Fatal("unexpected profile history row count")
	}
}

func TestNodeProfilePolicyAndNodeBinding(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	p := managedNodeProfile()
	if _, err := f.control.NodeProfile(ctx, "node-one", p.ID, 1); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing profile: %v", err)
	}
	f.policy.denied = true
	if err := f.control.ApproveNodeProfile(ctx, "node-one", p); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("unauthorized approval: %v", err)
	}
	if _, err := f.control.NodeProfile(ctx, "node-one", p.ID, 1); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("unauthorized read: %v", err)
	}
	f.policy.denied = false
	bad := p
	bad.Packages[0].Name = "--force"
	if err := f.control.ApproveNodeProfile(ctx, "node-one", bad); !errors.Is(err, runtime.ErrInvalid) {
		t.Fatalf("invalid package name accepted: %v", err)
	}
	if err := f.control.ApproveNodeProfile(ctx, "nonexistent", p); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("unregistered node accepted: %v", err)
	}
	if err := f.control.ApproveNodeProfile(ctx, "node-two", p); err != nil {
		t.Fatal(err)
	}
	if _, err := f.control.NodeProfile(ctx, "node-one", p.ID, 1); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("profile leaked to another node: %v", err)
	}
	row, err := f.control.NodeProfile(ctx, "node-two", p.ID, 1)
	if err != nil || row.Digest != agent.NodeProfileDigest(p) || row.Profile.ID != p.ID {
		t.Fatalf("own node profile unavailable: %+v %v", row, err)
	}
}
