package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/resource"
	"github.com/pavlith/arc/services/core/models"
)

func TestAvatarReceiptRequiresFilesOwnerSessionAndLiveKey(t *testing.T) {
	db := identitySQLiteDB(t)
	c := &Core{GormDB: db}
	ctx := context.Background()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	provider := "10000000-0000-4000-8000-000000000001"
	if err := db.Create(&models.IdentityServiceAccount{ID: provider, ServiceDefinition: "files", Deployment: "test"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.IdentityServiceCredential{Kid: "files-key", ServiceAccountID: provider, PublicKey: pub, SecretReference: "fixture", NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}).Error; err != nil {
		t.Fatal(err)
	}
	claim := resource.AvatarClaim{Ref: resource.Ref{Kind: "file", RootID: "10000000-0000-4000-8000-000000000002", ID: "10000000-0000-4000-8000-000000000003"}, Provider: provider, Kid: "files-key", UserID: "alice", SessionID: "session-a", ExpiresAt: now.Add(time.Minute)}
	receipt, err := resource.SignAvatar(key, claim)
	if err != nil {
		t.Fatal(err)
	}
	user := Session{ID: "session-a", UserID: "alice"}
	ref, err := c.avatarRef(ctx, user, receipt)
	if err != nil || ref == nil || ref.ID != claim.Ref.ID {
		t.Fatalf("valid receipt: %+v %v", ref, err)
	}
	for _, session := range []Session{{ID: "session-a", UserID: "bob"}, {ID: "different", UserID: "alice"}} {
		if _, err := c.avatarRef(ctx, session, receipt); err == nil {
			t.Fatal("receipt crossed user/session")
		}
	}
	claim.ExpiresAt = now.Add(-time.Second)
	expired, _ := resource.SignAvatar(key, claim)
	if _, err := c.avatarRef(ctx, user, expired); err == nil {
		t.Fatal("expired receipt accepted")
	}
	if err := db.Model(&models.IdentityServiceCredential{}).Where("kid=?", "files-key").Update("revoked_at", now).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := c.avatarRef(ctx, user, receipt); err == nil {
		t.Fatal("revoked provider key accepted")
	}
	if ref, err := c.avatarRef(ctx, user, ""); err != nil || ref != nil {
		t.Fatal("clear avatar rejected")
	}
	external := "https://evil.example/image"
	if avatarPath(&external) != nil {
		t.Fatal("unchecked URL exposed")
	}
}
