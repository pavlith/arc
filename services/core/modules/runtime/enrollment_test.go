package runtime_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/runtime"
)

func prepareEnrollment(t *testing.T, f *controlFixture, node, account, kid string) (runtime.EnrollmentRequest, ed25519.PrivateKey) {
	t.Helper()
	if err := f.db.Exec(
		"INSERT INTO identity_service_accounts(id,service_definition,deployment) VALUES(?,'arc-agent',?)",
		account, node,
	).Error; err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return runtime.EnrollmentRequest{
		Node: runtime.NodeRegistration{
			ID: node, ServiceAccountID: account,
			Capabilities: []agent.Kind{agent.Systemd, agent.Docker},
		},
		Kid: kid, PublicKey: pub, TTL: 5 * time.Minute,
	}, key
}

func TestEnrollmentSingleUseAndCredentialBinding(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	req, key := prepareEnrollment(t, f, "node-three", "node-three-sa", "node-three-key")
	offer, err := f.control.IssueEnrollment(ctx, req)
	if err != nil || offer.Token == "" || offer.ID == "" {
		t.Fatalf("could not issue enrollment: %+v %v", offer, err)
	}
	if err := f.db.Exec("UPDATE runtime_enrollment_offers SET token_hash='tampered' WHERE id=?", offer.ID).Error; err == nil {
		t.Fatal("SQLite allowed an enrollment ticket to be modified")
	}
	if err := f.db.Exec("DELETE FROM runtime_enrollment_offers WHERE id=?", offer.ID).Error; err == nil {
		t.Fatal("SQLite allowed enrollment history deletion")
	}
	var stored struct {
		TokenHash string
	}
	if err := f.db.Table("runtime_enrollment_offers").Where("id=?", offer.ID).Take(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if stored.TokenHash == offer.Token || strings.Contains(stored.TokenHash, offer.Token) || len(stored.TokenHash) != 64 {
		t.Fatal("plaintext enrollment token stored in Core")
	}
	if _, err := f.control.IssueEnrollment(ctx, req); !errors.Is(err, runtime.ErrConflict) {
		t.Fatalf("pending offer superseded without revocation: %v", err)
	}
	claim, err := agent.SignEnrollmentClaim(offer.ID, offer.Token, key)
	if err != nil {
		t.Fatal(err)
	}
	bad := claim
	bad.Token = bad.Token[:42] + "!"
	if err := f.control.ClaimEnrollment(ctx, bad); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("wrong secret accepted: %v", err)
	}
	_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bad, err = agent.SignEnrollmentClaim(offer.ID, offer.Token, wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.control.ClaimEnrollment(ctx, bad); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("unapproved signing key accepted: %v", err)
	}
	if countRows(t, f.db, "identity_service_credentials") != 0 {
		t.Fatal("unauthorized claim created an identity credential")
	}
	if err := f.control.ClaimEnrollment(ctx, claim); err != nil {
		t.Fatalf("approved claim failed: %v", err)
	}
	var count int64
	if err := f.db.Table("runtime_nodes").Where("id=? AND service_account_id=?", req.Node.ID, req.Node.ServiceAccountID).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("node not bound: count=%d err=%v", count, err)
	}
	var cred struct {
		PublicKey       []byte
		SecretReference string
	}
	if err := f.db.Table("identity_service_credentials").Where("kid=?", req.Kid).Take(&cred).Error; err != nil {
		t.Fatal(err)
	}
	if string(cred.PublicKey) != string(req.PublicKey) || cred.SecretReference != "operator:enrollment:"+offer.ID {
		t.Fatal("credential not bound to the approved key")
	}
	if err := f.control.ClaimEnrollment(ctx, claim); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("one-time ticket reused: %v", err)
	}
	if err := f.control.RevokeEnrollment(ctx, offer.ID); !errors.Is(err, runtime.ErrConflict) {
		t.Fatalf("already claimed offer revoked: %v", err)
	}
	if err := f.db.Exec("UPDATE runtime_enrollment_offers SET redeemed_at=NULL WHERE id=?", offer.ID).Error; err == nil {
		t.Fatal("claimed ticket reactivated through SQL")
	}
}

func TestEnrollmentTTLRevocationAndAdminPermissions(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	req, key := prepareEnrollment(t, f, "node-expiry", "node-expiry-sa", "node-expiry-key")
	f.policy.denied = true
	if _, err := f.control.IssueEnrollment(ctx, req); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("unauthorized issue accepted: %v", err)
	}
	f.policy.denied = false
	req.TTL = 31 * time.Minute
	if _, err := f.control.IssueEnrollment(ctx, req); !errors.Is(err, runtime.ErrInvalid) {
		t.Fatalf("unbounded TTL accepted: %v", err)
	}
	req.TTL = time.Minute
	offer, err := f.control.IssueEnrollment(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := agent.SignEnrollmentClaim(offer.ID, offer.Token, key)
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Minute)
	if err := f.control.ClaimEnrollment(ctx, claim); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("expired ticket accepted: %v", err)
	}
	next, err := f.control.IssueEnrollment(ctx, req)
	if err != nil || next.ID == offer.ID {
		t.Fatalf("expired offer could not be replaced: %+v %v", next, err)
	}
	f.policy.denied = true
	if err := f.control.RevokeEnrollment(ctx, next.ID); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("unauthorized revocation accepted: %v", err)
	}
	f.policy.denied = false
	if err := f.control.RevokeEnrollment(ctx, next.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.control.RevokeEnrollment(ctx, next.ID); err != nil {
		t.Fatalf("revocation was not idempotent: %v", err)
	}
	claim, err = agent.SignEnrollmentClaim(next.ID, next.Token, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.control.ClaimEnrollment(ctx, claim); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("revoked ticket accepted: %v", err)
	}
}

func TestEnrollmentAtomicRollbackOnAuditFailure(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	req, key := prepareEnrollment(t, f, "node-rollback", "node-rollback-sa", "node-rollback-key")
	offer, err := f.control.IssueEnrollment(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := agent.SignEnrollmentClaim(offer.ID, offer.Token, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.Exec(`CREATE TRIGGER enrollment_audit_fail BEFORE INSERT ON runtime_audit
		WHEN NEW.action='node.enroll.claim' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.control.ClaimEnrollment(ctx, claim); err == nil {
		t.Fatal("claim succeeded despite unavailable audit")
	}
	var rows int64
	if err := f.db.Table("identity_service_credentials").Where("kid=?", req.Kid).Count(&rows).Error; err != nil || rows != 0 {
		t.Fatal("failed claim left an identity credential")
	}
	if err := f.db.Table("runtime_nodes").Where("id=?", req.Node.ID).Count(&rows).Error; err != nil || rows != 0 {
		t.Fatal("failed claim left a registered node")
	}
	if err := f.db.Table("runtime_enrollment_offers").
		Where("id=? AND redeemed_at IS NOT NULL", offer.ID).
		Count(&rows).Error; err != nil || rows != 0 {
		t.Fatal("failed claim consumed the ticket")
	}
	if err := f.db.Exec("DROP TRIGGER enrollment_audit_fail").Error; err != nil {
		t.Fatal(err)
	}
	if err := f.control.ClaimEnrollment(ctx, claim); err != nil {
		t.Fatalf("retry after a rolled-back transaction failed: %v", err)
	}
}

func TestEnrollmentConcurrentClaimAtMostOnce(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	req, key := prepareEnrollment(t, f, "node-concurrent", "node-concurrent-sa", "node-concurrent-key")
	offer, err := f.control.IssueEnrollment(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := agent.SignEnrollmentClaim(offer.ID, offer.Token, key)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 5
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f.control.ClaimEnrollment(ctx, claim) == nil {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("ticket was consumed %d times, want exactly one", success)
	}
}
