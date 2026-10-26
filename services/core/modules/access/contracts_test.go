package access

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"

	"github.com/pavlith/arc/pkgs/rpc"
	"github.com/pavlith/arc/pkgs/security"
	"github.com/pavlith/arc/services/core/modules/identity"
)

func TestApprovedContracts(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes32(81))
	provider := "00000000-0000-4000-8000-000000000001"
	actor := "user:00000000-0000-4000-8000-000000000002"
	a := Approval{Rules: []Rule{{Caller: provider, Audience: "access/v1", Operation: "access.v1.check", ActorKinds: []string{"user"}, Actions: []string{"calendar.read"}, DownstreamFrom: []string{"calendar/v1:calendar.read"}, DownstreamActions: map[string][]string{"calendar/v1:calendar.read": {"calendar.read"}}}}}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = security.CanonicalJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(key, raw)
	if _, err = NewContracts(key.Public().(ed25519.PublicKey), []Approved{{Payload: raw, Signature: signature}}); err != nil {
		t.Fatal(err)
	}
	for _, signed := range []Approved{{Payload: []byte(`{"rules":[]}`), Signature: signature}, {Payload: raw, Signature: make([]byte, 64)}} {
		if _, err = NewContracts(key.Public().(ed25519.PublicKey), []Approved{signed}); !errors.Is(err, security.ErrUnauthenticated) {
			t.Fatalf("tampered approval accepted: %v", err)
		}
	}
	a.Rules = append(a.Rules, a.Rules[0])
	raw, _ = json.Marshal(a)
	raw, _ = security.CanonicalJSON(raw)
	if _, err = NewContracts(key.Public().(ed25519.PublicKey), []Approved{{Payload: raw, Signature: ed25519.Sign(key, raw)}}); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("ambiguous policy accepted: %v", err)
	}
	// Missing dependencies fail closed.
	c := &Core{}
	if err = c.Authorize(context.Background(), identity.Authorization{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing policy dependency: %v", err)
	}
	contracts := signedContracts(t, key, Approval{Rules: a.Rules[:1]})
	if _, err = contracts.rule(provider, actor, "access/v1", "access.v1.grants.add"); !errors.Is(err, security.ErrDenied) {
		t.Fatal("undeclared operation accepted")
	}
	if _, err = contracts.Type("rogue.root", provider, ""); !errors.Is(err, security.ErrDenied) {
		t.Fatal("undeclared resource type accepted")
	}
	db, err := sql.Open("pgx", "host=/nonexistent dbname=unused")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c = &Core{DB: db, Identity: &identity.Core{DB: db}, Contracts: contracts}
	incoming := security.Claims{Subject: actor, Audience: "calendar/v1", Operation: "calendar.read"}
	auth := identity.Authorization{Caller: provider, Actor: actor, Audience: "access/v1", Operation: "access.v1.check", Incoming: &incoming}
	if err = c.Authorize(context.Background(), auth); err != nil {
		t.Fatalf("approved transition: %v", err)
	}
	for _, forged := range []security.Claims{
		{Subject: "user:00000000-0000-4000-8000-000000000099", Audience: "calendar/v1", Operation: "calendar.read"},
		{Subject: actor, Audience: "wrong/v1", Operation: "calendar.read"},
		{Subject: actor, Audience: "calendar/v1", Operation: "calendar.delete"},
		{Subject: actor, Audience: "calendar/v1", Operation: "calendar.read", WorkspaceID: provider},
	} {
		auth.Incoming = &forged
		if err = c.Authorize(context.Background(), auth); !errors.Is(err, ErrDenied) {
			t.Fatalf("forged downstream accepted: %v", err)
		}
	}
	c.Contracts = signedContracts(t, key, Approval{AdminUsers: []string{actor[5:]}, Deployments: []Deployment{{"calendar", "approved-instance"}}})
	for _, instance := range []string{"approved-instance", "rogue-instance"} {
		err = c.Authorize(context.Background(), identity.Authorization{Actor: actor, Audience: "calendar", Operation: "deployment.approved", Resources: []string{instance}})
		if instance == "approved-instance" && err != nil || instance == "rogue-instance" && !errors.Is(err, ErrDenied) {
			t.Fatalf("deployment %s: %v", instance, err)
		}
	}
	var client *Client
	if _, err = client.Check(context.Background(), CheckRequest{}); rpc.ErrorCode(err) != rpc.CodeUnavailable {
		t.Fatalf("missing Access client: %v", err)
	}
}
