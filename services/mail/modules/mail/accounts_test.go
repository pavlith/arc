package mail

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/mail/api/v1"
)

func TestAccountCollectionRequiresDirectPersonalUser(t *testing.T) {
	if _, err := collectionUser(context.Background()); err == nil {
		t.Fatal("unverified user accepted")
	}
	for _, tc := range []struct {
		claims  security.Claims
		allowed bool
	}{
		{security.Claims{Subject: "user:" + owner, SessionID: "session"}, true},
		{security.Claims{Subject: "user:" + owner}, false},
		{security.Claims{Subject: "service:" + owner, SessionID: "session"}, false},
		{security.Claims{Subject: "user:" + owner, SessionID: "session", WorkspaceID: root}, false},
		{security.Claims{Subject: "user:" + owner, SessionID: "session", DelegationID: root, OnBehalfOf: owner}, false},
	} {
		tc.claims.Operation = v1.ListAccounts.ID
		authorize := rpc.RemoteInvocationAuthorizer(func(context.Context, string, []byte) (security.Claims, error) { return tc.claims, nil })
		ctx, err := authorize(context.Background(), "fixture", []byte(`{"operation":"mail.personal.accounts.list","auth":"fixture","payload":{"limit":20},"proof":{}}`))
		if err != nil {
			t.Fatal(err)
		}
		user, err := collectionUser(ctx)
		if (err == nil) != tc.allowed || tc.allowed && user != owner {
			t.Fatal("personal actor boundary", tc.claims, err)
		}
	}
}
func TestAccountCreateContractRejectsAuthorityAndCredentials(t *testing.T) {
	s, _, in := fixture(t)
	op, err := s.Contract.Operation(v1.CreatePersonalAccount.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(v1.CreateAccount{AccountInput: in})
	if err := s.Contract.Validate(op.RequestSchema, raw); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"owner_id", "acl_root_id", "generation", "password", "sealed"} {
		var object map[string]any
		_ = json.Unmarshal(raw, &object)
		object[field] = owner
		bad, _ := json.Marshal(object)
		if err := s.Contract.Validate(op.RequestSchema, bad); err == nil {
			t.Fatal("accepted privileged or credential field", field)
		}
	}
}
