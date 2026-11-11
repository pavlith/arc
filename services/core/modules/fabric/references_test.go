package fabric

import (
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/testcontract"
	"github.com/pavlith/arc/services/core/modules/access"
	notifyv1 "github.com/pavlith/arc/services/notify/api/v1"
	"testing"
)

func TestReferenceReadEdgesAreExactUserReads(t *testing.T) {
	c, err := contract.Compile(testcontract.Artifact(1))
	if err != nil {
		t.Fatal(err)
	}
	source := "books/v1:" + c.Manifest.Operations[0].ID
	r := access.Rule{Caller: "provider", Audience: "files/v1", Operation: "files.files.get", ActorKinds: []string{"user"}, Actions: []string{"files.read"}, DownstreamFrom: []string{source}, DownstreamActions: map[string][]string{source: {"files.read"}}}
	if !referenceReadRule(r, "provider", "books/v1", c) {
		t.Fatal("exact user read rejected")
	}
	for _, change := range []func(*access.Rule){
		func(r *access.Rule) { r.Operation = "files.uploads.abort" }, func(r *access.Rule) { r.Actions = []string{"files.write"} },
		func(r *access.Rule) { r.ActorKinds = []string{"service"} }, func(r *access.Rule) { r.Caller = "other" },
		func(r *access.Rule) { r.DownstreamFrom = []string{"books/v1:missing"} }, func(r *access.Rule) {
			r.DownstreamActions = map[string][]string{source: {"files.read"}, "other": {"files.read"}}
		},
	} {
		bad := r
		change(&bad)
		if referenceReadRule(bad, "provider", "books/v1", c) {
			t.Fatalf("unsafe edge accepted: %+v", bad)
		}
	}
}

func TestPagesCompoundReadCheckDoesNotWidenOtherSources(t *testing.T) {
	op := contract.Operation{ID: "pages.templates.use", Auth: contract.Auth{Mode: "resource", ResourceType: "pages.workspace", Action: "pages.create"}}
	if !pagesReadCheck(op, "access.v1.check", "pages.read") {
		t.Fatal("template compound read rejected")
	}
	op.Auth.Action = "pages.delete"
	if pagesReadCheck(op, "access.v1.check", "pages.read") {
		t.Fatal("mismatched source action accepted")
	}
	op.Auth.Action = "pages.create"
	op.ID = "pages.pages.archive"
	if pagesReadCheck(op, "access.v1.check", "pages.read") {
		t.Fatal("unrelated source widened")
	}
}

func TestNotifyReadChecksAreClosedUserOnly(t *testing.T) {
	op := contract.Operation{ID: "notify.inbox.list", Auth: contract.Auth{Mode: "service", Action: "notify.read"}}
	r := access.Rule{ActorKinds: []string{"user"}}
	for _, a := range []string{"task.read", "pages.read", "files.read"} {
		if !notifyReadCheck(op, "access.v1.check_many", a, r) {
			t.Fatal(a)
		}
	}
	for _, change := range []func(){func() { op.ID = "notify.health" }, func() { op.Auth.Action = "notify.create" }, func() { r.ActorKinds = []string{"service"} }} {
		old, oldR := op, r
		change()
		if notifyReadCheck(op, "access.v1.check_many", "files.read", r) {
			t.Fatal("unsafe source accepted")
		}
		op, r = old, oldR
	}
	if notifyReadCheck(op, "access.v1.grants.add", "files.read", r) || notifyReadCheck(op, "access.v1.check_many", "files.write", r) {
		t.Fatal("write widened")
	}
}

func TestNotifyPolicyAllowsOnlyExplicitReadSources(t *testing.T) {
	c, e := contract.Compile(notifyv1.Artifact())
	if e != nil {
		t.Fatal(e)
	}
	src := "notify/v1:" + notifyv1.InboxList.ID
	r := access.Rule{Caller: "provider", Audience: "access/v1", Operation: "access.v1.check_many", ActorKinds: []string{"user"}, Actions: []string{"task.read", "pages.read", "files.read"}, DownstreamFrom: []string{src}, DownstreamActions: map[string][]string{src: {"task.read", "pages.read", "files.read"}}}
	if !notifyReadRule(r, "provider", "notify/v1", c) {
		t.Fatal("explicit rule denied")
	}
	for _, mutate := range []func(*access.Rule){func(r *access.Rule) { r.Caller = "other" }, func(r *access.Rule) { r.ActorKinds = []string{"service"} }, func(r *access.Rule) { r.Actions = []string{"files.write"} }, func(r *access.Rule) { r.Operation = "access.v1.grants.add" }, func(r *access.Rule) { r.DownstreamFrom = []string{"notify/v1:notify.health"} }, func(r *access.Rule) {
		r.DownstreamActions = map[string][]string{src: {"files.read"}, "notify/v1:notify.health": {"files.read"}}
	}} {
		bad := r
		mutate(&bad)
		if notifyReadRule(bad, "provider", "notify/v1", c) {
			t.Fatal("unsafe rule accepted", bad)
		}
	}
}
