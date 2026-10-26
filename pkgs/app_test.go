package pkgs_test

import (
	"context"
	"errors"
	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/pkgs"
	"github.com/pavlith/arc/pkgs/internal/testcontract"
	"testing"
)

type closedRegistry struct{ calls int }

func (r *closedRegistry) Register(context.Context, *nats.Conn, pkgs.Registration) error {
	r.calls++
	return errors.New("not approved")
}
func (r *closedRegistry) Ready(context.Context, pkgs.Registration, pkgs.ReadyEvidence) error {
	return errors.New("not approved")
}
func (r *closedRegistry) Check(context.Context, pkgs.Registration) error {
	return errors.New("not approved")
}
func TestAppRequiresAllHandlersAndTransactionalCommands(t *testing.T) {
	r := &closedRegistry{}
	a, e := pkgs.NewApp(pkgs.AppConfig{Artifact: testcontract.Artifact(1), Instance: "test", Registry: r, SelfCheck: func(context.Context) error { return nil }, Authorize: func(ctx context.Context, _ string, _ []byte) (context.Context, error) { return ctx, nil }, Resource: func(context.Context, string, string) error { return nil }})
	if e != nil {
		t.Fatal(e)
	}
	h := func(context.Context, map[string]any) (map[string]any, error) { return nil, nil }
	if e = pkgs.Handle(a, "books.read", h); e != nil {
		t.Fatal(e)
	}
	if e = pkgs.Handle(a, "books.read", h); e == nil {
		t.Fatal("duplicate binding")
	}
	if e = pkgs.Handle(a, "books.rogue", h); e == nil {
		t.Fatal("rogue binding")
	}
	if e = pkgs.Handle(a, "books.create", h); e == nil {
		t.Fatal("command without domain transaction")
	}
	if e = a.Start(context.Background()); e == nil {
		t.Fatal("missing mandatory command handler")
	}
	if r.calls != 0 {
		t.Fatal("partial app contacted registry")
	}
}
