package service_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/module"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/sdk/service"
	"github.com/pavlith/arc/sdk/testcontract"
)

type denyRegistry struct{ calls int }

func (d *denyRegistry) Register(context.Context, *nats.Conn, sdk.Registration) error {
	d.calls++
	return errors.New("not approved")
}
func (d *denyRegistry) Ready(context.Context, sdk.Registration, sdk.ReadyEvidence) error {
	return errors.New("not approved")
}
func (d *denyRegistry) Check(context.Context, sdk.Registration) error {
	return errors.New("not approved")
}

type testModule struct {
	id   string
	bind func(*module.Registry) error
}

func (m testModule) ID() string                        { return m.id }
func (m testModule) Register(r *module.Registry) error { return m.bind(r) }

type request struct {
	RootID string `json:"root_id"`
	Value  string `json:"value"`
}
type response struct {
	Value string `json:"value"`
}

func policy() module.Policy {
	return module.Policy{Resource: func(context.Context, string, string) error { return security.ErrDenied }}
}
func read(r *module.Registry) error {
	return module.BindQuery(r, module.Query[request, response]{ID: "books.read"}, policy(),
		func(_ context.Context, q request) (response, error) { return response{q.Value}, nil })
}
func create(r *module.Registry) error {
	return module.BindCommand(r, module.Command[request, response]{ID: "books.create"}, policy(),
		events.Store{DB: &sql.DB{}, Schema: "books"},
		func(_ context.Context, _ *sql.Tx, q request) (response, error) { return response{q.Value}, nil })
}
func config(mods ...module.Module) (service.Config, *denyRegistry) {
	d := &denyRegistry{}
	return service.Config{
		Definition: service.Definition{Name: "books", APIMajor: 1, Kind: service.Domain, Modules: mods},
		Runtime: sdk.AppConfig{
			Artifact: testcontract.Artifact(1),
			Instance: "example", Registry: d,
			Authorize: func(ctx context.Context, _ string, _ []byte) (context.Context, error) { return ctx, nil },
			SelfCheck: func(context.Context) error { return nil },
		},
	}, d
}

func TestComposeFullTypedBindingsWithoutContactingFabric(t *testing.T) {
	cfg, d := config(testModule{"reader", read}, testModule{"writer", create})
	app, err := service.Compose(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if d.calls != 0 {
		t.Fatal("composition contacted Fabric before Start")
	}
	if app.Connection() != nil {
		t.Fatal("composition opened NATS subscription")
	}
	if !errors.Is(app.Wait(context.Background()), service.ErrInvalid) {
		t.Fatal("Wait before Start accepted")
	}
	if err := app.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := app.Stop(); err != nil {
		t.Fatal("Stop must be idempotent", err)
	}
	if !errors.Is(app.Start(context.Background()), service.ErrStopped) {
		t.Fatal("restart after Stop accepted")
	}
}

func TestComposeRejectsIncompleteContractAndUnsafeBindings(t *testing.T) {
	cases := []struct {
		name    string
		modules []module.Module
	}{
		{"missing_command", []module.Module{testModule{"reader", read}}},
		{"duplicate_module", []module.Module{testModule{"both", func(r *module.Registry) error {
			if err := read(r); err != nil {
				return err
			}
			return create(r)
		}}, testModule{"both", func(*module.Registry) error { return nil }}}},
		{"wrong_operation_kind", []module.Module{testModule{"reader", func(r *module.Registry) error {
			return module.BindQuery(r, module.Query[request, response]{ID: "books.create"}, policy(),
				func(context.Context, request) (response, error) { return response{}, nil })
		}}}},
		{"missing_owner_policy", []module.Module{testModule{"reader", func(r *module.Registry) error {
			return module.BindQuery(r, module.Query[request, response]{ID: "books.read"}, module.Policy{},
				func(context.Context, request) (response, error) { return response{}, nil })
		}}}},
		{"unknown_operation", []module.Module{testModule{"reader", func(r *module.Registry) error {
			return module.BindQuery(r, module.Query[request, response]{ID: "books.export"}, policy(),
				func(context.Context, request) (response, error) { return response{}, nil })
		}}}},
		{"duplicate_worker", []module.Module{testModule{"workers", func(r *module.Registry) error {
			w := module.Worker{ID: "publisher", Run: func(context.Context) error { return nil }}
			if err := r.AddWorker(w); err != nil {
				return err
			}
			return r.AddWorker(w)
		}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, d := config(tc.modules...)
			if app, err := service.Compose(cfg); err == nil {
				_ = app.Stop()
				t.Fatal("invalid service composed")
			}
			if d.calls != 0 {
				t.Fatal("invalid composition contacted Fabric")
			}
		})
	}
}

func TestComposeDisallowsUnverifiedPolicyOverrides(t *testing.T) {
	cfg, _ := config(testModule{"reader", read})
	cfg.Runtime.Resource = func(context.Context, string, string) error { return nil }
	if _, err := service.Compose(cfg); !errors.Is(err, service.ErrInvalid) {
		t.Fatal("caller overwrote operation authorization", err)
	}
	cfg, _ = config(testModule{"reader", read})
	cfg.Definition.Name = "notify"
	if _, err := service.Compose(cfg); !errors.Is(err, service.ErrInvalid) {
		t.Fatal("service identity mismatch", err)
	}
}

func TestWorkerRegistryDoesNotGrantAuthority(t *testing.T) {
	cfg, _ := config(testModule{"both", func(r *module.Registry) error {
		if err := read(r); err != nil {
			return err
		}
		if err := create(r); err != nil {
			return err
		}
		return r.AddWorker(module.Worker{ID: "inbox", Run: func(context.Context) error { return nil }})
	}})
	app, err := service.Compose(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Stop(); err != nil {
		t.Fatal(err)
	}
}
