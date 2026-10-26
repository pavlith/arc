package client_test

import (
	"context"
	"errors"
	"testing"

	"github.com/pavlith/arc/pkgs/client"
	"github.com/pavlith/arc/pkgs/contract"
	"github.com/pavlith/arc/pkgs/internal/testcontract"
	"github.com/pavlith/arc/pkgs/module"
	"github.com/pavlith/arc/pkgs/rpc"
)

func TestTypedCallRejectsWrongOperationBeforeTransport(t *testing.T) {
	c, err := client.New(&rpc.Client{}, testcontract.Artifact(1))
	if err != nil {
		t.Fatal(err)
	}
	type req struct {
		RootID string
		Value  string
	}
	type res struct{ Value string }
	if _, err := client.Query(context.Background(), c, module.Query[req, res]{ID: "books.create"}, req{}); !errors.Is(err, contract.ErrInvalid) {
		t.Fatal("command accepted as query", err)
	}
	if _, err := client.Command(context.Background(), c, module.Command[req, res]{ID: "books.read"}, req{}); !errors.Is(err, contract.ErrInvalid) {
		t.Fatal("query accepted as command", err)
	}
	if _, err := client.Query(context.Background(), c, module.Query[req, res]{ID: "books.unknown"}, req{}); !errors.Is(err, contract.ErrInvalid) {
		t.Fatal("unknown operation accepted", err)
	}
	if _, err := client.New(nil, testcontract.Artifact(1)); !errors.Is(err, contract.ErrInvalid) {
		t.Fatal("nil client accepted", err)
	}
}
