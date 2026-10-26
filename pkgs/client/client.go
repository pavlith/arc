// Package client provides schema-checked, strongly typed RPC calls.
package client

import (
    "context"

    "github.com/pavlith/arc/pkgs/contract"
    "github.com/pavlith/arc/pkgs/module"
    "github.com/pavlith/arc/pkgs/rpc"
)

type Client struct {
    RPC *rpc.Client
    Approved *contract.Compiled
}

func New(rpcClient *rpc.Client, artifact contract.Artifact) (*Client, error) {
    if rpcClient == nil { return nil, contract.ErrInvalid }
    compiled, err := contract.Compile(artifact)
    if err != nil { return nil, err }
    return &Client{RPC: rpcClient, Approved: compiled}, nil
}

func call[Req, Res any](ctx context.Context, c *Client, id, kind string, req Req) (Res, error) {
    var zero Res
    if c == nil || c.RPC == nil || c.Approved == nil || id == "" {
        return zero, contract.ErrInvalid
    }
    op, err := c.Approved.Operation(id)
    if err != nil || op.Kind != kind { return zero, contract.ErrInvalid }
    return rpc.CallValidated[Req, Res](ctx, c.RPC, id, op.Subject, req,
        func(raw []byte) error { return c.Approved.Validate(op.RequestSchema, raw) },
        func(raw []byte) error { return c.Approved.Validate(op.ResponseSchema, raw) })
}

func Query[Req, Res any](ctx context.Context, c *Client, op module.Query[Req, Res], req Req) (Res, error) {
    return call[Req, Res](ctx, c, op.ID, "query", req)
}

func Command[Req, Res any](ctx context.Context, c *Client, op module.Command[Req, Res], req Req) (Res, error) {
    // Caller must supply the original idempotency key and signed credentials.
    return call[Req, Res](ctx, c, op.ID, "command", req)
}
