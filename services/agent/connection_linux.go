package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/json"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/sdk"
	contract "github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/services/core/modules/identity"
)

// nodeConnection owns the private identity signing key and broker connection.
// A preview command has the same node identity and trust root as normal Agent.
type nodeConnection struct {
	connection *nats.Conn
	provider   *contract.NodeClient
	coreKey    ed25519.PublicKey
	key        ed25519.PrivateKey
}

func (c *nodeConnection) Close() {
	if c == nil {
		return
	}
	if c.connection != nil {
		c.connection.Close()
	}
	for i := range c.key {
		c.key[i] = 0
	}
}

func openNodeClient(ctx context.Context, cfg FileConfig) (session *nodeConnection, err error) {
	seed, err := readOwned(cfg.KeyFile, true, ed25519.SeedSize)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, ErrInvalid
	}
	key := ed25519.NewKeyFromSeed(seed)
	for i := range seed {
		seed[i] = 0
	}
	session = &nodeConnection{key: key}
	defer func() {
		if err != nil {
			session.Close()
		}
	}()
	public, err := readOwned(cfg.CoreSnapshotKeyFile, false, 4096)
	if err != nil {
		return nil, ErrInvalid
	}
	if json.Unmarshal(public, &session.coreKey) != nil || len(session.coreKey) != ed25519.PublicKeySize {
		return nil, ErrInvalid
	}
	cfg.NATS.Name = "arc-agent-" + cfg.NodeID
	cfg.NATS.InboxPrefix = "_INBOX.runtime." + cfg.NodeID
	brokerSeed, err := readOwned(cfg.NATS.NKeySeedFile, true, 4096)
	if err != nil {
		return nil, ErrInvalid
	}
	for i := range brokerSeed {
		brokerSeed[i] = 0
	}
	session.connection, err = sdk.Connect(ctx, cfg.NATS)
	if err != nil {
		return nil, ErrUnavailable
	}
	rpcClient, err := rpc.NewClient(session.connection)
	if err != nil {
		return nil, ErrUnavailable
	}
	session.provider, err = contract.NewNodeClient(rpcClient, cfg.NodeID,
		Credentials(identity.Client{
			RPC: rpcClient, ServiceID: cfg.ServiceID, Kid: cfg.Kid, PrivateKey: key,
		}))
	if err != nil {
		return nil, ErrInvalid
	}
	return session, nil
}
