package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	contract "github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/identity"
)

// Credentials obtains each invocation online. Reading our returned JWT's JTI is
// solely for signing proof; the receiver verifies its signature and live state.
func Credentials(client identity.Client) contract.InvocationCredentials {
	return func(ctx context.Context, operation string) (rpc.Credentials, error) {
		if _, err := contract.NodeSubject("node", operation); err != nil {
			return rpc.Credentials{}, ErrInvalid
		}
		token, err := identity.Call[identity.ServiceExchange, identity.TokenResult](ctx, client, "identity.v1.invocations.exchange_service", identity.ServiceExchange{Target: identity.Target{Audience: contract.NodeAudience, Operation: operation}})
		if err != nil {
			return rpc.Credentials{}, ErrUnavailable
		}
		if len(token.Token) > 16384 {
			return rpc.Credentials{}, ErrUnavailable
		}
		parts := strings.Split(token.Token, ".")
		if len(parts) != 3 {
			return rpc.Credentials{}, ErrUnavailable
		}
		raw, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return rpc.Credentials{}, ErrUnavailable
		}
		var claims security.Claims
		if json.Unmarshal(raw, &claims) != nil || claims.JTI == "" || claims.Caller != client.ServiceID || claims.Subject != "service:"+client.ServiceID || claims.Audience != contract.NodeAudience || claims.Operation != operation || claims.Confirmation.Kid != client.Kid || claims.ExpiresAt <= time.Now().Unix() {
			return rpc.Credentials{}, ErrUnavailable
		}
		return rpc.Credentials{Token: token.Token, Proof: func(subject string, raw []byte) (security.Proof, error) {
			random, err := nonce("")
			if err != nil {
				return security.Proof{}, err
			}
			return security.SignProof(client.PrivateKey, subject, raw, claims.JTI, security.Proof{Kid: client.Kid, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Nonce: random})
		}}, nil
	}
}
