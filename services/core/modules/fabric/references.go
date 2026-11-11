package fabric

import (
	"strings"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/resource"
	"github.com/pavlith/arc/services/core/modules/access"
)

// referenceReadRule permits only an explicit signed user read edge. The target
// domain still verifies current session, object/root binding and its own ACL.
func referenceReadRule(r access.Rule, account, audience string, compiled *contract.Compiled) bool {
	if r.Caller != account || len(r.ActorKinds) != 1 || r.ActorKinds[0] != "user" || len(r.Actions) != 1 || !resource.ReadTarget(r.Audience, r.Operation, r.Actions[0]) || r.Audience == audience || len(r.DownstreamFrom) == 0 || len(r.DownstreamFrom) != len(r.DownstreamActions) {
		return false
	}
	seen := map[string]bool{}
	for _, src := range r.DownstreamFrom {
		if seen[src] || !strings.HasPrefix(src, audience+":") {
			return false
		}
		seen[src] = true
		op, err := compiled.Operation(strings.TrimPrefix(src, audience+":"))
		actions := r.DownstreamActions[src]
		if err != nil || op.Auth.Mode != "resource" || len(actions) != 1 || actions[0] != r.Actions[0] {
			return false
		}
	}
	return true
}
