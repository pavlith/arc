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

// Pages snapshots and resource embeds require a second, live read decision.
// This closed compound contract cannot widen arbitrary source operations.
func pagesReadCheck(source contract.Operation, target, action string) bool {
	if target != "access.v1.check" || action != "pages.read" || source.Auth.Mode != "resource" || (source.Auth.ResourceType != "pages.workspace" && source.Auth.ResourceType != "pages.personal") {
		return false
	}
	id := strings.Replace(source.ID, "pages.personal.", "pages.", 1)
	switch id {
	case "pages.pages.create", "pages.templates.use":
		return source.Auth.Action == "pages.create"
	case "pages.pages.update", "pages.pages.restore", "pages.templates.create", "pages.templates.update":
		return source.Auth.Action == "pages.write"
	}
	return false
}

// Personal Notify queries can ask only current content-read decisions. Actor
// identity is retained and Core evaluates the actual target root and membership.
func notifyReadCheck(source contract.Operation, target, action string, r access.Rule) bool {
	if source.Auth.Mode != "service" || len(r.ActorKinds) != 1 || r.ActorKinds[0] != "user" || (action != "task.read" && action != "pages.read" && action != "files.read") {
		return false
	}
	switch source.ID {
	case "notify.inbox.list", "notify.inbox.mark_all_read", "notify.subscriptions.list":
		return target == "access.v1.check_many" && (source.Auth.Action == "notify.read" || source.Auth.Action == "notify.write")
	case "notify.subscriptions.subscribe":
		return target == "access.v1.check" && source.Auth.Action == "notify.write"
	}
	return false
}

func notifyReadRule(r access.Rule, account, audience string, c *contract.Compiled) bool {
	if audience != "notify/v1" || r.Caller != account || r.Audience != "access/v1" || len(r.DownstreamFrom) == 0 || len(r.DownstreamFrom) != len(r.DownstreamActions) || len(r.Actions) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, src := range r.DownstreamFrom {
		if seen[src] || !strings.HasPrefix(src, "notify/v1:") {
			return false
		}
		seen[src] = true
		op, e := c.Operation(strings.TrimPrefix(src, "notify/v1:"))
		if e != nil || len(r.DownstreamActions[src]) == 0 {
			return false
		}
		for _, act := range r.Actions {
			if !notifyReadCheck(op, r.Operation, act, r) {
				return false
			}
		}
	}
	return true
}
