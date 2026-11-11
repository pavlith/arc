package v1

import "testing"

func TestScopeRequiresExplicitKind(t *testing.T) {
	if q := (Scope{RootID: "id"}); q.Kind() != "" || q.Action() != "" {
		t.Fatal("missing kind unexpectedly granted Task read")
	}
	for _, v := range []struct{ kind, action string }{
		{"task", "task.read"}, {"page", "pages.read"}, {"file", "files.read"},
	} {
		if action := (Scope{ResourceKind: v.kind}).Action(); action != v.action {
			t.Fatalf("kind %q action %q; want %q", v.kind, action, v.action)
		}
	}
	if (Scope{ResourceKind: "unknown"}).Action() != "" {
		t.Fatal("unknown kind unexpectedly granted authority")
	}
}
