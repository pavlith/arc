package contract

import (
	"encoding/json"
	"reflect"

	"github.com/pavlith/arc/sdk/security"
)

// Compatible is conservative: existing endpoints, resource semantics, events and
// responses stay identical. Requests may add optional object properties. More
// complex schema evolution requires a new major instead of guessed subsumption.
func Compatible(oldArtifact, newArtifact Artifact) bool {
	old, e := Compile(oldArtifact)
	if e != nil {
		return false
	}
	next, e := Compile(newArtifact)
	if e != nil {
		return false
	}
	if old.Manifest.Service.Name != next.Manifest.Service.Name || old.Manifest.Service.APIMajor != next.Manifest.Service.APIMajor {
		return false
	}
	for _, raw := range oldArtifact.Schemas {
		if hasRef(raw) {
			for name, prior := range oldArtifact.Schemas {
				if !sameJSON(prior, newArtifact.Schemas[name]) {
					return false
				}
			}
			break
		}
	}
	for _, r := range old.Manifest.Resources {
		found := false
		for _, n := range next.Manifest.Resources {
			if n.Type == r.Type {
				found = reflect.DeepEqual(r, n)
			}
		}
		if !found {
			return false
		}
	}
	for _, o := range old.Manifest.Operations {
		n, e := next.Operation(o.ID)
		if e != nil || !reflect.DeepEqual(o, n) || !sameJSON(oldArtifact.Schemas[o.ResponseSchema], newArtifact.Schemas[n.ResponseSchema]) || !additiveRequest(oldArtifact.Schemas[o.RequestSchema], newArtifact.Schemas[n.RequestSchema]) {
			return false
		}
	}
	for _, ev := range old.Manifest.Events {
		found := false
		for _, n := range next.Manifest.Events {
			if reflect.DeepEqual(ev, n) && sameJSON(oldArtifact.Schemas[ev.Schema], newArtifact.Schemas[n.Schema]) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	// References can hide constraints outside the root schema. Conservatively pin
	// all unchanged schema resources used through a reference.
	for name, raw := range oldArtifact.Schemas {
		if hasRef(raw) && !sameJSON(raw, newArtifact.Schemas[name]) {
			return false
		}
	}
	return true
}
func sameJSON(a, b []byte) bool {
	x, e := security.CanonicalJSON(a)
	if e != nil {
		return false
	}
	y, e := security.CanonicalJSON(b)
	return e == nil && string(x) == string(y)
}
func hasRef(raw []byte) bool {
	var v any
	_ = json.Unmarshal(raw, &v)
	var walk func(any) bool
	walk = func(v any) bool {
		switch x := v.(type) {
		case map[string]any:
			for k, v := range x {
				if k == "$ref" || k == "$dynamicRef" {
					return true
				}
				if walk(v) {
					return true
				}
			}
		case []any:
			for _, v := range x {
				if walk(v) {
					return true
				}
			}
		}
		return false
	}
	return walk(v)
}
func additiveRequest(a, b []byte) bool {
	if sameJSON(a, b) {
		return true
	}
	if hasRef(a) || hasRef(b) {
		return false
	}
	var old, next map[string]json.RawMessage
	if json.Unmarshal(a, &old) != nil || json.Unmarshal(b, &next) != nil {
		return false
	}
	var op, np map[string]json.RawMessage
	if json.Unmarshal(old["properties"], &op) != nil || json.Unmarshal(next["properties"], &np) != nil {
		return false
	}
	for k, p := range op {
		if !sameJSON(p, np[k]) {
			return false
		}
	}
	var or, nr []string
	if json.Unmarshal(old["required"], &or) != nil || json.Unmarshal(next["required"], &nr) != nil {
		return false
	}
	for _, r := range nr {
		if !has(or, r) {
			return false
		}
	}
	delete(old, "properties")
	delete(next, "properties")
	delete(old, "required")
	delete(next, "required")
	x, _ := json.Marshal(old)
	y, _ := json.Marshal(next)
	return sameJSON(x, y)
}
