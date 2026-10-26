package contract

import (
	"regexp"
	"strings"
)

var segment = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
var parameter = regexp.MustCompile(`^\{([a-z][a-z0-9_]*)\}$`)

// ValidateHTTP rejects system namespaces and ambiguous/executable bindings.
func ValidateHTTP(h HTTP) error {
	if !h.Expose {
		return nil
	}
	if !strings.HasPrefix(h.Path, "/api/v") || strings.HasPrefix(h.Path, "/api/v1/arc/") || h.Path == "/api/v1/arc" || strings.ContainsAny(h.Path, "%*\\?#") {
		return ErrInvalid
	}
	parts := strings.Split(h.Path, "/")
	if len(parts) < 5 {
		return ErrInvalid
	}
	if has([]string{"arc", "identity", "access", "fabric", "runtime", "gate", "health", "dav", "ws"}, parts[3]) {
		return ErrInvalid
	}
	params := map[string]bool{}
	for _, p := range parts[1:] {
		if match := parameter.FindStringSubmatch(p); match != nil {
			if params[match[1]] {
				return ErrInvalid
			}
			params[match[1]] = true
		} else if !segment.MatchString(p) {
			return ErrInvalid
		}
	}
	names, fields := map[string]bool{}, map[string]bool{}
	for _, b := range h.Bindings {
		if !segment.MatchString(b.Name) || !segment.MatchString(b.Field) || ReservedIdentityField(b.Field) || !has([]string{"string", "integer", "number", "boolean"}, b.Type) || fields[b.Field] || names[b.Source+":"+b.Name] {
			return ErrInvalid
		}
		fields[b.Field] = true
		names[b.Source+":"+b.Name] = true
		if b.Source == "path" {
			if !params[b.Name] || b.Type != "string" {
				return ErrInvalid
			}
		} else if b.Source != "query" {
			return ErrInvalid
		}
	}
	// Legacy manifests may have unbound path parameters; Gate rejects them until
	// explicitly bound. This keeps M0-04 internal contracts readable.
	return nil
}
func ReservedIdentityField(s string) bool {
	return has([]string{"actor", "caller", "on_behalf_of", "scopes", "service_identity", "subject", "delegation_id", "invocation", "auth"}, s)
}
