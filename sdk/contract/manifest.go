// Package contract validates immutable install artifacts without network loaders.
package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/pavlith/arc/sdk/security"
	schema "github.com/santhosh-tekuri/jsonschema/v6"
)

var ErrInvalid = errors.New("invalid service contract")
var token = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
var version = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$`)
var selector = regexp.MustCompile(`^payload(\.[a-z][a-z0-9_]*)+$`)

type Service struct {
	Name         string `json:"name"`
	BuildVersion string `json:"build_version"`
	APIMajor     int    `json:"api_major"`
}
type Resource struct {
	Type             string   `json:"type"`
	Actions          []string `json:"actions"`
	ShareAction      string   `json:"share_action"`
	CreateAction     string   `json:"create_action"`
	DeleteAction     string   `json:"delete_action"`
	AllowInheritance bool     `json:"allow_inheritance"`
}
type Auth struct {
	Mode         string `json:"mode"`
	ResourceType string `json:"resource_type,omitempty"`
	Action       string `json:"action"`
	ResourceFrom string `json:"resource_from,omitempty"`
}
type Exposure struct {
	Expose bool `json:"expose"`
}
type HTTP struct {
	Expose        bool   `json:"expose"`
	Method        string `json:"method,omitempty"`
	Path          string `json:"path,omitempty"`
	SuccessStatus int    `json:"success_status,omitempty"`
}
type Operation struct {
	ID             string   `json:"id"`
	Kind           string   `json:"kind"`
	Subject        string   `json:"subject"`
	RequestSchema  string   `json:"request_schema"`
	ResponseSchema string   `json:"response_schema"`
	Auth           Auth     `json:"auth"`
	Idempotency    string   `json:"idempotency"`
	TimeoutMS      int      `json:"timeout_ms"`
	HTTP           HTTP     `json:"http"`
	Tool           Exposure `json:"tool"`
	Workflow       Exposure `json:"workflow"`
}
type Event struct {
	Name    string `json:"name"`
	Subject string `json:"subject"`
	Schema  string `json:"schema"`
}
type Manifest struct {
	ManifestVersion int         `json:"manifest_version"`
	Service         Service     `json:"service"`
	Resources       []Resource  `json:"resources"`
	Operations      []Operation `json:"operations"`
	Events          []Event     `json:"events"`
}
type Artifact struct {
	Manifest json.RawMessage            `json:"manifest"`
	Schemas  map[string]json.RawMessage `json:"schemas"`
}
type Compiled struct {
	Manifest Manifest
	Digest   string
	schemas  map[string]*schema.Schema
}

func Strict(raw []byte, v any) error {
	if len(raw) > 256<<10 {
		return ErrInvalid
	}
	if _, e := security.CanonicalJSON(raw); e != nil {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return ErrInvalid
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func namespaced(s string) bool {
	ps := strings.Split(s, ".")
	if len(ps) < 2 {
		return false
	}
	for _, p := range ps {
		if !token.MatchString(p) {
			return false
		}
	}
	return true
}
func schemaPath(s string) bool {
	return strings.HasPrefix(s, "schemas/") && path.Clean(s) == s && !strings.ContainsAny(s, ":\\?#") && strings.HasSuffix(s, ".json")
}

type closedLoader struct{}

func (closedLoader) Load(string) (any, error) {
	return nil, errors.New("external schema loading forbidden")
}
func Compile(a Artifact) (*Compiled, error) {
	var m Manifest
	if Strict(a.Manifest, &m) != nil || m.ManifestVersion != 1 || !token.MatchString(m.Service.Name) || !version.MatchString(m.Service.BuildVersion) || m.Service.APIMajor < 1 || m.Service.APIMajor > 1000 || has([]string{"identity", "access", "fabric", "runtime", "gate", "arc"}, m.Service.Name) || len(m.Operations) == 0 || len(m.Operations) > 100 || len(a.Schemas) > 200 {
		return nil, ErrInvalid
	}
	prefix := fmt.Sprintf("rpc.%s.v%d.", m.Service.Name, m.Service.APIMajor)
	types := map[string]Resource{}
	actions := map[string]bool{}
	for _, r := range m.Resources {
		if !namespaced(r.Type) || !strings.HasPrefix(r.Type, m.Service.Name+".") || types[r.Type].Type != "" || len(r.Actions) == 0 {
			return nil, ErrInvalid
		}
		seen := map[string]bool{}
		for _, act := range r.Actions {
			if !namespaced(act) || seen[act] || (!strings.HasPrefix(act, m.Service.Name+".") && act != "access.grants.manage") {
				return nil, ErrInvalid
			}
			seen[act] = true
			actions[act] = true
		}
		if !seen[r.ShareAction] || !seen[r.CreateAction] || !seen[r.DeleteAction] || !seen["access.grants.manage"] {
			return nil, ErrInvalid
		}
		types[r.Type] = r
	}
	used := map[string]bool{}
	ops := map[string]bool{}
	routes := map[string]bool{}
	httpOps := []HTTP{}
	for _, o := range m.Operations {
		if !namespaced(o.ID) || !strings.HasPrefix(o.ID, m.Service.Name+".") || ops[o.ID] || o.Subject != prefix+strings.TrimPrefix(o.ID, m.Service.Name+".") {
			return nil, ErrInvalid
		}
		ops[o.ID] = true
		if (o.Kind != "query" && o.Kind != "command") || (o.Kind == "query" && (o.TimeoutMS < 1 || o.TimeoutMS > 5000 || o.Idempotency != "none")) || (o.Kind == "command" && (o.TimeoutMS < 1 || o.TimeoutMS > 10000 || o.Idempotency != "required")) {
			return nil, ErrInvalid
		}
		if !actions[o.Auth.Action] {
			return nil, ErrInvalid
		}
		if o.Auth.Mode == "resource" {
			r := types[o.Auth.ResourceType]
			if !has(r.Actions, o.Auth.Action) || !selector.MatchString(o.Auth.ResourceFrom) {
				return nil, ErrInvalid
			}
		} else if o.Auth.Mode != "service" || o.Auth.ResourceType != "" || o.Auth.ResourceFrom != "" {
			return nil, ErrInvalid
		}
		if !schemaPath(o.RequestSchema) || !schemaPath(o.ResponseSchema) {
			return nil, ErrInvalid
		}
		used[o.RequestSchema] = true
		used[o.ResponseSchema] = true
		if o.HTTP.Expose {
			if !has([]string{"GET", "POST", "PUT", "PATCH", "DELETE"}, o.HTTP.Method) || !strings.HasPrefix(o.HTTP.Path, fmt.Sprintf("/api/v%d/%s/", m.Service.APIMajor, m.Service.Name)) || strings.ContainsAny(o.HTTP.Path, "?#*\\") || path.Clean(o.HTTP.Path) != o.HTTP.Path || o.HTTP.SuccessStatus < 200 || o.HTTP.SuccessStatus > 299 {
				return nil, ErrInvalid
			}
			key := o.HTTP.Method + " " + regexp.MustCompile(`\{[^/{}]+\}`).ReplaceAllString(o.HTTP.Path, "{}")
			if routes[key] {
				return nil, ErrInvalid
			}
			for _, prev := range httpOps {
				if RoutesOverlap(prev, o.HTTP) {
					return nil, ErrInvalid
				}
			}
			httpOps = append(httpOps, o.HTTP)
			routes[key] = true
		} else if o.HTTP.Method != "" || o.HTTP.Path != "" || o.HTTP.SuccessStatus != 0 {
			return nil, ErrInvalid
		}
	}
	events := map[string]bool{}
	for _, ev := range m.Events {
		p := strings.Split(ev.Name, ".")
		if len(p) != 3 || p[0] != m.Service.Name || !namespaced(ev.Name) || ev.Subject != fmt.Sprintf("evt.%s.v%d", ev.Name, m.Service.APIMajor) || events[ev.Name] || !schemaPath(ev.Schema) {
			return nil, ErrInvalid
		}
		events[ev.Name] = true
		used[ev.Schema] = true
	}
	if len(used) != len(a.Schemas) {
		return nil, ErrInvalid
	}
	compiler := schema.NewCompiler()
	compiler.UseLoader(closedLoader{})
	compiler.AssertFormat()
	hashes := map[string]string{}
	paths := []string{}
	for name, raw := range a.Schemas {
		if !used[name] {
			return nil, ErrInvalid
		}
		canonical, e := security.CanonicalJSON(raw)
		if e != nil || len(raw) > 256<<10 {
			return nil, ErrInvalid
		}
		doc, e := schema.UnmarshalJSON(bytes.NewReader(raw))
		if e != nil {
			return nil, ErrInvalid
		}
		// Only artifact-local references are allowed, including nested schemas.
		if !safeRefs(doc) {
			return nil, ErrInvalid
		}
		if e = compiler.AddResource("https://arc.invalid/"+name, doc); e != nil {
			return nil, ErrInvalid
		}
		sum := sha256.Sum256(canonical)
		hashes[name] = hex.EncodeToString(sum[:])
		paths = append(paths, name)
	}
	out := &Compiled{Manifest: m, schemas: map[string]*schema.Schema{}}
	for _, name := range paths {
		s, e := compiler.Compile("https://arc.invalid/" + name)
		if e != nil {
			return nil, fmt.Errorf("%w: schema %s", ErrInvalid, name)
		}
		out.schemas[name] = s
	}
	sort.Strings(paths)
	entries := []any{}
	for _, p := range paths {
		entries = append(entries, struct {
			Path string `json:"path"`
			Hash string `json:"sha256"`
		}{p, hashes[p]})
	}
	raw, _ := json.Marshal(struct {
		Manifest Manifest `json:"manifest"`
		Schemas  []any    `json:"schemas"`
	}{m, entries})
	raw, e := security.CanonicalJSON(raw)
	if e != nil {
		return nil, ErrInvalid
	}
	sum := sha256.Sum256(raw)
	out.Digest = hex.EncodeToString(sum[:])
	return out, nil
}
func safeRefs(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, v := range x {
			if k == "$id" {
				return false
			}
			if k == "$ref" || k == "$dynamicRef" {
				s, ok := v.(string)
				if !ok || strings.ContainsAny(s, ":\\") || strings.HasPrefix(s, "/") || strings.Contains(s, "..") {
					return false
				}
			}
			if !safeRefs(v) {
				return false
			}
		}
	case []any:
		for _, v := range x {
			if !safeRefs(v) {
				return false
			}
		}
	}
	return true
}
func has(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}
func (c *Compiled) Validate(name string, raw []byte) error {
	s := c.schemas[name]
	if s == nil {
		return ErrInvalid
	}
	if _, e := security.CanonicalJSON(raw); e != nil {
		return ErrInvalid
	}
	v, e := schema.UnmarshalJSON(bytes.NewReader(raw))
	if e != nil {
		return ErrInvalid
	}
	return s.Validate(v)
}
func (c *Compiled) Operation(id string) (Operation, error) {
	for _, o := range c.Manifest.Operations {
		if o.ID == id {
			return o, nil
		}
	}
	return Operation{}, ErrInvalid
}
func Extract(raw []byte, sel string) (string, error) {
	if !selector.MatchString(sel) {
		return "", ErrInvalid
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return "", ErrInvalid
	}
	for _, p := range strings.Split(strings.TrimPrefix(sel, "payload."), ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return "", ErrInvalid
		}
		v = m[p]
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", ErrInvalid
	}
	return s, nil
}

// RoutesOverlap compares fixed segments and parameter positions conservatively.
func RoutesOverlap(a, b HTTP) bool {
	if a.Method != b.Method {
		return false
	}
	xs, ys := strings.Split(a.Path, "/"), strings.Split(b.Path, "/")
	if len(xs) != len(ys) {
		return false
	}
	for i, x := range xs {
		y := ys[i]
		param := func(s string) bool { return strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") }
		if x != y && !param(x) && !param(y) {
			return false
		}
	}
	return true
}
