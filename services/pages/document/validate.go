// Package document validates the closed Arc Tiptap JSON vocabulary.
package document

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/resource"
	"github.com/pavlith/arc/sdk/security"
)

type Node struct {
	Type    string                     `json:"type"`
	Attrs   map[string]json.RawMessage `json:"attrs,omitempty"`
	Text    string                     `json:"text,omitempty"`
	Content []Node                     `json:"content,omitempty"`
	Marks   []Mark                     `json:"marks,omitempty"`
}
type Mark struct {
	Type  string                     `json:"type"`
	Attrs map[string]json.RawMessage `json:"attrs,omitempty"`
}

func Validate(raw json.RawMessage) ([]resource.Ref, error) {
	if len(raw) > 65536 || len(raw) == 0 {
		return nil, security.ErrDenied
	}
	encoded, err := json.Marshal(raw)
	if err != nil || len(encoded) > 65536 {
		return nil, security.ErrDenied
	}
	canonical, err := security.CanonicalJSON(raw)
	if err != nil {
		return nil, security.ErrDenied
	}
	var root Node
	if contract.Strict(canonical, &root) != nil || root.Type != "doc" {
		return nil, security.ErrDenied
	}
	refs := []resource.Ref{}
	seen := map[resource.Ref]bool{}
	count := 0
	var visit func(Node, int) bool
	visit = func(n Node, depth int) bool {
		count++
		if depth > 32 || count > 2000 {
			return false
		}
		allowed := map[string]bool{}
		leaf := false
		switch n.Type {
		case "doc", "paragraph", "blockquote", "bulletList", "listItem", "taskList", "table", "tableRow":
		case "heading":
			allowed["level"] = true
			if !integer(n.Attrs["level"], 1, 6) {
				return false
			}
		case "orderedList":
			allowed["start"] = true
			if v := n.Attrs["start"]; v != nil && !integer(v, 1, 1000000) {
				return false
			}
		case "taskItem":
			allowed["checked"] = true
			var b bool
			if v := n.Attrs["checked"]; v != nil && json.Unmarshal(v, &b) != nil {
				return false
			}
		case "codeBlock":
			allowed["language"] = true
			var lang string
			if v := n.Attrs["language"]; v != nil && string(v) != "null" && (json.Unmarshal(v, &lang) != nil || !regexp.MustCompile(`^[a-zA-Z0-9_+-]{0,32}$`).MatchString(lang)) {
				return false
			}
		case "tableCell", "tableHeader":
			for _, k := range []string{"colspan", "rowspan"} {
				allowed[k] = true
				if v := n.Attrs[k]; v != nil && !integer(v, 1, 10) {
					return false
				}
			}
			allowed["colwidth"] = true
			if v := n.Attrs["colwidth"]; v != nil && string(v) != "null" {
				var widths []int
				if json.Unmarshal(v, &widths) != nil || len(widths) > 10 {
					return false
				}
				for _, w := range widths {
					if w < 1 || w > 4096 {
						return false
					}
				}
			}
		case "image", "fileAttachment", "resourceLink":
			leaf = true
			allowed["ref"] = true
			var ref resource.Ref
			if contract.Strict(n.Attrs["ref"], &ref) != nil || !ref.Valid() || (n.Type != "resourceLink" && ref.Kind != "file") {
				return false
			}
			if !seen[ref] {
				seen[ref] = true
				refs = append(refs, ref)
				if len(refs) > 4 {
					return false
				}
			}
			if n.Type == "image" {
				allowed["alt"] = true
				var alt string
				if a := n.Attrs["alt"]; a != nil && string(a) != "null" && (json.Unmarshal(a, &alt) != nil || len(alt) > 1024) {
					return false
				}
			}
		case "text":
			leaf = true
			if n.Text == "" {
				return false
			}
		case "horizontalRule", "hardBreak":
			leaf = true
		default:
			return false
		}
		if n.Type != "text" && (n.Text != "" || len(n.Marks) > 0) {
			return false
		}
		if leaf && len(n.Content) > 0 {
			return false
		}
		for key := range n.Attrs {
			if !allowed[key] {
				return false
			}
		}
		for _, mark := range n.Marks {
			switch mark.Type {
			case "bold", "italic", "strike", "underline", "code":
				if len(mark.Attrs) > 0 {
					return false
				}
			case "link":
				if len(mark.Attrs) != 1 {
					return false
				}
				var href string
				if json.Unmarshal(mark.Attrs["href"], &href) != nil || len(href) > 2048 || strings.ContainsAny(href, "\r\n\x00") {
					return false
				}
				u, err := url.Parse(href)
				if err != nil || u.User != nil || (u.Scheme != "https" || u.Host == "") && (u.Scheme != "mailto" || u.Opaque == "") {
					return false
				}
			default:
				return false
			}
		}
		for _, child := range n.Content {
			if !childAllowed(n.Type, child.Type) || !visit(child, depth+1) {
				return false
			}
		}
		return true
	}
	if !visit(root, 0) {
		return nil, security.ErrDenied
	}
	return refs, nil
}
func integer(raw []byte, min, max int) bool {
	var n int
	return raw != nil && json.Unmarshal(raw, &n) == nil && n >= min && n <= max
}
func childAllowed(parent, child string) bool {
	switch parent {
	case "paragraph", "heading":
		return child == "text" || child == "hardBreak" || child == "resourceLink"
	case "codeBlock":
		return child == "text"
	case "bulletList", "orderedList":
		return child == "listItem"
	case "taskList":
		return child == "taskItem"
	case "table":
		return child == "tableRow"
	case "tableRow":
		return child == "tableCell" || child == "tableHeader"
	case "doc", "blockquote", "listItem", "taskItem", "tableCell", "tableHeader":
		switch child {
		case "paragraph", "heading", "blockquote", "bulletList", "orderedList", "taskList", "codeBlock", "table", "horizontalRule", "image", "fileAttachment", "resourceLink":
			return true
		}
	}
	return false
}
