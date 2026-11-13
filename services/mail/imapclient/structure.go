package imapclient

import (
	"context"
	"encoding/json"
	"fmt"
	"mime"
	"strconv"
	"strings"
)

// StructureQuery binds a UID to its exact mailbox namespace.
type StructureQuery struct {
	WireName    string `json:"wire_name"`
	UIDValidity uint32 `json:"uid_validity"`
	UID         uint32 `json:"uid"`
}

func (q StructureQuery) Valid() bool {
	return q.UID > 0 && q.UIDValidity > 0 && (MessageQuery{WireName: q.WireName, UIDWindow: 1}).Valid()
}

// MIMEPart describes server metadata only. Embedded messages remain opaque leaves.
type MIMEPart struct {
	Section               string            `json:"section"`
	MediaType             string            `json:"media_type"`
	Parameters            map[string]string `json:"parameters"`
	ContentID             string            `json:"content_id"`
	Description           string            `json:"description"`
	Encoding              string            `json:"encoding"`
	Size                  *int64            `json:"size"`
	Lines                 *int64            `json:"lines"`
	Disposition           string            `json:"disposition"`
	DispositionParameters map[string]string `json:"disposition_parameters"`
	Filename              string            `json:"filename"`
	Embedded              bool              `json:"embedded"`
}
type MessageStructure struct {
	UID         uint32     `json:"uid"`
	UIDValidity uint32     `json:"uid_validity"`
	Parts       []MIMEPart `json:"parts"`
	Attachments []string   `json:"attachments"`
}

func EmptyStructure(q StructureQuery) MessageStructure {
	return MessageStructure{UID: q.UID, UIDValidity: q.UIDValidity, Parts: []MIMEPart{}, Attachments: []string{}}
}
func (c *Client) Structure(ctx context.Context, s Settings, password []byte, q StructureQuery) Result {
	if !q.Valid() {
		return Result{Status: "protocol_error"}
	}
	return c.run(ctx, s, password, func(p *protocol, caps map[string]bool) Result {
		structure, status := p.messageStructure(q, caps["IMAP4REV2"])
		return Result{Status: status, Structure: &structure}
	})
}
func (p *protocol) messageStructure(q StructureQuery, isUTF8 bool) (MessageStructure, string) {
	out := EmptyStructure(q)
	fail := func(status string) (MessageStructure, string) { return EmptyStructure(q), status }
	page, status := p.selectFolder(q.WireName, q.UIDValidity, isUTF8)
	if status != "ok" {
		return fail(status)
	}
	if page.Exists == 0 || q.UID >= page.UIDNext {
		return fail("message_unavailable")
	}
	if p.write(fmt.Sprintf("MF UID FETCH %d (UID BODYSTRUCTURE)", q.UID)) != nil {
		return fail("unavailable")
	}
	tokens := 0
	found := false
	for i := 0; i < 160; i++ {
		line, err := p.read()
		if err != nil {
			return fail("protocol_error")
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return fail("protocol_error")
		}
		if fields[0] == "MF" {
			if !strings.EqualFold(fields[1], "OK") {
				return fail("protocol_error")
			}
			if !found {
				return fail("message_unavailable")
			}
			encoded, err := json.Marshal(out)
			if err != nil || len(encoded) > 128<<10 {
				return fail("limit_exceeded")
			}
			return out, "ok"
		}
		if fields[0] != "*" {
			return fail("protocol_error")
		}
		if strings.EqualFold(fields[1], "OK") {
			if strings.Contains(strings.ToUpper(line), "[UIDVALIDITY ") {
				return fail("uidvalidity_changed")
			}
			continue
		}
		if len(fields) == 3 && (strings.EqualFold(fields[2], "EXISTS") || strings.EqualFold(fields[2], "RECENT")) {
			if _, err := number(fields[1], 32); err != nil {
				return fail("protocol_error")
			}
			continue
		}
		// A concurrent expunge can invalidate the observed result; retry on a fresh connection.
		if len(fields) == 3 && strings.EqualFold(fields[2], "EXPUNGE") {
			return fail("message_unavailable")
		}
		if len(fields) < 4 || !strings.EqualFold(fields[2], "FETCH") {
			return fail("protocol_error")
		}
		seq, err := number(fields[1], 32)
		if err != nil || seq == 0 {
			return fail("protocol_error")
		}
		at := strings.IndexByte(line, '(')
		if at < 0 {
			return fail("protocol_error")
		}
		parser := dataParser{p: p, line: line[at:], tokens: &tokens}
		value, err := parser.read(0)
		if err != nil || value.kind != 'l' || strings.TrimSpace(parser.line[parser.pos:]) != "" {
			return fail("protocol_error")
		}
		attrs, err := fetchAttributes(value)
		if err != nil {
			return fail("protocol_error")
		}
		uid, hasUID := attrs["UID"]
		if hasUID {
			n, err := number(uid.atom, 32)
			if err != nil || uid.kind != 'a' || n == 0 {
				return fail("protocol_error")
			}
		}
		body, full := attrs["BODYSTRUCTURE"]
		if !full {
			flags, ok := attrs["FLAGS"]
			if !ok {
				return fail("protocol_error")
			}
			if _, err := messageFlags(flags); err != nil {
				return fail("protocol_error")
			}
			for key := range attrs {
				if key != "UID" && key != "FLAGS" {
					return fail("protocol_error")
				}
			}
			continue
		}
		n, _ := number(uid.atom, 32)
		if found || !hasUID || n != uint64(q.UID) || len(attrs) != 2 {
			return fail("protocol_error")
		}
		if err := appendMIME(&out, body, "", 0); err != nil {
			return fail("protocol_error")
		}
		found = true
	}
	return fail("protocol_error")
}
func mimeString(v dataValue, limit int) (string, error) { return plainText(v, limit) }
func mimeToken(v dataValue) (string, error) {
	s, err := mimeString(v, 127)
	if err != nil || s == "" {
		return "", ErrInvalid
	}
	for _, r := range s {
		if r <= 32 || r >= 127 || strings.ContainsRune("()<>@,;:\\\"/[]?=", r) {
			return "", ErrInvalid
		}
	}
	return strings.ToLower(s), nil
}
func mimeParameters(v dataValue) (map[string]string, error) {
	out := map[string]string{}
	if v.kind == 'n' {
		return out, nil
	}
	if v.kind != 'l' || len(v.list) > 64 || len(v.list)%2 != 0 {
		return nil, ErrInvalid
	}
	for i := 0; i < len(v.list); i += 2 {
		key, err := mimeToken(v.list[i])
		if err != nil {
			return nil, err
		}
		value, err := mimeString(v.list[i+1], 1024)
		if err != nil || v.list[i+1].kind == 'n' {
			return nil, ErrInvalid
		}
		if _, ok := out[key]; ok {
			return nil, ErrInvalid
		}
		out[key] = value
	}
	return out, nil
}
func mimeFilename(params map[string]string, key string) (string, error) {
	// ParseMediaType handles RFC 2231 UTF-8/Latin-1 extended and continued values.
	formatted := mime.FormatMediaType("application/octet-stream", params)
	if formatted == "" {
		return "", ErrInvalid
	}
	_, decoded, err := mime.ParseMediaType(formatted)
	if err != nil {
		return "", ErrInvalid
	}
	return headerText(dataValue{kind: 's', atom: decoded[key]}, 256)
}
func mimeNumber(v dataValue) (*int64, error) {
	if v.kind != 'a' {
		return nil, ErrInvalid
	}
	n, err := number(v.atom, 53)
	if err != nil {
		return nil, err
	}
	value := int64(n)
	return &value, nil
}
func appendMIME(out *MessageStructure, v dataValue, section string, depth int) error {
	if depth > 5 || len(out.Parts) >= 64 || v.kind != 'l' || len(v.list) == 0 {
		return ErrInvalid
	}
	part := MIMEPart{Section: section, Parameters: map[string]string{}, DispositionParameters: map[string]string{}}
	multipart := v.list[0].kind == 'l'
	ext := 0
	children := 0
	var err error
	if multipart {
		for children < len(v.list) && v.list[children].kind == 'l' {
			children++
		}
		if children >= len(v.list) {
			return ErrInvalid
		}
		subtype, e := mimeToken(v.list[children])
		if e != nil {
			return e
		}
		part.MediaType = "multipart/" + subtype
		ext = children + 1
		if ext < len(v.list) {
			part.Parameters, err = mimeParameters(v.list[ext])
			if err != nil {
				return err
			}
		}
	} else {
		if len(v.list) < 7 {
			return ErrInvalid
		}
		typ, e := mimeToken(v.list[0])
		if e != nil {
			return e
		}
		subtype, e := mimeToken(v.list[1])
		if e != nil || typ == "multipart" {
			return ErrInvalid
		}
		part.MediaType = typ + "/" + subtype
		if part.Section == "" {
			part.Section = "1"
		}
		part.Parameters, err = mimeParameters(v.list[2])
		if err != nil {
			return err
		}
		part.ContentID, err = mimeString(v.list[3], 1024)
		if err != nil {
			return err
		}
		part.Description, err = headerText(v.list[4], 1024)
		if err != nil {
			return err
		}
		part.Encoding, err = mimeToken(v.list[5])
		if err != nil {
			return err
		}
		part.Size, err = mimeNumber(v.list[6])
		if err != nil {
			return err
		}
		ext = 7
		if typ == "text" {
			if len(v.list) < 8 {
				return ErrInvalid
			}
			part.Lines, err = mimeNumber(v.list[7])
			if err != nil {
				return err
			}
			ext = 8
		} else if typ == "message" && (subtype == "rfc822" || subtype == "global") {
			if len(v.list) < 10 || v.list[7].kind != 'l' || len(v.list[7].list) != 10 || v.list[8].kind != 'l' {
				return ErrInvalid
			}
			part.Lines, err = mimeNumber(v.list[9])
			if err != nil {
				return err
			}
			part.Embedded = true
			ext = 10
		}
		// Single-part extensions start with MD5; multipart extensions start with parameters.
		if ext < len(v.list) {
			if _, err = mimeString(v.list[ext], 1024); err != nil {
				return err
			}
		}
	}
	if ext+1 < len(v.list) && v.list[ext+1].kind != 'n' {
		disp := v.list[ext+1]
		if disp.kind != 'l' || len(disp.list) != 2 {
			return ErrInvalid
		}
		part.Disposition, err = mimeToken(disp.list[0])
		if err != nil {
			return err
		}
		part.DispositionParameters, err = mimeParameters(disp.list[1])
		if err != nil {
			return err
		}
	}
	part.Filename, err = mimeFilename(part.DispositionParameters, "filename")
	if err != nil {
		return err
	}
	if part.Filename == "" {
		part.Filename, err = mimeFilename(part.Parameters, "name")
		if err != nil {
			return err
		}
	}
	out.Parts = append(out.Parts, part)
	if part.Disposition == "attachment" || part.Filename != "" {
		out.Attachments = append(out.Attachments, part.Section)
	}
	if multipart {
		for i := 0; i < children; i++ {
			childSection := strconv.Itoa(i + 1)
			if section != "" {
				childSection = section + "." + childSection
			}
			if err := appendMIME(out, v.list[i], childSection, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
