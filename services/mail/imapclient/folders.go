package imapclient

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

type Folder struct {
	Name       string   `json:"name"`
	WireName   string   `json:"wire_name"`
	Delimiter  *string  `json:"delimiter"`
	Attributes []string `json:"attributes"`
	Selectable bool     `json:"selectable"`
}

func (c *Client) Folders(ctx context.Context, s Settings, password []byte) Result {
	return c.run(ctx, s, password, func(p *protocol, caps map[string]bool) Result {
		folders, status := p.listFolders(caps["IMAP4REV2"])
		return Result{Status: status, Folders: folders}
	})
}
func (p *protocol) listFolders(isUTF8 bool) ([]Folder, string) {
	empty := []Folder{}
	p.maxLines = 256
	if p.write(`M4 LIST "" "*"`) != nil {
		return empty, "unavailable"
	}
	out := []Folder{}
	seen := map[string]bool{}
	for i := 0; i < 96; i++ {
		line, err := p.read()
		if err != nil {
			return empty, "protocol_error"
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return empty, "protocol_error"
		}
		if fields[0] == "M4" {
			if !strings.EqualFold(fields[1], "OK") {
				return empty, "protocol_error"
			}
			raw, err := json.Marshal(out)
			if err != nil || len(raw) > 128<<10 {
				return empty, "limit_exceeded"
			}
			return out, "ok"
		}
		if fields[0] != "*" {
			return empty, "protocol_error"
		}
		if !strings.EqualFold(fields[1], "LIST") {
			if strings.EqualFold(fields[1], "OK") {
				continue
			}
			return empty, "protocol_error"
		}
		if len(out) == 64 {
			return empty, "limit_exceeded"
		}
		folder, err := p.parseList(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line[1:]), fields[1])), isUTF8)
		identity := "wire:" + folder.WireName
		if strings.EqualFold(folder.Name, "INBOX") {
			identity = "inbox"
		}
		if err != nil || seen[identity] {
			return empty, "protocol_error"
		}
		seen[identity] = true
		out = append(out, folder)
	}
	return empty, "limit_exceeded"
}
func (p *protocol) parseList(s string, isUTF8 bool) (Folder, error) {
	out := Folder{Attributes: []string{}, Selectable: true}
	if len(s) == 0 || s[0] != '(' {
		return out, ErrInvalid
	}
	end := strings.IndexByte(s, ')')
	if end < 0 {
		return out, ErrInvalid
	}
	attributes := strings.Fields(s[1:end])
	if len(attributes) > 32 {
		return out, ErrInvalid
	}
	for _, flag := range attributes {
		if len(flag) > 64 || flag == "" {
			return out, ErrInvalid
		}
		for i, r := range flag {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == '\\' && i == 0) {
				return out, ErrInvalid
			}
		}
		out.Attributes = append(out.Attributes, flag)
		if strings.EqualFold(flag, `\Noselect`) {
			out.Selectable = false
		}
	}
	if len(s) <= end+1 || s[end+1] != ' ' {
		return out, ErrInvalid
	}
	s = strings.TrimLeft(s[end+1:], " ")
	if len(s) >= 4 && strings.EqualFold(s[:3], "NIL") && s[3] == ' ' {
		s = s[4:]
	} else {
		delimiter, rest, err := p.listString(s, true)
		if err != nil || !utf8.ValidString(delimiter) || utf8.RuneCountInString(delimiter) != 1 {
			return out, ErrInvalid
		}
		for _, r := range delimiter {
			if unicode.IsControl(r) {
				return out, ErrInvalid
			}
		}
		out.Delimiter = &delimiter
		s = rest
	}
	name, rest, err := p.listString(strings.TrimLeft(s, " "), false)
	if err != nil || rest != "" || len(name) == 0 || len(name) > 1024 {
		return out, ErrInvalid
	}
	decoded := name
	if !isUTF8 {
		decoded, err = decodeUTF7(name)
	}
	if err != nil || !utf8.ValidString(decoded) || utf8.RuneCountInString(decoded) > 1024 {
		return out, ErrInvalid
	}
	for _, r := range decoded {
		if unicode.IsControl(r) {
			return out, ErrInvalid
		}
	}
	out.Name = decoded
	out.WireName = base64.RawURLEncoding.EncodeToString([]byte(name))
	return out, nil
}

// LIST literals are bounded before allocation and read from the same aggregate
// limited reader. No general unbounded IMAP literal decoder is exposed.
func (p *protocol) listString(s string, quotedOnly bool) (string, string, error) {
	if len(s) == 0 {
		return "", "", ErrInvalid
	}
	if s[0] == '"' {
		var out strings.Builder
		for i := 1; i < len(s); i++ {
			if s[i] == '"' {
				if len(s) > i+1 && s[i+1] != ' ' {
					return "", "", ErrInvalid
				}
				return out.String(), strings.TrimLeft(s[i+1:], " "), nil
			}
			if s[i] == '\\' {
				i++
				if i == len(s) || s[i] != '\\' && s[i] != '"' {
					return "", "", ErrInvalid
				}
			}
			out.WriteByte(s[i])
		}
		return "", "", ErrInvalid
	}
	if quotedOnly {
		return "", "", ErrInvalid
	}
	if s[0] == '{' {
		if !strings.HasSuffix(s, "}") {
			return "", "", ErrInvalid
		}
		n, err := strconv.Atoi(s[1 : len(s)-1])
		if err != nil || n < 1 || n > 1024 {
			return "", "", ErrInvalid
		}
		raw := make([]byte, n)
		if _, err := io.ReadFull(p.reader, raw); err != nil {
			return "", "", ErrInvalid
		}
		rest, err := p.read()
		if err != nil {
			return "", "", err
		}
		return string(raw), rest, nil
	}
	end := strings.IndexByte(s, ' ')
	if end < 0 {
		end = len(s)
	}
	atom := s[:end]
	for _, r := range atom {
		if r <= 32 || r >= 127 || strings.ContainsRune(`(){%*"\`, r) {
			return "", "", ErrInvalid
		}
	}
	return atom, strings.TrimLeft(s[end:], " "), nil
}
func decodeUTF7(s string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(s); {
		b := s[i]
		if b < 32 || b > 126 {
			return "", ErrInvalid
		}
		if b != '&' {
			out.WriteByte(b)
			i++
			continue
		}
		end := strings.IndexByte(s[i+1:], '-')
		if end < 0 {
			return "", ErrInvalid
		}
		end += i + 1
		encoded := s[i+1 : end]
		if encoded == "" {
			out.WriteByte('&')
			i = end + 1
			continue
		}
		for _, r := range encoded {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '+' || r == ',') {
				return "", ErrInvalid
			}
		}
		raw, err := base64.RawStdEncoding.Strict().DecodeString(strings.ReplaceAll(encoded, ",", "/"))
		if err != nil || len(raw)%2 != 0 {
			return "", ErrInvalid
		}
		for j := 0; j < len(raw); j += 2 {
			unit := binary.BigEndian.Uint16(raw[j : j+2])
			r := rune(unit)
			if unit >= 0xd800 && unit <= 0xdbff {
				if j+4 > len(raw) {
					return "", ErrInvalid
				}
				low := binary.BigEndian.Uint16(raw[j+2 : j+4])
				if low < 0xdc00 || low > 0xdfff {
					return "", ErrInvalid
				}
				r = utf16.DecodeRune(rune(unit), rune(low))
				j += 2
			} else if unit >= 0xdc00 && unit <= 0xdfff {
				return "", ErrInvalid
			}
			if r >= 32 && r <= 126 || unicode.IsControl(r) {
				return "", ErrInvalid
			}
			out.WriteRune(r)
		}
		i = end + 1
	}
	return out.String(), nil
}
