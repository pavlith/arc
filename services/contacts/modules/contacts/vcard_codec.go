package contacts

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	v1 "github.com/pavlith/arc/services/contacts/api/v1"
)

const maxVCardBytes = 96 << 10

// Keep raw headers and values: unknown properties, groups, parameter quoting and
// unprojected structured components must survive native edits without decoding.
type cardLine struct {
	name, head, value string
	params            map[string][]string
}
type cardDocument struct {
	version string
	lines   []cardLine
}

func token(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
func quotedSplit(s string, sep byte) ([]string, error) {
	parts := []string{}
	start := 0
	quote := false
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			quote = !quote
		}
		if s[i] == sep && !quote {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	if quote {
		return nil, invalid()
	}
	return append(parts, s[start:]), nil
}
func parseCardLine(line string) (cardLine, error) {
	p := cardLine{}
	quote := false
	colon := -1
	for i := 0; i < len(line); i++ {
		if line[i] == '"' {
			quote = !quote
		}
		if line[i] == ':' && !quote {
			colon = i
			break
		}
	}
	if colon < 1 || colon > 4096 {
		return p, invalid()
	}
	p.head, p.value = line[:colon], line[colon+1:]
	fields, err := quotedSplit(p.head, ';')
	if err != nil || len(fields) > 33 {
		return p, invalid()
	}
	names := strings.Split(fields[0], ".")
	if len(names) > 2 {
		return p, invalid()
	}
	for _, s := range names {
		if !token(s) {
			return p, invalid()
		}
	}
	p.name = strings.ToUpper(names[len(names)-1])
	p.params = map[string][]string{}
	for _, field := range fields[1:] {
		pair := strings.SplitN(field, "=", 2)
		if len(pair) != 2 || !token(pair[0]) || pair[1] == "" {
			return p, invalid()
		}
		values, err := quotedSplit(pair[1], ',')
		if err != nil || len(values) > 32 {
			return p, invalid()
		}
		key := strings.ToUpper(pair[0])
		for _, v := range values {
			if strings.HasPrefix(v, `"`) {
				if len(v) < 2 || !strings.HasSuffix(v, `"`) {
					return p, invalid()
				}
				v = v[1 : len(v)-1]
			}
			if strings.ContainsRune(v, '"') {
				return p, invalid()
			}
			p.params[key] = append(p.params[key], v)
		}
	}
	return p, nil
}
func decodeCard(data string) (cardDocument, error) {
	doc := cardDocument{}
	if len(data) == 0 || len(data) > maxVCardBytes || !utf8.ValidString(data) {
		return doc, invalid()
	}
	data = strings.ReplaceAll(data, "\r\n", "\n")
	for _, r := range data {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return doc, invalid()
		}
	}
	physical := strings.Split(strings.TrimSuffix(data, "\n"), "\n")
	if len(physical) > 2048 {
		return doc, invalid()
	}
	lines := []string{}
	for _, line := range physical {
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if len(lines) == 0 {
				return doc, invalid()
			}
			lines[len(lines)-1] += line[1:]
		} else {
			lines = append(lines, line)
		}
		if len(lines) > 514 || len(lines[len(lines)-1]) > 64<<10 {
			return doc, invalid()
		}
	}
	if len(lines) < 5 || !strings.EqualFold(lines[0], "BEGIN:VCARD") || !strings.EqualFold(lines[len(lines)-1], "END:VCARD") {
		return doc, invalid()
	}
	for i, line := range lines[1 : len(lines)-1] {
		p, err := parseCardLine(line)
		if err != nil || p.name == "BEGIN" || p.name == "END" {
			return doc, invalid()
		}
		if p.name == "VERSION" {
			if i != 0 || !strings.EqualFold(p.head, "VERSION") || p.value != "3.0" && p.value != "4.0" {
				return doc, invalid()
			}
			doc.version = p.value
		}
		doc.lines = append(doc.lines, p)
	}
	if doc.version == "" {
		return doc, invalid()
	}
	return doc, nil
}
func encodeCard(doc cardDocument) (string, error) {
	var out strings.Builder
	write := func(line string) {
		first := true
		for len(line) > 0 {
			width := 75
			if !first {
				width = 74
				out.WriteByte(' ')
			}
			cut := len(line)
			if cut > width {
				cut = width
				for !utf8.RuneStart(line[cut]) {
					cut--
				}
			}
			out.WriteString(line[:cut])
			out.WriteString("\r\n")
			line = line[cut:]
			first = false
		}
	}
	write("BEGIN:VCARD")
	for _, p := range doc.lines {
		write(p.head + ":" + p.value)
	}
	write("END:VCARD")
	data := out.String()
	wire, err := json.Marshal(data)
	if err != nil || len(data) > maxVCardBytes || len(wire) > 160<<10 {
		return "", invalid()
	}
	return data, nil
}
func splitComponents(s string) []string {
	parts := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == ';' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}
func decodeText(s string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			out.WriteByte(s[i])
			continue
		}
		i++
		if i == len(s) {
			return "", invalid()
		}
		switch s[i] {
		case '\\', ',', ';':
			out.WriteByte(s[i])
		case 'n', 'N':
			out.WriteByte('\n')
		default:
			return "", invalid()
		}
	}
	return out.String(), nil
}
func encodeText(s string) string {
	return strings.NewReplacer("\\", "\\\\", "\n", "\\n", ",", "\\,", ";", "\\;").Replace(s)
}
func singleParam(p cardLine, key string) (string, error) {
	v := p.params[key]
	if len(v) > 1 {
		return "", invalid()
	}
	if len(v) == 0 {
		return "", nil
	}
	return v[0], nil
}
func managedText(p cardLine) (string, error) { return managedTextKinds(p, "text") }
func managedTextKinds(p cardLine, kinds ...string) (string, error) {
	enc, err := singleParam(p, "ENCODING")
	if err != nil || enc != "" {
		return "", invalid()
	}
	charset, err := singleParam(p, "CHARSET")
	if err != nil || charset != "" && !strings.EqualFold(charset, "UTF-8") {
		return "", invalid()
	}
	value, err := singleParam(p, "VALUE")
	allowed := value == ""
	for _, kind := range kinds {
		allowed = allowed || strings.EqualFold(value, kind)
	}
	if err != nil || !allowed {
		return "", invalid()
	}
	return decodeText(p.value)
}
func cardLabel(p cardLine) (string, error) {
	encoded, err := singleParam(p, "X-ARC-LABEL-B64")
	if err != nil {
		return "", err
	}
	if encoded != "" {
		b, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return "", invalid()
		}
		return string(b), nil
	}
	for _, value := range p.params["TYPE"] {
		for _, part := range strings.Split(value, ",") {
			if !token(part) {
				return "", invalid()
			}
		}
	}

	return strings.Join(p.params["TYPE"], ","), nil
}
func customKey(p cardLine) (string, error) {
	encoded, err := singleParam(p, "X-ARC-KEY")
	if err != nil || encoded == "" {
		return "", invalid()
	}
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", invalid()
	}
	key, err := text(string(b), 64, false)
	if err != nil || key == "" {
		return "", invalid()
	}
	return key, nil
}
func validUID(uid string) bool {
	if uid == "" || len(uid) > 255 || !utf8.ValidString(uid) {
		return false
	}
	for _, r := range uid {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func cardProjection(doc cardDocument) (string, v1.Input, error) {
	in := v1.Input{}
	uid := ""
	counts := map[string]int{}
	for _, p := range doc.lines {
		counts[p.name]++
		switch p.name {
		case "VERSION":
		case "UID":
			if counts[p.name] > 1 || strings.ContainsAny(strings.Split(p.head, ";")[0], ".") {
				return "", in, invalid()
			}
			kind, err := singleParam(p, "VALUE")
			if err != nil {
				return "", in, err
			}
			if kind == "" {
				if doc.version == "4.0" {
					kind = "uri"
				} else {
					kind = "text"
				}
			}
			if strings.EqualFold(kind, "text") {
				uid, err = managedText(p)
			} else if strings.EqualFold(kind, "uri") {
				if len(p.params["ENCODING"]) != 0 || len(p.params["CHARSET"]) != 0 {
					return "", in, invalid()
				}
				uid = p.value
				u, e := url.Parse(uid)
				if e != nil || u.Scheme == "" {
					return "", in, invalid()
				}
			} else {
				return "", in, invalid()
			}
			if err != nil || !validUID(uid) {
				return "", in, invalid()
			}
		case "FN", "ROLE", "NOTE":
			if counts[p.name] > 1 {
				return "", in, invalid()
			}
			value, err := managedText(p)
			if err != nil {
				return "", in, err
			}
			switch p.name {
			case "FN":
				in.DisplayName = value
			case "ROLE":
				in.Role = value
			case "NOTE":
				in.Notes = value
			}
		case "N", "ORG", "ADR":
			if p.name != "ADR" && counts[p.name] > 1 {
				return "", in, invalid()
			}
			// Validate representation before interpreting the structured separators.
			if _, err := managedText(p); err != nil {
				return "", in, err
			}
			raw := splitComponents(p.value)
			values := make([]string, len(raw))
			for i, v := range raw {
				value, err := decodeText(v)
				if err != nil {
					return "", in, err
				}
				values[i] = value
			}
			switch p.name {
			case "N":
				if len(values) != 5 {
					return "", in, invalid()
				}
				in.FamilyName = values[0]
				in.GivenName = values[1]
				in.AdditionalName = values[2]
				in.Prefix = values[3]
				in.Suffix = values[4]
			case "ORG":
				in.Organization = values[0]
			case "ADR":
				if len(values) != 7 {
					return "", in, invalid()
				}
				label, err := cardLabel(p)
				if err != nil {
					return "", in, err
				}
				in.Addresses = append(in.Addresses, v1.Address{Label: label, Street: values[2], Locality: values[3], Region: values[4], PostalCode: values[5], Country: values[6]})
			}
		case "TEL", "EMAIL":
			label, err := cardLabel(p)
			if err != nil {
				return "", in, err
			}
			var value string
			kind, err := singleParam(p, "VALUE")
			if err != nil {
				return "", in, err
			}
			if p.name == "TEL" && doc.version == "4.0" && (kind == "" || strings.EqualFold(kind, "uri")) {
				if len(p.params["ENCODING"]) != 0 || len(p.params["CHARSET"]) != 0 {
					return "", in, invalid()
				}
				u, err := url.Parse(p.value)
				if err != nil || u.Scheme == "" || strings.ContainsAny(p.value, " \t") {
					return "", in, invalid()
				}
				value = p.value
			} else {
				if p.name == "TEL" && doc.version == "3.0" {
					value, err = managedTextKinds(p, "text", "phone-number")
				} else {
					value, err = managedText(p)
				}
				if err != nil {
					return "", in, err
				}
			}
			item := v1.LabelledValue{Label: label, Value: value}
			if p.name == "TEL" {
				in.Phones = append(in.Phones, item)
			} else {
				in.Emails = append(in.Emails, item)
			}
		case "X-ARC-CUSTOM":
			key, err := customKey(p)
			if err != nil {
				return "", in, err
			}
			value, err := managedText(p)
			if err != nil {
				return "", in, err
			}
			if in.CustomFields == nil {
				in.CustomFields = map[string]string{}
			}
			if _, ok := in.CustomFields[key]; ok {
				return "", in, invalid()
			}
			in.CustomFields[key] = value
		}
	}
	if counts["UID"] != 1 || counts["FN"] != 1 || doc.version == "3.0" && counts["N"] != 1 {
		return "", in, invalid()
	}
	normalized, _, err := validate(in)
	return uid, normalized, err
}
func parseVCard(data string) (string, v1.Input, string, error) {
	doc, err := decodeCard(data)
	if err != nil {
		return "", v1.Input{}, "", err
	}
	uid, in, err := cardProjection(doc)
	if err != nil {
		return "", in, "", err
	}
	normalized, err := encodeCard(doc)
	return uid, in, normalized, err
}
func line(name, value string) cardLine {
	return cardLine{name: name, head: name, value: encodeText(value), params: map[string][]string{}}
}

// setParam changes only the named, modeled parameter; every other raw parameter
// (including quoted/caret values) remains byte-for-byte intact after unfolding.
func setParam(p cardLine, key, value string) cardLine {
	fields, _ := quotedSplit(p.head, ';')
	kept := []string{fields[0]}
	for _, field := range fields[1:] {
		name := strings.SplitN(field, "=", 2)[0]
		if !strings.EqualFold(name, key) {
			kept = append(kept, field)
		}
	}
	if value != "" {
		kept = append(kept, key+"="+value)
	}
	p.head = strings.Join(kept, ";")
	return p
}
func setLabel(p cardLine, label string) cardLine {
	p = setParam(p, "TYPE", "")
	p = setParam(p, "X-ARC-LABEL-B64", "")
	if label == "" {
		return p
	}
	valid := true
	for _, part := range strings.Split(label, ",") {
		if !token(part) {
			valid = false
		}
	}
	if valid {
		return setParam(p, "TYPE", label)
	}
	return setParam(p, "X-ARC-LABEL-B64", base64.RawURLEncoding.EncodeToString([]byte(label)))
}

// renderVCard is a field-level patch over an imported template. Unchanged modeled
// fields keep their raw lines; changed components retain unmodeled neighbors.
func renderVCard(in v1.Input, uid, template string) (string, error) {
	normalized, _, err := validate(in)
	if err != nil {
		return "", err
	}
	in = normalized

	if !validUID(uid) {
		return "", invalid()
	}
	doc := cardDocument{version: "4.0", lines: []cardLine{line("VERSION", "4.0"), {name: "UID", head: "UID;VALUE=text", value: encodeText(uid)}}}
	old := v1.Input{}
	if template != "" {
		var err error
		doc, err = decodeCard(template)
		if err != nil {
			return "", err
		}
		previous, projected, err := cardProjection(doc)
		if err != nil || previous != uid {
			return "", invalid()
		}
		old = projected
	}
	result := []cardLine{}
	seen := map[string]int{}
	customSeen := map[string]bool{}
	scalar := func(name string) (string, string) {
		switch name {
		case "FN":
			return old.DisplayName, in.DisplayName
		case "ROLE":
			return old.Role, in.Role
		case "NOTE":
			return old.Notes, in.Notes
		}
		return "", ""
	}
	names := func(v v1.Input) []string {
		return []string{v.FamilyName, v.GivenName, v.AdditionalName, v.Prefix, v.Suffix}
	}
	templates := map[string][]cardLine{}
	for _, p := range doc.lines {
		templates[p.name] = append(templates[p.name], p)
	}
	values := func(name string, before, after []v1.LabelledValue) []cardLine {
		mapping := matchItems(before, after, func(a, b v1.LabelledValue) bool { return a.Value == b.Value })
		out := []cardLine{}
		for i, v := range after {
			p := line(name, v.Value)
			if name == "TEL" && doc.version == "4.0" {
				p = setParam(p, "VALUE", "text")
			}
			previous := mapping[i]
			if previous >= 0 {
				p = templates[name][previous]
				if before[previous].Value != v.Value {
					p.value = encodeText(v.Value)
					if name == "TEL" && doc.version == "4.0" {
						p = setParam(p, "VALUE", "text")
					}
				}
				if before[previous].Label != v.Label {
					p = setLabel(p, v.Label)
				}
			} else {
				p = setLabel(p, v.Label)
			}
			out = append(out, p)
		}
		return out
	}
	addressLines := func() []cardLine {
		mapping := matchItems(old.Addresses, in.Addresses, func(a, b v1.Address) bool { a.Label = ""; b.Label = ""; return a == b })
		out := []cardLine{}
		components := func(v v1.Address) []string {
			return []string{"", "", v.Street, v.Locality, v.Region, v.PostalCode, v.Country}
		}
		for i, v := range in.Addresses {
			p := cardLine{name: "ADR", head: "ADR"}
			previous := mapping[i]
			after := components(v)
			parts := make([]string, 7)
			for j, value := range after {
				parts[j] = encodeText(value)
			}
			if previous >= 0 {
				p = templates["ADR"][previous]
				parts = splitComponents(p.value)
				before := components(old.Addresses[previous])
				for j := 2; j < 7; j++ {
					if before[j] != after[j] {
						parts[j] = encodeText(after[j])
					}
				}
				if old.Addresses[previous].Label != v.Label {
					p = setLabel(p, v.Label)
				}
			} else {
				p = setLabel(p, v.Label)
			}
			p.value = strings.Join(parts, ";")
			out = append(out, p)
		}
		return out
	}

	for _, p := range doc.lines {
		idx := seen[p.name]
		seen[p.name]++
		switch p.name {
		case "FN", "ROLE", "NOTE":
			before, after := scalar(p.name)
			if before != after {
				p.value = encodeText(after)
			}
			if after == "" && before != after {
				continue
			}
		case "N", "ORG":
			before, after := names(old), names(in)
			if p.name == "ORG" {
				before = []string{old.Organization}
				after = []string{in.Organization}
			}
			values := splitComponents(p.value)
			for i := range after {
				if before[i] != after[i] {
					values[i] = encodeText(after[i])
				}
			}
			p.value = strings.Join(values, ";")
		case "TEL", "EMAIL":
			if idx == 0 {
				before, after := old.Phones, in.Phones
				if p.name == "EMAIL" {
					before, after = old.Emails, in.Emails
				}
				result = append(result, values(p.name, before, after)...)
			}
			continue
		case "ADR":
			if idx == 0 {
				result = append(result, addressLines()...)
			}
			continue

		case "X-ARC-CUSTOM":
			key, err := customKey(p)
			if err != nil {
				return "", err
			}
			value, ok := in.CustomFields[key]
			if !ok {
				continue
			}
			customSeen[key] = true
			if old.CustomFields[key] != value {
				p.value = encodeText(value)
			}
		}
		result = append(result, p)
	}
	for _, name := range []string{"FN", "ROLE", "NOTE"} {
		_, value := scalar(name)
		if seen[name] == 0 && value != "" {
			result = append(result, line(name, value))
		}
	}
	if seen["N"] == 0 {
		values := names(in)
		for i := range values {
			values[i] = encodeText(values[i])
		}
		result = append(result, cardLine{name: "N", head: "N", value: strings.Join(values, ";")})
	}
	if seen["ORG"] == 0 && in.Organization != "" {
		result = append(result, line("ORG", in.Organization))
	}
	if seen["TEL"] == 0 {
		result = append(result, values("TEL", old.Phones, in.Phones)...)
	}
	if seen["EMAIL"] == 0 {
		result = append(result, values("EMAIL", old.Emails, in.Emails)...)
	}
	if seen["ADR"] == 0 {
		result = append(result, addressLines()...)
	}

	keys := []string{}
	for key := range in.CustomFields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if customSeen[key] {
			continue
		}
		p := line("X-ARC-CUSTOM", in.CustomFields[key])
		p = setParam(p, "X-ARC-KEY", base64.RawURLEncoding.EncodeToString([]byte(key)))
		result = append(result, p)
	}
	doc.lines = result
	data, err := encodeCard(doc)
	if err != nil {
		return "", err
	}
	// Check the serialized projection too: parameter edits must not create a card
	// that disagrees with the native representation or cannot be imported again.
	checkUID, check, _, err := parseVCard(data)
	if err != nil || checkUID != uid || !reflect.DeepEqual(check, in) {
		return "", invalid()
	}
	return data, nil
}

// Match unchanged repeated items before positional edits, so removing/reordering
// an item carries the surviving item's own group and opaque parameters with it.
func matchItems[T comparable](before, after []T, same func(T, T) bool) []int {
	out := make([]int, len(after))
	used := make([]bool, len(before))
	for i, v := range after {
		out[i] = -1
		for j, old := range before {
			if !used[j] && old == v {
				out[i] = j
				used[j] = true
				break
			}
		}
	}
	for i, v := range after {
		if out[i] >= 0 {
			continue
		}
		for j, old := range before {
			if !used[j] && same(old, v) {
				out[i] = j
				used[j] = true
				break
			}
		}
	}

	for i := range after {
		if out[i] >= 0 {
			continue
		}
		if i < len(before) && !used[i] {
			out[i] = i
			used[i] = true
			continue
		}
		for j := range before {
			if !used[j] {
				out[i] = j
				used[j] = true
				break
			}
		}
	}
	return out
}
