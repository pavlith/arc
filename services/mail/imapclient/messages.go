package imapclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/encoding/htmlindex"
)

type MessageQuery struct {
	WireName    string `json:"wire_name"`
	UIDWindow   uint32 `json:"uid_window"`
	UIDValidity uint32 `json:"uid_validity,omitempty"`
	BeforeUID   uint32 `json:"before_uid,omitempty"`
}
type Address struct {
	Name    string `json:"name"`
	Mailbox string `json:"mailbox"`
	Host    string `json:"host"`
}
type Message struct {
	UID          uint32    `json:"uid"`
	Flags        []string  `json:"flags"`
	InternalDate time.Time `json:"internal_date"`
	Size         int64     `json:"size"`
	Subject      string    `json:"subject"`
	HeaderDate   string    `json:"header_date"`
	From         []Address `json:"from"`
	To           []Address `json:"to"`
	MessageID    string    `json:"message_id"`
	InReplyTo    string    `json:"in_reply_to"`
}
type MessagePage struct {
	UIDValidity   uint32    `json:"uid_validity"`
	UIDNext       uint32    `json:"uid_next"`
	Exists        uint32    `json:"exists"`
	NextBeforeUID uint32    `json:"next_before_uid,omitempty"`
	Messages      []Message `json:"messages"`
}

func (q MessageQuery) Valid() bool {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(q.WireName)
	if err != nil || len(raw) == 0 || len(raw) > 1024 || !utf8.Valid(raw) || q.UIDWindow < 1 || q.UIDWindow > 20 || q.BeforeUID > 0 && q.UIDValidity == 0 {
		return false
	}
	for _, r := range string(raw) {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func (c *Client) Messages(ctx context.Context, s Settings, password []byte, q MessageQuery) Result {
	if !q.Valid() {
		return Result{Status: "protocol_error", Page: MessagePage{Messages: []Message{}}}
	}
	return c.run(ctx, s, password, func(p *protocol, caps map[string]bool) Result {
		page, status := p.messagePage(q, caps["IMAP4REV2"])
		return Result{Status: status, Page: page}
	})
}
func (p *protocol) messagePage(q MessageQuery, isUTF8 bool) (MessagePage, string) {
	page := MessagePage{Messages: []Message{}}
	fail := func(status string) (MessagePage, string) {
		page.Messages = []Message{}
		page.NextBeforeUID = 0
		return page, status
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(q.WireName)
	if err != nil || len(raw) == 0 || len(raw) > 1024 || q.UIDWindow < 1 || q.UIDWindow > 20 || q.BeforeUID > 0 && q.UIDValidity == 0 {
		return fail("protocol_error")
	}
	wire := string(raw)
	name := wire
	if !isUTF8 {
		name, err = decodeUTF7(wire)
	}
	if err != nil || !utf8.ValidString(name) {
		return fail("protocol_error")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return fail("protocol_error")
		}
	}
	quoted := `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(wire) + `"`
	p.maxLines = 256
	if p.write("M4 EXAMINE "+quoted) != nil {
		return fail("unavailable")
	}
	sawValidity, sawNext, sawExists, selected := false, false, false, false
	for i := 0; i < 64; i++ {
		line, err := p.read()
		if err != nil {
			return fail("protocol_error")
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return fail("protocol_error")
		}
		if fields[0] == "M4" {
			if strings.EqualFold(fields[1], "NO") {
				return fail("folder_unavailable")
			}
			if !strings.EqualFold(fields[1], "OK") {
				return fail("protocol_error")
			}
			selected = true
			break
		}
		if fields[0] != "*" {
			return fail("protocol_error")
		}
		if len(fields) == 3 && strings.EqualFold(fields[2], "EXISTS") {
			n, err := number(fields[1], 32)
			if err != nil || sawExists {
				return fail("protocol_error")
			}
			page.Exists = uint32(n)
			sawExists = true
			continue
		}
		if strings.EqualFold(fields[1], "OK") {
			upper := strings.ToUpper(line)
			for _, code := range []string{"UIDVALIDITY", "UIDNEXT"} {
				prefix := "* OK [" + code + " "
				if strings.HasPrefix(upper, prefix) {
					end := strings.IndexByte(line[len(prefix):], ']')
					if end < 0 {
						return fail("protocol_error")
					}
					n, err := number(line[len(prefix):len(prefix)+end], 32)
					if err != nil || n == 0 {
						return fail("protocol_error")
					}
					if code == "UIDVALIDITY" {
						if sawValidity {
							return fail("protocol_error")
						}
						page.UIDValidity = uint32(n)
						sawValidity = true
					} else {
						if sawNext {
							return fail("protocol_error")
						}
						page.UIDNext = uint32(n)
						sawNext = true
					}
				}
			}
			continue
		}
		if len(fields) == 3 && strings.EqualFold(fields[2], "RECENT") {
			if _, err := number(fields[1], 32); err != nil {
				return fail("protocol_error")
			}
			continue
		}

		if strings.EqualFold(fields[1], "FLAGS") {
			continue
		}
		return fail("protocol_error")
	}
	if !selected || !sawValidity || !sawNext || !sawExists {
		return fail("protocol_error")
	}
	if q.UIDValidity != 0 && q.UIDValidity != page.UIDValidity {
		return fail("uidvalidity_changed")
	}
	if page.Exists == 0 {
		return page, "ok"
	}
	before := q.BeforeUID
	if before == 0 {
		before = page.UIDNext
	}
	if before > page.UIDNext {
		return fail("protocol_error")
	}
	if before <= 1 {
		return page, "ok"
	}
	high := before - 1
	low := uint32(1)
	if high >= q.UIDWindow {
		low = high - q.UIDWindow + 1
	}
	if p.write(fmt.Sprintf("MF UID FETCH %d:%d (UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE)", low, high)) != nil {
		return fail("unavailable")
	}
	found := map[uint32]Message{}
	sequence := map[uint32]uint32{}
	tokens := 0
	complete := false
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
			complete = true
			break
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
		if len(fields) >= 3 && strings.EqualFold(fields[2], "EXISTS") {
			if _, err := number(fields[1], 32); err != nil {
				return fail("protocol_error")
			}
			continue
		}
		if len(fields) == 3 && strings.EqualFold(fields[2], "RECENT") {
			if _, err := number(fields[1], 32); err != nil {
				return fail("protocol_error")
			}
			continue
		}

		if len(fields) == 3 && strings.EqualFold(fields[2], "EXPUNGE") {
			n, err := number(fields[1], 32)
			if err != nil || n == 0 {
				return fail("protocol_error")
			}
			for uid, seq := range sequence {
				if seq == uint32(n) {
					delete(found, uid)
					delete(sequence, uid)
				} else if seq > uint32(n) {
					sequence[uid] = seq - 1
				}
			}
			continue
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
		if err != nil || strings.TrimSpace(parser.line[parser.pos:]) != "" || value.kind != 'l' {
			return fail("protocol_error")
		}
		attrs, err := fetchAttributes(value)
		if err != nil {
			return fail("protocol_error")
		}
		uidValue, hasUID := attrs["UID"]
		uid := uint64(0)
		if hasUID {
			uid, err = number(uidValue.atom, 32)
			if err != nil || uid == 0 || uidValue.kind != 'a' {
				return fail("protocol_error")
			}
		}
		_, full := attrs["ENVELOPE"]
		if !full {
			if _, hasFlags := attrs["FLAGS"]; !hasFlags {
				return fail("protocol_error")
			}
			for key := range attrs {
				if key != "UID" && key != "FLAGS" {
					return fail("protocol_error")
				}
			}
			if flags, ok := attrs["FLAGS"]; ok {
				parsed, err := messageFlags(flags)
				if err != nil {
					return fail("protocol_error")
				}
				if old, ok := found[uint32(uid)]; ok && hasUID {
					old.Flags = parsed
					found[uint32(uid)] = old
				}
			}
			continue
		}
		if !hasUID || uid < uint64(low) || uid > uint64(high) {
			return fail("protocol_error")
		}
		if _, ok := found[uint32(uid)]; ok {
			return fail("protocol_error")
		}
		message, err := messageSummary(attrs)
		if err != nil {
			return fail("protocol_error")
		}
		found[message.UID] = message
		sequence[message.UID] = uint32(seq)
	}
	if !complete {
		return fail("protocol_error")
	}
	for _, message := range found {
		page.Messages = append(page.Messages, message)
	}
	sort.Slice(page.Messages, func(i, j int) bool { return page.Messages[i].UID > page.Messages[j].UID })
	if low > 1 {
		page.NextBeforeUID = low
	}
	encoded, err := json.Marshal(page)
	if err != nil || len(encoded) > 128<<10 {
		return fail("limit_exceeded")
	}
	return page, "ok"
}
func number(s string, bits int) (uint64, error) {
	if s == "" {
		return 0, ErrInvalid
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, ErrInvalid
		}
	}
	v, err := strconv.ParseUint(s, 10, bits)
	if err != nil {
		return 0, ErrInvalid
	}
	return v, nil
}

type dataValue struct {
	kind byte
	atom string
	list []dataValue
}
type dataParser struct {
	p      *protocol
	line   string
	pos    int
	tokens *int
}

func (d *dataParser) read(depth int) (dataValue, error) {
	fail := func() (dataValue, error) { return dataValue{}, ErrInvalid }
	*d.tokens = *d.tokens + 1
	if *d.tokens > 8192 || depth > 8 {
		return fail()
	}
	for d.pos < len(d.line) && d.line[d.pos] == ' ' {
		d.pos++
	}
	if d.pos == len(d.line) {
		return fail()
	}
	switch d.line[d.pos] {
	case '(':
		d.pos++
		out := dataValue{kind: 'l', list: []dataValue{}}
		for {
			for d.pos < len(d.line) && d.line[d.pos] == ' ' {
				d.pos++
			}
			if d.pos == len(d.line) {
				return fail()
			}
			if d.line[d.pos] == ')' {
				d.pos++
				return out, nil
			}
			if len(out.list) >= 512 {
				return fail()
			}
			value, err := d.read(depth + 1)
			if err != nil {
				return fail()
			}
			out.list = append(out.list, value)
			if d.pos < len(d.line) && d.line[d.pos] != ' ' && d.line[d.pos] != ')' {
				return fail()
			}
		}
	case '"':
		d.pos++
		var value strings.Builder
		for d.pos < len(d.line) {
			b := d.line[d.pos]
			d.pos++
			if b == '"' {
				return dataValue{kind: 's', atom: value.String()}, nil
			}
			if b == '\\' {
				if d.pos == len(d.line) || d.line[d.pos] != '\\' && d.line[d.pos] != '"' {
					return fail()
				}
				b = d.line[d.pos]
				d.pos++
			}
			value.WriteByte(b)
		}
		return fail()
	case '{':
		tail := d.line[d.pos:]
		if !strings.HasSuffix(tail, "}") {
			return fail()
		}
		n, err := number(tail[1:len(tail)-1], 32)
		if err != nil || n > 8192 {
			return fail()
		}
		literal := make([]byte, int(n))
		if _, err := io.ReadFull(d.p.reader, literal); err != nil {
			return fail()
		}
		next, err := d.p.read()
		if err != nil {
			return fail()
		}
		d.line = next
		d.pos = 0
		return dataValue{kind: 's', atom: string(literal)}, nil
	default:
		start := d.pos
		for d.pos < len(d.line) && d.line[d.pos] != ' ' && d.line[d.pos] != ')' {
			b := d.line[d.pos]
			if b < 33 || b > 126 || b == '(' || b == '{' || b == '"' {
				return fail()
			}
			d.pos++
		}
		atom := d.line[start:d.pos]
		if atom == "" {
			return fail()
		}
		if strings.EqualFold(atom, "NIL") {
			return dataValue{kind: 'n'}, nil
		}
		return dataValue{kind: 'a', atom: atom}, nil
	}
}
func fetchAttributes(v dataValue) (map[string]dataValue, error) {
	if len(v.list)%2 != 0 {
		return nil, ErrInvalid
	}
	out := map[string]dataValue{}
	for i := 0; i < len(v.list); i += 2 {
		if v.list[i].kind != 'a' {
			return nil, ErrInvalid
		}
		key := strings.ToUpper(v.list[i].atom)
		switch key {
		case "UID", "FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE":
		default:
			return nil, ErrInvalid
		}
		if _, ok := out[key]; ok {
			return nil, ErrInvalid
		}
		out[key] = v.list[i+1]
	}
	return out, nil
}
func messageFlags(v dataValue) ([]string, error) {
	if v.kind != 'l' || len(v.list) > 64 {
		return nil, ErrInvalid
	}
	out := []string{}
	for _, flag := range v.list {
		if flag.kind != 'a' || len(flag.atom) > 64 {
			return nil, ErrInvalid
		}
		out = append(out, flag.atom)
	}
	return out, nil
}
func plainText(v dataValue, max int) (string, error) {
	if v.kind == 'n' {
		return "", nil
	}
	if v.kind != 's' || len(v.atom) > 8192 || !utf8.ValidString(v.atom) {
		return "", ErrInvalid
	}
	text := strings.NewReplacer("\r\n ", " ", "\r\n\t", " ").Replace(v.atom)
	if utf8.RuneCountInString(text) > max {
		return "", ErrInvalid
	}
	for _, r := range text {
		if unicode.IsControl(r) && r != '\t' {
			return "", ErrInvalid
		}
	}
	return text, nil
}
func headerText(v dataValue, max int) (string, error) {
	text, err := plainText(v, 8192)
	if err != nil {
		return "", err
	}
	decoder := mime.WordDecoder{CharsetReader: func(charset string, r io.Reader) (io.Reader, error) {
		enc, err := htmlindex.Get(charset)
		if err != nil {
			return nil, ErrInvalid
		}
		return enc.NewDecoder().Reader(io.LimitReader(r, 8193)), nil
	}}
	decoded, err := decoder.DecodeHeader(text)
	if err != nil || len(decoded) > 8192 {
		return "", ErrInvalid
	}
	return plainText(dataValue{kind: 's', atom: decoded}, max)
}
func addresses(v dataValue) ([]Address, error) {
	out := []Address{}
	if v.kind == 'n' {
		return out, nil
	}
	if v.kind != 'l' || len(v.list) > 32 {
		return nil, ErrInvalid
	}
	for _, item := range v.list {
		if item.kind != 'l' || len(item.list) != 4 {
			return nil, ErrInvalid
		}
		name, err := headerText(item.list[0], 256)
		if err != nil {
			return nil, err
		}
		if item.list[1].kind != 'n' {
			if _, err := plainText(item.list[1], 320); err != nil {
				return nil, err
			}
		}
		mailbox, err := plainText(item.list[2], 320)
		if err != nil {
			return nil, err
		}
		host, err := plainText(item.list[3], 320)
		if err != nil {
			return nil, err
		}
		// Group boundary entries are not individual addresses in this summary view.
		if item.list[3].kind == 'n' {
			continue
		}
		if mailbox == "" || host == "" {
			return nil, ErrInvalid
		}
		out = append(out, Address{Name: name, Mailbox: mailbox, Host: host})
	}
	return out, nil
}
func messageSummary(attrs map[string]dataValue) (Message, error) {
	out := Message{}
	if len(attrs) != 5 {
		return out, ErrInvalid
	}
	if attrs["UID"].kind != 'a' || attrs["RFC822.SIZE"].kind != 'a' {
		return out, ErrInvalid
	}
	uid, err := number(attrs["UID"].atom, 32)
	if err != nil || uid == 0 {
		return out, ErrInvalid
	}
	out.UID = uint32(uid)
	size, err := number(attrs["RFC822.SIZE"].atom, 53)
	if err != nil {
		return out, ErrInvalid
	}
	out.Size = int64(size)
	out.Flags, err = messageFlags(attrs["FLAGS"])
	if err != nil {
		return out, err
	}
	date, err := plainText(attrs["INTERNALDATE"], 64)
	if err != nil {
		return out, err
	}
	out.InternalDate, err = time.Parse("_2-Jan-2006 15:04:05 -0700", date)
	if err != nil || out.InternalDate.Year() < 1 {
		return out, ErrInvalid
	}
	envelope := attrs["ENVELOPE"]
	if envelope.kind != 'l' || len(envelope.list) != 10 {
		return out, ErrInvalid
	}
	e := envelope.list
	out.Subject, err = headerText(e[1], 2048)
	if err != nil {
		return out, err
	}
	out.HeaderDate, err = plainText(e[0], 256)
	if err != nil {
		return out, err
	}
	out.From, err = addresses(e[2])
	if err != nil {
		return out, err
	}
	out.To, err = addresses(e[5])
	if err != nil {
		return out, err
	}
	for _, i := range []int{3, 4, 6, 7} {
		if _, err = addresses(e[i]); err != nil {
			return out, err
		}
	}
	out.InReplyTo, err = plainText(e[8], 1024)
	if err != nil {
		return out, err
	}
	out.MessageID, err = plainText(e[9], 1024)
	return out, err
}
