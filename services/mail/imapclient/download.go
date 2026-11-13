package imapclient

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"mime/quotedprintable"
	"regexp"
	"strings"
	"time"
)

const MaxDownloadSize int64 = 32 << 20
const DownloadBlockSize = 256 << 10

var sectionPattern = regexp.MustCompile(`^[1-9][0-9]*(\.[1-9][0-9]*){0,5}$`)

type DownloadQuery struct {
	StructureQuery
	// Empty means the raw RFC 5322 message; numeric sections select MIME leaves.
	Section string `json:"section"`
}

func (q DownloadQuery) Valid() bool {
	return q.StructureQuery.Valid() && (q.Section == "" || len(q.Section) <= 32 && sectionPattern.MatchString(q.Section))
}

// Download delivers bounded verified blocks through a reader; byte content never
// enters an RPC Result. Each partial FETCH is completed and UID-checked first.
func (c *Client) Download(ctx context.Context, s Settings, password []byte, q DownloadQuery, check func() error, consume func(io.Reader) error) string {
	if !q.Valid() || check == nil || consume == nil {
		return "protocol_error"
	}
	result := c.runWithin(ctx, s, password, 45*time.Second, func(p *protocol, caps map[string]bool) Result {
		size := int64(0)
		encoding := "binary"
		if q.Section == "" {
			page, status := p.selectFolder(q.WireName, q.UIDValidity, caps["IMAP4REV2"])
			if status != "ok" {
				return Result{Status: status}
			}
			if page.Exists == 0 || q.UID >= page.UIDNext {
				return Result{Status: "message_unavailable"}
			}
			if p.write(fmt.Sprintf("MS UID FETCH %d (UID RFC822.SIZE)", q.UID)) != nil {
				return Result{Status: "unavailable"}
			}
			attrs, status := p.downloadFetch("MS", q.UID, "", 0)
			if status != "ok" {
				return Result{Status: status}
			}
			value, err := mimeNumber(attrs["RFC822.SIZE"])
			if err != nil {
				return Result{Status: "protocol_error"}
			}
			size = *value
		} else {
			structure, status := p.messageStructure(q.StructureQuery, caps["IMAP4REV2"])
			if status != "ok" {
				return Result{Status: status}
			}
			found := false
			for _, part := range structure.Parts {
				if part.Section == q.Section && part.Size != nil {
					size = *part.Size
					encoding = part.Encoding
					found = true
					break
				}
			}
			if !found {
				return Result{Status: "message_unavailable"}
			}
		}
		if size > MaxDownloadSize {
			return Result{Status: "limit_exceeded"}
		}
		p.maxLines = 1024
		source := &partialReader{p: p, q: q, size: size, check: check}
		var reader io.Reader = source
		switch encoding {
		case "base64":
			reader = base64.NewDecoder(base64.StdEncoding, reader)
		case "quoted-printable":
			reader = quotedprintable.NewReader(reader)
		case "7bit", "8bit", "binary":
		default:
			return Result{Status: "unsupported_encoding"}
		}
		if err := consume(reader); err != nil {
			return Result{Status: "unavailable"}
		}
		// Require EOF from the decoding reader as well as the encoded source.
		var extra [1]byte
		if n, err := reader.Read(extra[:]); n != 0 || err != io.EOF {
			return Result{Status: "protocol_error"}
		}
		// Consumers cannot accept only a prefix and turn it into a successful download.
		if source.offset != size || len(source.pending) != 0 {
			return Result{Status: "protocol_error"}
		}
		return Result{Status: "ok"}
	})
	return result.Status
}

type partialReader struct {
	p            *protocol
	q            DownloadQuery
	size, offset int64
	pending      []byte
	check        func() error
}

func (r *partialReader) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	if len(r.pending) == 0 {
		if r.offset == r.size {
			return 0, io.EOF
		}
		if err := r.check(); err != nil {
			return 0, err
		}
		count := int64(DownloadBlockSize)
		if left := r.size - r.offset; left < count {
			count = left
		}
		if r.p.write(fmt.Sprintf("MB UID FETCH %d (UID BODY.PEEK[%s]<%d.%d>)", r.q.UID, r.q.Section, r.offset, count)) != nil {
			return 0, ErrInvalid
		}
		key := fmt.Sprintf("BODY[%s]<%d>", r.q.Section, r.offset)
		attrs, status := r.p.downloadFetch("MB", r.q.UID, key, count)
		if status != "ok" {
			return 0, ErrInvalid
		}
		if err := r.check(); err != nil {
			return 0, err
		}
		r.pending = []byte(attrs[key].atom)
		r.offset += int64(len(r.pending))
	}
	n := copy(dst, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

// downloadFetch permits exactly the requested attributes. Literal bytes are held
// in one bounded block until the UID and tagged completion have been verified,
// including servers that put UID after the literal rather than before it.
func (p *protocol) downloadFetch(tag string, uid uint32, bodyKey string, count int64) (map[string]dataValue, string) {
	var found map[string]dataValue
	tokens := 0
	for i := 0; i < 64; i++ {
		line, err := p.read()
		if err != nil {
			return nil, "protocol_error"
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, "protocol_error"
		}
		if fields[0] == tag {
			if !strings.EqualFold(fields[1], "OK") {
				return nil, "protocol_error"
			}
			if found == nil {
				return nil, "message_unavailable"
			}
			return found, "ok"
		}
		if fields[0] != "*" {
			return nil, "protocol_error"
		}
		if strings.EqualFold(fields[1], "OK") {
			if strings.Contains(strings.ToUpper(line), "[UIDVALIDITY ") {
				return nil, "uidvalidity_changed"
			}
			continue
		}
		if len(fields) == 3 && (strings.EqualFold(fields[2], "EXISTS") || strings.EqualFold(fields[2], "RECENT")) {
			if _, err := number(fields[1], 32); err != nil {
				return nil, "protocol_error"
			}
			continue
		}
		if len(fields) == 3 && strings.EqualFold(fields[2], "EXPUNGE") {
			return nil, "message_unavailable"
		}
		if len(fields) < 4 || !strings.EqualFold(fields[2], "FETCH") {
			return nil, "protocol_error"
		}
		seq, err := number(fields[1], 32)
		if err != nil || seq == 0 {
			return nil, "protocol_error"
		}
		at := strings.IndexByte(line, '(')
		if at < 0 {
			return nil, "protocol_error"
		}
		var literal []byte
		if strings.HasSuffix(line, "}") {
			start := strings.LastIndexByte(line, '{')
			if bodyKey == "" || start < at {
				return nil, "protocol_error"
			}
			n, err := number(line[start+1:len(line)-1], 32)
			if err != nil || int64(n) != count || n > DownloadBlockSize || p.budget == nil {
				return nil, "protocol_error"
			}
			p.budget.N += int64(n)
			literal = make([]byte, int(n))
			if _, err := io.ReadFull(p.reader, literal); err != nil {
				return nil, "protocol_error"
			}
			tail, err := p.read()
			if err != nil {
				return nil, "protocol_error"
			}
			line = line[:start] + `"block"` + tail
		}
		parser := dataParser{p: p, line: line[at:], tokens: &tokens}
		value, err := parser.read(0)
		if err != nil || value.kind != 'l' || len(value.list)%2 != 0 || strings.TrimSpace(parser.line[parser.pos:]) != "" {
			return nil, "protocol_error"
		}
		attrs := map[string]dataValue{}
		for j := 0; j < len(value.list); j += 2 {
			key := strings.ToUpper(value.list[j].atom)
			if value.list[j].kind != 'a' {
				return nil, "protocol_error"
			}
			if _, ok := attrs[key]; ok {
				return nil, "protocol_error"
			}
			attrs[key] = value.list[j+1]
		}
		if flags, ok := attrs["FLAGS"]; ok && len(attrs) <= 2 {
			if _, err := messageFlags(flags); err != nil {
				return nil, "protocol_error"
			}
			for key := range attrs {
				if key != "FLAGS" && key != "UID" {
					return nil, "protocol_error"
				}
			}
			continue
		}
		n, err := number(attrs["UID"].atom, 32)
		if err != nil || attrs["UID"].kind != 'a' || n != uint64(uid) || len(attrs) != 2 || found != nil {
			return nil, "protocol_error"
		}
		if bodyKey != "" {
			body, ok := attrs[bodyKey]
			if !ok || body.kind != 's' || body.atom != "block" || literal == nil {
				return nil, "protocol_error"
			}
			attrs[bodyKey] = dataValue{kind: 's', atom: string(literal)}
		} else if _, ok := attrs["RFC822.SIZE"]; !ok {
			return nil, "protocol_error"
		}
		found = attrs
	}
	return nil, "protocol_error"
}
