package imapclient

import (
	"bufio"
	"encoding/base64"
	"io"
	"strings"
	"testing"
)

func TestMIMEStructureMetadataAndBounds(t *testing.T) {
	parse := func(wire string) (MessageStructure, error) {
		p := &protocol{reader: bufio.NewReader(strings.NewReader(""))}
		tokens := 0
		parser := dataParser{p: p, line: wire, tokens: &tokens}
		v, err := parser.read(0)
		out := MessageStructure{}
		if err == nil {
			err = appendMIME(&out, v, "", 0)
		}
		return out, err
	}
	wire := `(("TEXT" "PLAIN" ("CHARSET" "UTF-8") NIL NIL "8BIT" 10 1)("APPLICATION" "PDF" NIL "<cid>" NIL "BASE64" 100 NIL ("INLINE" ("FILENAME*0*" "utf-8''report%20" "FILENAME*1*" "final.pdf"))) "MIXED")`
	out, err := parse(wire)
	if err != nil || len(out.Parts) != 3 || out.Parts[0].Size != nil || out.Parts[1].Section != "1" || out.Parts[2].Filename != "report final.pdf" || len(out.Attachments) != 1 || out.Attachments[0] != "2" {
		t.Fatal(out, err)
	}
	embedded := `("MESSAGE" "RFC822" NIL NIL NIL "7BIT" 123 (NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL) ("TEXT" "PLAIN" NIL NIL NIL "7BIT" 5 1) 7)`
	out, err = parse(embedded)
	if err != nil || len(out.Parts) != 1 || !out.Parts[0].Embedded || out.Parts[0].Section != "1" {
		t.Fatal(out, err)
	}
	single := `("TEXT" "HTML" NIL NIL NIL "7BIT" 12 1)`
	for _, bad := range []string{
		`("TEXT" "PLAIN" NIL NIL NIL "7BIT" 12)`,
		`("APPLICATION" "PDF" ("NAME" "a" "name" "b") NIL NIL "BASE64" 12)`,
		`("APPLICATION" "PDF" NIL NIL NIL "BASE64" 9007199254740992)`,
		`("APPLICATION" "PDF" NIL NIL NIL "BASE64" 12 NIL ("ATTACHMENT" ("FILENAME" "bad` + "\x00" + `name")))`,
		`(` + strings.Repeat(single, 64) + ` "MIXED")`,
		strings.Repeat("(", 10) + single + strings.Repeat(` "MIXED")`, 10),
	} {
		if _, err := parse(bad); err == nil {
			t.Fatal("unbounded or malformed structure accepted", bad)
		}
	}
}
func TestStructureFetchFailsWithoutPartialMetadata(t *testing.T) {
	q := StructureQuery{WireName: base64.RawURLEncoding.EncodeToString([]byte("INBOX")), UIDValidity: 77, UID: 102}
	selected := "* 2 EXISTS\r\n* OK [UIDVALIDITY 77] valid\r\n* OK [UIDNEXT 103] next\r\nM4 OK selected\r\n"
	body := `* 2 FETCH (UID 102 BODYSTRUCTURE ("TEXT" "PLAIN" NIL NIL NIL "7BIT" 12 1))` + "\r\n"
	for _, tc := range []struct{ wire, status string }{
		{selected + body + "MF OK done\r\n", "ok"},
		{selected + "MF OK done\r\n", "message_unavailable"},
		{selected + strings.Replace(body, "UID 102", "UID 101", 1) + "MF OK done\r\n", "protocol_error"},
		{selected + body + body + "MF OK done\r\n", "protocol_error"},
		{selected + body + "* 2 EXPUNGE\r\nMF OK done\r\n", "message_unavailable"},
		{selected + body + "* OK [UIDVALIDITY 78] reset\r\nMF OK done\r\n", "uidvalidity_changed"},
		{strings.Replace(selected, "UIDVALIDITY 77", "UIDVALIDITY 78", 1) + body + "MF OK done\r\n", "uidvalidity_changed"},
	} {
		p := &protocol{reader: bufio.NewReader(strings.NewReader(tc.wire)), writer: io.Discard}
		result, status := p.messageStructure(q, false)
		if status != tc.status || status != "ok" && (len(result.Parts) != 0 || len(result.Attachments) != 0) {
			t.Fatal(status, result, tc.status)
		}
	}
}
