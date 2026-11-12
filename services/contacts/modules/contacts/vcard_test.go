package contacts

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/contacts/api/v1"
)

func externalCard(version string) string {
	uid := "UID:urn:uuid:external-contact"
	if version == "3.0" {
		uid = "UID:external-contact"
	}
	return "BEGIN:VCARD\r\nVERSION:" + version + "\r\n" + uid + "\r\n" +
		"FN;LANGUAGE=ru;X-VENDOR=keep:Иван Петров\r\nN;X-ORDER=keep:Петров;Иван;;;\r\n" +
		"ORG;X-ORG=keep:Arc;Research;Team\\;One\r\nROLE:Engineer\r\n" +
		"item1.EMAIL;TYPE=work;X-META=first:ivan@example.test\r\nitem2.EMAIL;TYPE=home;X-META=second:home@example.test\r\n" +
		"item1.X-ABLabel:Vendor label\r\nADR;TYPE=work;X-GEO=keep:PO Box;Floor;Main\\; Street;Moscow;;123;RU\r\n" +
		"NOTE:Line one\\nLine two\\, with comma\r\n" +
		"X-VENDOR;X-PARAM=\"semi;colon:comma,^'quote\":opaque\\,value\r\nPHOTO;VALUE=uri:https://private.invalid/photo\r\nEND:VCARD\r\n"
}
func unfoldCard(data string) string {
	return strings.ReplaceAll(strings.ReplaceAll(data, "\r\n ", ""), "\r\n\t", "")
}
func TestVCardRoundTripAndNativePatch(t *testing.T) {
	for _, version := range []string{"3.0", "4.0"} {
		t.Run(version, func(t *testing.T) {
			raw := externalCard(version)
			uid, in, data, err := parseVCard(raw)
			if err != nil || in.GivenName != "Иван" || in.Organization != "Arc" || in.Addresses[0].Street != "Main; Street" || len(in.Emails) != 2 {
				t.Fatalf("projection: %+v %v", in, err)
			}
			same, err := renderVCard(in, uid, data)
			if err != nil || same != data {
				t.Fatal("unmodified round-trip", err)
			}
			in.DisplayName = "Иван Updated"
			in.GivenName = "Changed"
			in.Organization = "New org"
			in.Addresses[0].Street = "New street"
			// Reorder/delete repeated values without moving first-item metadata onto the survivor.
			in.Emails = []v1.LabelledValue{in.Emails[1]}
			in.Emails[0].Label = "Личный адрес"
			in.CustomFields = map[string]string{"key;comma,quote\"": "v;1,2\\3"}
			changed, err := renderVCard(in, uid, data)
			if err != nil {
				t.Fatal(err)
			}
			unfolded := unfoldCard(changed)
			for _, want := range []string{"FN;LANGUAGE=ru;X-VENDOR=keep:Иван Updated", "N;X-ORDER=keep:Петров;Changed;;;", "ORG;X-ORG=keep:New org;Research;Team\\;One", "ADR;TYPE=work;X-GEO=keep:PO Box;Floor;New street;Moscow;;123;RU", "item2.EMAIL;X-META=second;X-ARC-LABEL-B64=", "item1.X-ABLabel:Vendor label", "X-VENDOR;X-PARAM=\"semi;colon:comma,^'quote\":opaque\\,value", "PHOTO;VALUE=uri:https://private.invalid/photo"} {
				if !strings.Contains(unfolded, want) {
					t.Fatalf("lost %q in %s", want, unfolded)
				}
			}
			if strings.Contains(unfolded, "item1.EMAIL") {
				t.Fatal("removed item retained")
			}
			_, got, _, err := parseVCard(changed)
			if err != nil || got.CustomFields["key;comma,quote\""] != "v;1,2\\3" {
				t.Fatal(got, err)
			}
		})
	}
	// Native Unicode fields, long folded lines and delimiter escaping round-trip.
	in := sample()
	in.DisplayName = strings.Repeat("я", 256)
	in.Notes = strings.Repeat("Я;comma,\\\n", 100)
	in.Phones = []v1.LabelledValue{{Label: "work,voice", Value: "+7 123"}, {Label: "mobile phone", Value: "tel:+1;ext=3"}}
	data, err := renderVCard(in, "native@arc", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, physical := range strings.Split(strings.TrimSuffix(data, "\r\n"), "\r\n") {
		if len(physical) > 75 || !utf8.ValidString(physical) {
			t.Fatal("invalid folding")
		}
	}
	uid, got, _, err := parseVCard(data)
	if err != nil || uid != "native@arc" || got.DisplayName != in.DisplayName || got.Notes != strings.TrimSpace(in.Notes) || got.Phones[1].Label != "mobile phone" {
		t.Fatal("native round-trip", err)
	}
	// URI phones stay opaque until explicitly replaced through the native API.
	raw := strings.Replace(externalCard("4.0"), "END:VCARD", "TEL;X-OPAQUE=keep:tel:+123;ext=2\r\nEND:VCARD", 1)
	uid, got, data, err = parseVCard(raw)
	if err != nil {
		t.Fatal(err)
	}
	got.Phones[0].Value = "+7 123"
	data, err = renderVCard(got, uid, data)
	if err != nil || !strings.Contains(data, "TEL;X-OPAQUE=keep;VALUE=text:+7 123") {
		t.Fatal("URI phone replacement", err)
	}
}
func TestVCardValidationAndBounds(t *testing.T) {
	good := externalCard("4.0")
	cases := []string{
		good + good, strings.Replace(good, "END:VCARD", "", 1), strings.Replace(good, "VERSION:4.0", "VERSION:2.1", 1),
		strings.Replace(good, "FN;LANGUAGE", "FN:Duplicate\r\nFN;LANGUAGE", 1), strings.Replace(good, "UID:urn:uuid:external-contact", "UID:bad uid", 1),
		strings.Replace(good, "N;X-ORDER=keep:Петров;Иван;;;", "N:too;few", 1), strings.Replace(good, "ROLE:Engineer", "ROLE;ENCODING=QUOTED-PRINTABLE:Engineer", 1),
		strings.Replace(good, "ROLE:Engineer", "ROLE;CHARSET=ISO-8859-1:Engineer", 1), strings.Replace(good, "ROLE:Engineer", "ROLE;VALUE=uri:https://example.test", 1),
		strings.Replace(good, "ROLE:Engineer", "ROLE:bad\\qescape", 1), strings.Replace(good, "ROLE:Engineer", "ROLE;X-PARAM=\"broken:value", 1),
		strings.Replace(good, "ROLE:Engineer", "NOT A PROPERTY:value", 1), strings.Replace(good, "ROLE:Engineer", "BEGIN:OTHER", 1),
		strings.Replace(good, "ROLE:Engineer", "ROLE:bad\x00value", 1), strings.Replace(good, "ROLE:Engineer", "ROLE:"+string([]byte{255}), 1),
		strings.Replace(good, "ROLE:Engineer", "ROLE:Engineer\r\n"+strings.Repeat("X-A:v\r\n", 513), 1),
		strings.Replace(good, "ROLE:Engineer", "ROLE:"+strings.Repeat("x", 129), 1),
		strings.Replace(good, "ROLE:Engineer", "X-HUGE:"+strings.Repeat("<", 30000), 1),
	}
	for i, data := range cases {
		if _, _, _, err := parseVCard(data); err == nil {
			t.Fatalf("malformed/unsupported input %d accepted", i)
		}
	}
	phone := strings.Replace(externalCard("3.0"), "END:VCARD", "TEL;VALUE=phone-number:+1 234\r\nEND:VCARD", 1)
	_, projected, _, err := parseVCard(phone)
	if err != nil || len(projected.Phones) != 1 || projected.Phones[0].Value != "+1 234" {
		t.Fatal("v3 phone-number", err)
	}

	// CRLF and LF input canonicalize identically; opaque values are not interpreted.
	_, _, a, err := parseVCard(good)
	if err != nil {
		t.Fatal(err)
	}
	_, _, b, err := parseVCard(strings.ReplaceAll(good, "\r\n", "\n"))
	if err != nil || a != b {
		t.Fatal("line-ending normalization", err)
	}
	large := strings.Replace(good, "END:VCARD", "X-HUGE:"+strings.Repeat("x", 40<<10)+"\r\nEND:VCARD", 1)
	_, _, data, err := parseVCard(large)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(data)
	if len(data) > maxVCardBytes || len(wire) > 160<<10 {
		t.Fatal("wire budget exceeded")
	}
}
func TestVCardObjectsCASReplayRollbackUIDAndRevoke(t *testing.T) {
	s := fixture(t)
	scope := v1.Scope{WorkspaceID: ws, RootID: root}
	ref := v1.ContactRef{Scope: scope, ContactID: newID()}
	create := v1.ObjectCreate{ContactRef: ref, IfNoneMatch: true, Data: externalCard("4.0")}
	created, err := command(t, s, v1.CreateObject.ID, "contacts.create", "object-create", create, s.createObject)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := command(t, s, v1.CreateObject.ID, "contacts.create", "object-create", create, s.createObject)
	if err != nil || replay.ETag != created.ETag {
		t.Fatal("object replay", err)
	}
	dup := create
	dup.ContactID = newID()
	if _, err := command(t, s, v1.CreateObject.ID, "contacts.create", "duplicate-uid", dup, s.createObject); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatal("duplicate UID", err)
	}
	// The same external UID is valid in an independently permissioned book.
	other := v1.Scope{RootID: newID()}
	mustExec := s.DB.Exec("INSERT INTO roots(acl_root_id,workspace_id,owner_id,state,name,revision) VALUES(?,'',?,'active','Other',1)", other.RootID, newID()).Error
	if mustExec != nil {
		t.Fatal(mustExec)
	}
	dup.Scope = other
	if _, err := command(t, s, v1.PersonalCreateObject.ID, "contacts.create", "other-book", dup, s.createObject); err != nil {
		t.Fatal("UID incorrectly global", err)
	}
	native, err := s.get(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	native.DisplayName = "Native edited"
	_, err = command(t, s, v1.UpdateContact.ID, "contacts.write", "native-edit", v1.Update{ContactRef: ref, Input: native.Input, Revision: 1}, s.update)
	if err != nil {
		t.Fatal(err)
	}
	current, err := s.getObject(context.Background(), ref)
	if err != nil || current.ETag == created.ETag || !strings.Contains(unfoldCard(current.Data), "X-VENDOR;") {
		t.Fatal("native object coherence", err)
	}
	update := v1.ObjectUpdate{ContactRef: ref, IfMatch: created.ETag, Data: current.Data}
	if _, err := command(t, s, v1.UpdateObject.ID, "contacts.write", "stale", update, s.updateObject); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatal("stale ETag", err)
	}
	update.IfMatch = current.ETag
	update.Data = strings.Replace(current.Data, "UID:urn:uuid:external-contact", "UID:urn:uuid:different", 1)
	if _, err := command(t, s, v1.UpdateObject.ID, "contacts.write", "rebind", update, s.updateObject); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatal("UID rebind", err)
	}
	update.Data = current.Data
	if err := s.DB.Exec("CREATE TRIGGER deny_object BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fixture'); END").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := command(t, s, v1.UpdateObject.ID, "contacts.write", "rollback-object", update, s.updateObject); err == nil {
		t.Fatal("outbox rollback failed")
	}
	unchanged, err := s.getObject(context.Background(), ref)
	if err != nil || unchanged.ETag != current.ETag {
		t.Fatal("object partially committed", err)
	}
	var n int64
	if err := s.DB.Table("command_results").Where("idempotency_key='rollback-object'").Count(&n).Error; err != nil || n != 0 {
		t.Fatal("failed replay retained", err)
	}
	if err := s.DB.Exec("DROP TRIGGER deny_object").Error; err != nil {
		t.Fatal(err)
	}
	saved, err := command(t, s, v1.UpdateObject.ID, "contacts.write", "object-update", update, s.updateObject)
	if err != nil || saved.Revision != 3 || saved.ETag == current.ETag {
		t.Fatal("same-payload revision ETag", err)
	}
	s.Check = func(context.Context, string, string) error { return security.ErrDenied }
	if _, err := command(t, s, v1.CreateObject.ID, "contacts.create", "object-create", create, s.createObject); !errors.Is(err, security.ErrDenied) {
		t.Fatal("revoked replay", err)
	}
	s.Check = func(context.Context, string, string) error { return nil }
	_, err = command(t, s, v1.DeleteObject.ID, "contacts.delete", "delete-object", v1.ObjectDelete{ContactRef: ref, IfMatch: saved.ETag}, s.deleteObject)
	if err != nil {
		t.Fatal(err)
	}
	dup = create
	dup.ContactID = newID()
	if _, err := command(t, s, v1.CreateObject.ID, "contacts.create", "tombstone-uid", dup, s.createObject); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatal("tombstone UID reused", err)
	}
	if _, err := s.getObject(context.Background(), ref); rpc.ErrorCode(err) != rpc.CodeNotFound {
		t.Fatal("deleted object readable", err)
	}
}

func TestLegacyNativeExportAndFailedNativeMerge(t *testing.T) {
	s := fixture(t)
	scope := v1.Scope{WorkspaceID: ws, RootID: root}
	created, err := command(t, s, v1.CreateContact.ID, "contacts.create", "legacy", v1.Create{Scope: scope, Input: sample()}, s.create)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.DB.Exec("UPDATE contacts SET v_card_raw='' WHERE id=?", created.ID).Error; err != nil {
		t.Fatal(err)
	}
	ref := v1.ContactRef{Scope: scope, ContactID: created.ID}
	first, err := s.getObject(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.getObject(context.Background(), ref)
	if err != nil || first.ETag != again.ETag || first.UID != created.UID {
		t.Fatal("unstable legacy export", err)
	}
	// A large opaque extension can fit alone, but not together with new modeled
	// data. The entire native update must roll back instead of losing extensions.
	create := v1.ObjectCreate{ContactRef: v1.ContactRef{Scope: scope, ContactID: newID()}, IfNoneMatch: true, Data: strings.Replace(externalCard("4.0"), "END:VCARD", "X-BIG:"+strings.Repeat("<", 24000)+"\r\nEND:VCARD", 1)}
	imported, err := command(t, s, v1.CreateObject.ID, "contacts.create", "large-import", create, s.createObject)
	if err != nil {
		t.Fatal(err)
	}
	native, err := s.get(context.Background(), create.ContactRef)
	if err != nil {
		t.Fatal(err)
	}
	native.Notes = strings.Repeat("<", 5000)
	if _, err = command(t, s, v1.UpdateContact.ID, "contacts.write", "oversized-merge", v1.Update{ContactRef: create.ContactRef, Input: native.Input, Revision: 1}, s.update); rpc.ErrorCode(err) != rpc.CodeValidation {
		t.Fatal("oversized merge committed", err)
	}
	current, err := s.getObject(context.Background(), create.ContactRef)
	if err != nil || current.ETag != imported.ETag || current.Data != imported.Data {
		t.Fatal("opaque merge was not atomic", err)
	}
}
