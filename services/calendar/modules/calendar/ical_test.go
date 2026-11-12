package calendar

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/calendar/api/v1"
	"github.com/pavlith/arc/services/calendar/models"
)

func calendarText(body string) string {
	return "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Fixture//EN\r\nX-CLIENT-CALENDAR:preserve\r\nBEGIN:VEVENT\r\nUID:external-uid@client.test\r\nDTSTAMP:20261112T000000Z\r\n" + body + "\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
}
func sampleICal() string {
	return calendarText("DTSTART:20261112T090000Z\r\nDTEND:20261112T100000Z\r\nSUMMARY:Review\\, plan\r\nDESCRIPTION:Line one\\nLine two\r\nSTATUS:TENTATIVE\r\nX-CLIENT;X-PARAM=\"a:b\":opaque\r\nATTENDEE;CN=Guest:mailto:guest@example.test\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nDESCRIPTION:Reminder\r\nEND:VALARM")
}
func TestICalendarCodecRoundTripAndBounds(t *testing.T) {
	ctx := context.Background()
	uid, in, err := parseICal(ctx, sampleICal())
	if err != nil || uid != "external-uid@client.test" || in.Title != "Review, plan" || in.Description != "Line one\nLine two" {
		t.Fatalf("import: %s %+v %v", uid, in, err)
	}
	stamp := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	data, err := renderICal(in, uid, 1, stamp, sampleICal())
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{"X-CLIENT-CALENDAR:preserve", "X-CLIENT;X-PARAM=\"a:b\":opaque", "ATTENDEE;CN=Guest:mailto:guest@example.test", "BEGIN:VALARM", "STATUS:TENTATIVE"} {
		if !strings.Contains(data, wanted) {
			t.Fatal("opaque property lost", wanted)
		}
	}
	again, err := renderICal(in, uid, 1, stamp, sampleICal())
	if err != nil || data != again {
		t.Fatal("unstable export", err)
	}
	_, decoded, err := parseICal(ctx, data)
	if err != nil || decoded.Title != in.Title || decoded.Description != in.Description {
		t.Fatalf("roundtrip: %+v %v", decoded, err)
	}
	// Folding preserves UTF-8 and escaped text across long logical lines.
	in.Title = strings.Repeat("会議", 80)
	data, err = renderICal(in, uid, 1, stamp, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(data, "\r\n") {
		if len(line) > 75 {
			t.Fatal("unfolded physical line", len(line))
		}
	}
	_, decoded, err = parseICal(ctx, data)
	if err != nil || decoded.Title != in.Title {
		t.Fatal("UTF-8 folding roundtrip", decoded.Title, err)
	}
	// IANA recurring times keep wall-clock time and use explicit trusted transitions.
	series := v1.Input{Title: "Series", Description: "Private", Timezone: "America/New_York", Start: "2026-03-07T14:00:00Z", End: "2026-03-07T15:00:00Z", Busy: true, RRule: "FREQ=DAILY;COUNT=3", Exceptions: []v1.Exception{
		{RecurrenceID: "2026-03-08T13:00:00Z", Cancelled: true},
		{RecurrenceID: "2026-03-09T13:00:00Z", Start: "2026-03-10T13:00:00Z", End: "2026-03-10T14:00:00Z"},
	}}
	data, err = renderICal(series, uid, 2, stamp, "")
	if err != nil {
		t.Fatal("IANA export", err)
	}
	if !strings.Contains(data, "BEGIN:VTIMEZONE") || !strings.Contains(data, "DTSTART;TZID=America/New_York:20260307T090000") {
		t.Fatal("timezone absent")
	}
	_, decoded, err = parseICal(ctx, data)
	if err != nil || decoded.Timezone != series.Timezone || decoded.RRule != series.RRule || len(decoded.Exceptions) != 2 {
		t.Fatalf("IANA import: %+v %v", decoded, err)
	}
	day := v1.Input{Title: "All day", Timezone: "Europe/Berlin", AllDay: true, Start: "2026-03-28", End: "2026-03-29", RRule: "FREQ=DAILY;COUNT=3"}
	data, err = renderICal(day, uid, 1, stamp, "")
	if err != nil {
		t.Fatal(err)
	}
	_, decoded, err = parseICal(ctx, data)
	if err != nil || !decoded.AllDay || decoded.Start != day.Start || decoded.Timezone != day.Timezone {
		t.Fatal("DATE roundtrip", decoded, err)
	}
	exdate := calendarText("DTSTART:20261112T090000Z\r\nDTEND:20261112T100000Z\r\nSUMMARY:Excluded\r\nRRULE:FREQ=DAILY;COUNT=3\r\nEXDATE:20261113T090000Z,20261114T090000Z")
	_, decoded, err = parseICal(ctx, exdate)
	if err != nil || len(decoded.Exceptions) != 2 {
		t.Fatal("EXDATE", decoded, err)
	}
	for _, bad := range []string{
		strings.Replace(sampleICal(), "UID:external-uid@client.test", "UID:external-uid@client.test\r\nUID:other", 1),
		strings.Replace(sampleICal(), "DTSTART:20261112T090000Z", "DTSTART:20261112T090000", 1),
		strings.Replace(sampleICal(), "DTSTAMP:20261112T000000Z", "DTSTAMP:invalid", 1),
		strings.Replace(sampleICal(), "VERSION:2.0", "VERSION:2.0\r\nMETHOD:REQUEST", 1),
		sampleICal() + sampleICal(),
		strings.Replace(sampleICal(), "BEGIN:VALARM", "BEGIN:VALARM\r\nBEGIN:VEVENT", 1),
		calendarText("DTSTART:20261112T090000Z\r\nDTEND:20261112T100000Z\r\nSUMMARY:Unsafe\r\nRDATE:20261113T090000Z"),
		strings.Repeat("x", maxICalBytes+1),
	} {
		if _, _, err := parseICal(ctx, bad); rpc.ErrorCode(err) != rpc.CodeValidation {
			t.Fatal("unsupported/malformed accepted", err)
		}
	}
}
func TestICalendarObjectCASUIDReplayAndRollback(t *testing.T) {
	s := fixture(t)
	scope := v1.Scope{WorkspaceID: ws, RootID: root}
	ref := v1.EventRef{Scope: scope, EventID: newID()}
	q := v1.ObjectCreate{EventRef: ref, IfNoneMatch: true, Data: sampleICal()}
	created, err := command(t, s, v1.CreateObject.ID, "calendar.create", "ical-create", q, s.createObject)
	if err != nil {
		t.Fatal(err)
	}
	if !strongETag.MatchString(created.ETag) || created.UID != "external-uid@client.test" {
		t.Fatal(created)
	}
	replay, err := command(t, s, v1.CreateObject.ID, "calendar.create", "ical-create", q, s.createObject)
	if err != nil || replay.ETag != created.ETag || replay.Data != created.Data {
		t.Fatal("object replay", err)
	}
	fetched, err := s.getObject(context.Background(), ref)
	if err != nil || fetched.ETag != created.ETag || fetched.Data != created.Data {
		t.Fatal("object read changed", err)
	}
	duplicate := q
	duplicate.EventID = newID()
	if _, err = command(t, s, v1.CreateObject.ID, "calendar.create", "duplicate-uid", duplicate, s.createObject); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatal("duplicate UID accepted", err)
	}
	update := v1.ObjectUpdate{EventRef: ref, IfMatch: created.ETag, Data: strings.Replace(sampleICal(), "Review\\, plan", "Changed", 1)}
	saved, err := command(t, s, v1.UpdateObject.ID, "calendar.write", "ical-update", update, s.updateObject)
	if err != nil || saved.ETag == created.ETag || saved.UID != created.UID {
		t.Fatal("object update", err)
	}
	if _, err = command(t, s, v1.UpdateObject.ID, "calendar.write", "stale-ical-update", update, s.updateObject); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatal("stale ETag accepted", err)
	}
	update.IfMatch = saved.ETag
	update.Data = strings.Replace(update.Data, "external-uid@client.test", "different-uid", 1)
	if _, err = command(t, s, v1.UpdateObject.ID, "calendar.write", "change-uid", update, s.updateObject); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatal("UID rename accepted", err)
	}
	// JSON mutations keep UID and opaque fields while invalidating the object ETag.
	native := v1.Update{EventRef: ref, Input: sample(), Revision: 2}
	if _, err = command(t, s, v1.UpdateEvent.ID, "calendar.write", "native-update", native, s.update); err != nil {
		t.Fatal(err)
	}
	current, err := s.getObject(context.Background(), ref)
	if err != nil || current.UID != saved.UID || current.ETag == saved.ETag || !strings.Contains(current.Data, "X-CLIENT;") {
		t.Fatal("native update lost object fields", err)
	}
	update.IfMatch = current.ETag
	update.Data = sampleICal()
	s.Check = func(_ context.Context, _ string, action string) error {
		if action == "calendar.read" {
			return nil
		}
		return security.ErrDenied
	}
	readContext := invocation(t, v1.GetObject.ID, ws, "", ref)
	if err = s.Authorize(readContext, root, "calendar.read"); err != nil {
		t.Fatal(err)
	}
	if _, err = command(t, s, v1.UpdateObject.ID, "calendar.write", "readonly-object", update, s.updateObject); err == nil {
		t.Fatal("read-only actor changed an iCalendar object")
	}
	s.Check = func(context.Context, string, string) error { return nil }
	s.DB.Exec("CREATE TRIGGER deny_object BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fixture'); END")
	if _, err = command(t, s, v1.UpdateObject.ID, "calendar.write", "object-rollback", update, s.updateObject); err == nil {
		t.Fatal("outbox failure committed")
	}
	restored, err := s.getObject(context.Background(), ref)
	if err != nil || restored.ETag != current.ETag {
		t.Fatal("object rollback changed representation", err)
	}
	var n int64
	s.DB.Table("command_results").Where("idempotency_key='object-rollback'").Count(&n)
	if n != 0 {
		t.Fatal("failed object replay retained")
	}
	s.DB.Exec("DROP TRIGGER deny_object")
	s.Check = func(context.Context, string, string) error { return security.ErrDenied }
	if _, err = command(t, s, v1.CreateObject.ID, "calendar.create", "ical-create", q, s.createObject); err == nil {
		t.Fatal("revoked object replay allowed")
	}
	s.Check = func(context.Context, string, string) error { return nil }
	if _, err = command(t, s, v1.DeleteObject.ID, "calendar.delete", "stale-delete", v1.ObjectDelete{EventRef: ref, IfMatch: saved.ETag}, s.deleteObject); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatal("stale object delete allowed", err)
	}
	if _, err = command(t, s, v1.DeleteObject.ID, "calendar.delete", "object-delete", v1.ObjectDelete{EventRef: ref, IfMatch: current.ETag}, s.deleteObject); err != nil {
		t.Fatal(err)
	}
	if _, err = command(t, s, v1.CreateObject.ID, "calendar.create", "resurrect-uid", duplicate, s.createObject); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatal("tombstone UID reused", err)
	}
	s.DB.Model(&models.Occurrence{}).Where("event_id=?", ref.EventID).Count(&n)
	if n != 0 {
		t.Fatal("object delete retained occurrences")
	}
	foreign := ref
	foreign.RootID = newID()
	if _, err = s.getObject(context.Background(), foreign); rpc.ErrorCode(err) != rpc.CodeNotFound {
		t.Fatal("cross-root object lookup", err)
	}
}
