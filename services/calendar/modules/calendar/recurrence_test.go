package calendar

import (
	"context"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/rpc"
	v1 "github.com/pavlith/arc/services/calendar/api/v1"
	"github.com/pavlith/arc/services/calendar/models"
)

func TestRecurrenceCivilTimeAndBounds(t *testing.T) {
	base := v1.Input{Title: "Series", Timezone: "America/New_York", Start: "2026-03-07T09:00:00-05:00", End: "2026-03-07T10:00:00-05:00", Busy: true, RRule: "FREQ=DAILY;COUNT=3"}
	for _, tc := range []struct {
		name string
		in   v1.Input
		want []string
	}{
		{"spring", base, []string{"2026-03-07T14:00:00Z", "2026-03-08T13:00:00Z", "2026-03-09T13:00:00Z"}},
		{"gap", v1.Input{Title: "Gap", Timezone: base.Timezone, Start: "2026-03-07T02:30:00-05:00", End: "2026-03-07T03:30:00-05:00", RRule: base.RRule}, []string{"2026-03-07T07:30:00Z", "2026-03-09T06:30:00Z", "2026-03-10T06:30:00Z"}},
		{"month", v1.Input{Title: "Month", Timezone: "UTC", AllDay: true, Start: "2026-01-31", End: "2026-02-01", RRule: "FREQ=MONTHLY;COUNT=3"}, []string{"2026-01-31", "2026-03-31", "2026-05-31"}},
		{"leap", v1.Input{Title: "Leap", Timezone: "UTC", AllDay: true, Start: "2024-02-29", End: "2024-03-01", RRule: "FREQ=YEARLY;COUNT=3"}, []string{"2024-02-29", "2028-02-29", "2032-02-29"}},
		{"until", v1.Input{Title: "Until", Timezone: "UTC", AllDay: true, Start: "2026-03-07", End: "2026-03-08", RRule: "FREQ=DAILY;UNTIL=20260309"}, []string{"2026-03-07", "2026-03-08", "2026-03-09"}},
		{"weekdays", v1.Input{Title: "Weekly", Timezone: "UTC", AllDay: true, Start: "2026-03-09", End: "2026-03-10", RRule: "FREQ=WEEKLY;COUNT=3;BYDAY=MO,WE"}, []string{"2026-03-09", "2026-03-11", "2026-03-16"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, items, err := plan(context.Background(), tc.in)
			if err != nil || len(items) != len(tc.want) {
				t.Fatalf("plan: %+v %v", items, err)
			}
			for i, item := range items {
				if item.Start != tc.want[i] {
					t.Fatalf("%d: %s want %s", i, item.Start, tc.want[i])
				}
			}
		})
	}
	allDay := base
	allDay.AllDay = true
	allDay.Start = "2026-03-07"
	allDay.End = "2026-03-08"
	_, items, err := plan(context.Background(), allDay)
	if err != nil || items[1].EndAt.Sub(items[1].StartAt) != 23*time.Hour {
		t.Fatalf("all-day DST: %+v %v", items, err)
	}
	loc, _ := time.LoadLocation(base.Timezone)
	fold, ok := resolveWall(time.Date(2026, 11, 1, 1, 30, 0, 0, time.UTC), loc)
	if !ok || fold.UTC().Format(time.RFC3339) != "2026-11-01T05:30:00Z" {
		t.Fatal("ambiguous time did not choose first instant", fold)
	}
	for _, value := range []string{"FREQ=HOURLY;COUNT=3", "FREQ=DAILY", "FREQ=DAILY;COUNT=1001", "FREQ=DAILY;COUNT=2;UNTIL=20260309T000000Z", "FREQ=DAILY;COUNT=2;COUNT=3", "FREQ=DAILY;INTERVAL=0;COUNT=2", "FREQ=MONTHLY;COUNT=2;BYDAY=MO", "FREQ=DAILY;COUNT=3;BYHOUR=9", "FREQ=YEARLY;COUNT=1000"} {
		in := base
		in.RRule = value
		if _, _, err := plan(context.Background(), in); rpc.ErrorCode(err) != rpc.CodeValidation {
			t.Fatalf("unsupported/unbounded %s: %v", value, err)
		}
	}
}
func TestRecurringExceptionsAtomicityAndEffectiveQueries(t *testing.T) {
	s := fixture(t)
	scope := v1.Scope{WorkspaceID: ws, RootID: root}
	in := v1.Input{Title: "Secret series", Description: "Private", Timezone: "America/New_York", Start: "2026-03-07T09:00:00-05:00", End: "2026-03-07T10:00:00-05:00", Busy: true, RRule: "FREQ=DAILY;COUNT=3", Exceptions: []v1.Exception{
		{RecurrenceID: "2026-03-08T09:00:00-04:00", Cancelled: true},
		{RecurrenceID: "2026-03-09T13:00:00Z", Start: "2026-04-05T09:00:00-04:00", End: "2026-04-05T10:00:00-04:00"},
	}}
	q := v1.Create{Scope: scope, Input: in}
	created, err := command(t, s, v1.CreateEvent.ID, "calendar.create", "series", q, s.create)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := command(t, s, v1.CreateEvent.ID, "calendar.create", "series", q, s.create)
	if err != nil || replay.ID != created.ID {
		t.Fatal("recurrence replay", err)
	}
	ref := v1.EventRef{Scope: scope, EventID: created.ID}
	stored, err := s.get(context.Background(), ref)
	if err != nil || stored.RRule != in.RRule || len(stored.Exceptions) != 2 {
		t.Fatalf("series persistence: %+v %v", stored, err)
	}
	april := time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC)
	rangeQ := v1.Range{Scope: scope, From: april, Until: april.Add(24 * time.Hour)}
	list, err := s.list(context.Background(), v1.List{Range: rangeQ, Limit: 10})
	if err != nil || len(list.Events) != 1 || list.Events[0].ID != created.ID {
		t.Fatalf("moved-in series: %+v %v", list, err)
	}
	occ, err := s.occurrences(context.Background(), v1.OccurrenceQuery{Range: rangeQ, Limit: 10})
	if err != nil || len(occ.Occurrences) != 1 || occ.Occurrences[0].RecurrenceID != "2026-03-09T13:00:00Z" {
		t.Fatalf("moved occurrence identity: %+v %v", occ, err)
	}
	busy, err := s.freeBusy(context.Background(), rangeQ)
	if err != nil || len(busy.Intervals) != 1 {
		t.Fatal("moved free/busy", busy, err)
	}
	rangeQ.From = time.Date(2026, 3, 8, 0, 0, 0, 0, time.UTC)
	rangeQ.Until = rangeQ.From.Add(24 * time.Hour)
	busy, err = s.freeBusy(context.Background(), rangeQ)
	if err != nil || len(busy.Intervals) != 0 {
		t.Fatal("cancelled free/busy", busy, err)
	}
	wide := v1.Range{Scope: scope, From: time.Date(2026, 3, 7, 0, 0, 0, 0, time.UTC), Until: april.Add(24 * time.Hour)}
	first, err := s.occurrences(context.Background(), v1.OccurrenceQuery{Range: wide, Limit: 1})
	if err != nil || first.NextCursor == "" {
		t.Fatalf("occurrence pagination: %+v %v", first, err)
	}
	second, err := s.occurrences(context.Background(), v1.OccurrenceQuery{Range: wide, Limit: 1, Cursor: first.NextCursor})
	if err != nil || len(second.Occurrences) != 1 || second.Occurrences[0].RecurrenceID == first.Occurrences[0].RecurrenceID {
		t.Fatalf("occurrence next: %+v %v", second, err)
	}
	wrong := wide
	wrong.RootID = newID()
	other, err := s.occurrences(context.Background(), v1.OccurrenceQuery{Range: wrong, Limit: 10})
	if err != nil || len(other.Occurrences) != 0 {
		t.Fatal("foreign root occurrence leak", err)
	}
	// Failing materialization rolls back series metadata, effective rows and replay.
	if err = s.DB.Exec("CREATE TRIGGER deny_occurrence BEFORE INSERT ON event_occurrences BEGIN SELECT RAISE(ABORT,'fixture'); END").Error; err != nil {
		t.Fatal(err)
	}
	update := v1.Update{EventRef: ref, Input: in, Revision: 1}
	update.Title = "Changed"
	if _, err = command(t, s, v1.UpdateEvent.ID, "calendar.write", "failed-series", update, s.update); err == nil {
		t.Fatal("failed occurrence write committed")
	}
	stored, err = s.get(context.Background(), ref)
	if err != nil || stored.Revision != 1 || stored.Title != in.Title {
		t.Fatal("series rollback", stored, err)
	}
	var count int64
	s.DB.Model(&models.Occurrence{}).Where("event_id=?", created.ID).Count(&count)
	if count != 2 {
		t.Fatal("occurrences not rolled back", count)
	}
	s.DB.Table("command_results").Where("idempotency_key='failed-series'").Count(&count)
	if count != 0 {
		t.Fatal("failed replay retained")
	}
	s.DB.Exec("DROP TRIGGER deny_occurrence")
	update.Exceptions = nil
	if _, err = command(t, s, v1.UpdateEvent.ID, "calendar.write", "restore-series", update, s.update); err != nil {
		t.Fatal(err)
	}
	if _, err = command(t, s, v1.UpdateEvent.ID, "calendar.write", "stale-series", update, s.update); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatal("series stale CAS", err)
	}
	if _, err = command(t, s, v1.DeleteEvent.ID, "calendar.delete", "delete-series", v1.Delete{EventRef: ref, Revision: 2}, s.delete); err != nil {
		t.Fatal(err)
	}
	s.DB.Model(&models.Occurrence{}).Where("event_id=?", created.ID).Count(&count)
	if count != 0 {
		t.Fatal("deleted occurrences retained")
	}
	for _, exceptions := range [][]v1.Exception{
		{{RecurrenceID: "2026-03-08T13:00:00Z", Cancelled: true}, {RecurrenceID: "2026-03-08T09:00:00-04:00", Cancelled: true}},
		{{RecurrenceID: "2026-03-10T13:00:00Z", Cancelled: true}},
		{{RecurrenceID: "2026-03-08T13:00:00Z", Cancelled: true, Start: in.Start}},
		{{RecurrenceID: "2026-03-08T13:00:00Z", Start: "2026-03-08T13:00:00.1Z", End: "2026-03-08T14:00:00Z"}},
	} {
		invalid := in
		invalid.Exceptions = exceptions
		if _, _, err := plan(context.Background(), invalid); rpc.ErrorCode(err) != rpc.CodeValidation {
			t.Fatal("invalid exception accepted", exceptions, err)
		}
	}
}
