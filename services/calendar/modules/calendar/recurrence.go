package calendar

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	v1 "github.com/pavlith/arc/services/calendar/api/v1"
	"github.com/pavlith/arc/services/calendar/models"
	"github.com/teambition/rrule-go"
	"gorm.io/gorm"
)

const maxSeriesOccurrences = 1000
const maxRootOccurrences = 100000

// wall removes the timezone without changing civil date/time components. The
// iterator works in this floating coordinate system; local gaps do not consume COUNT.
func wall(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
}

// resolveWall skips nonexistent local times and chooses the first instant of a fold.
func resolveWall(w time.Time, loc *time.Location) (time.Time, bool) {
	guess := time.Date(w.Year(), w.Month(), w.Day(), w.Hour(), w.Minute(), w.Second(), w.Nanosecond(), loc)
	var first time.Time
	for _, hours := range []int{-48, -24, 0, 24, 48} {
		_, offset := guess.Add(time.Duration(hours) * time.Hour).Zone()
		candidate := w.Add(-time.Duration(offset) * time.Second).In(loc)
		if wall(candidate).Equal(w) && (first.IsZero() || candidate.Before(first)) {
			first = candidate
		}
	}
	return first, !first.IsZero()
}
func rule(in v1.Input, start time.Time) (*rrule.RRule, int, time.Time, string, error) {
	if len(in.RRule) > 256 || strings.ContainsAny(in.RRule, "\r\n \t") {
		return nil, 0, time.Time{}, "", invalid()
	}
	fields := map[string]string{}
	for _, part := range strings.Split(in.RRule, ";") {
		kv := strings.Split(part, "=")
		if len(kv) != 2 || kv[1] == "" || fields[kv[0]] != "" {
			return nil, 0, time.Time{}, "", invalid()
		}
		switch kv[0] {
		case "FREQ", "INTERVAL", "COUNT", "UNTIL", "BYDAY", "BYMONTHDAY":
		default:
			return nil, 0, time.Time{}, "", invalid()
		}
		fields[kv[0]] = kv[1]
	}
	switch fields["FREQ"] {
	case "DAILY", "WEEKLY", "MONTHLY", "YEARLY":
	default:
		return nil, 0, time.Time{}, "", invalid()
	}
	if (fields["COUNT"] == "") == (fields["UNTIL"] == "") {
		return nil, 0, time.Time{}, "", invalid()
	}
	if fields["INTERVAL"] != "" {
		n, e := strconv.Atoi(fields["INTERVAL"])
		if e != nil || n < 1 || n > 366 {
			return nil, 0, time.Time{}, "", invalid()
		}
	}
	if days := fields["BYDAY"]; days != "" {
		if fields["FREQ"] != "WEEKLY" {
			return nil, 0, time.Time{}, "", invalid()
		}
		seen := map[string]bool{}
		for _, day := range strings.Split(days, ",") {
			if seen[day] {
				return nil, 0, time.Time{}, "", invalid()
			}
			switch day {
			case "MO", "TU", "WE", "TH", "FR", "SA", "SU":
			default:
				return nil, 0, time.Time{}, "", invalid()
			}
			seen[day] = true
		}
	}
	if day := fields["BYMONTHDAY"]; day != "" {
		n, e := strconv.Atoi(day)
		if fields["FREQ"] != "MONTHLY" || e != nil || n == 0 || n < -31 || n > 31 {
			return nil, 0, time.Time{}, "", invalid()
		}
	}
	opt, err := rrule.StrToROption(in.RRule)
	if err != nil {
		return nil, 0, time.Time{}, "", invalid()
	}
	count := opt.Count
	if fields["COUNT"] != "" && (count < 1 || count > maxSeriesOccurrences) {
		return nil, 0, time.Time{}, "", invalid()
	}
	var until time.Time
	if value := fields["UNTIL"]; value != "" {
		if in.AllDay {
			until, err = time.ParseInLocation("20060102", value, start.Location())
		} else {
			until, err = time.Parse("20060102T150405Z", value)
		}
		if err != nil || until.Before(start) || until.Year() > 2100 {
			return nil, 0, time.Time{}, "", invalid()
		}
	}
	// The library never iterates beyond the supported civil horizon. COUNT is
	// applied after local gap detection, rather than counting normalized gap times.
	opt.Dtstart = wall(start)
	opt.Count = 0
	opt.Until = time.Date(2100, 12, 31, 23, 59, 59, 0, time.UTC)
	r, err := rrule.NewRRule(*opt)
	if err != nil {
		return nil, 0, time.Time{}, "", invalid()
	}
	keys := []string{"FREQ", "INTERVAL", "COUNT", "UNTIL", "BYDAY", "BYMONTHDAY"}
	parts := []string{}
	for _, key := range keys {
		if value := fields[key]; value != "" {
			parts = append(parts, key+"="+value)
		}
	}
	return r, count, until, strings.Join(parts, ";"), nil
}
func occurrenceKey(in v1.Input, start time.Time) string {
	if in.AllDay {
		return start.Format(time.DateOnly)
	}
	return start.UTC().Format(time.RFC3339Nano)
}

// plan validates the complete series and exceptions before changing any rows.
func plan(ctx context.Context, in v1.Input) (v1.Input, []models.Occurrence, error) {
	in, start, end, err := validate(in)
	if err != nil {
		return in, nil, err
	}
	if len(in.Exceptions) > 128 || in.RRule == "" && len(in.Exceptions) > 0 {
		return in, nil, invalid()
	}
	if in.RRule == "" {
		return in, []models.Occurrence{{RecurrenceID: in.Start, Start: in.Start, End: in.End, StartAt: start, EndAt: end, Busy: in.Busy}}, nil
	}
	loc, _ := location(in.Timezone)
	localStart := start.In(loc)
	if start.Nanosecond() != 0 || end.Nanosecond() != 0 {
		return in, nil, invalid()
	}
	r, count, until, canonical, err := rule(in, localStart)
	if err != nil {
		return in, nil, err
	}
	in.RRule = canonical
	exceptions := make(map[string]v1.Exception, len(in.Exceptions))
	// Copy before canonicalizing so callers do not observe slice mutations.
	in.Exceptions = append([]v1.Exception(nil), in.Exceptions...)
	for i, x := range in.Exceptions {
		var key string
		if in.AllDay {
			date, e := time.Parse(time.DateOnly, x.RecurrenceID)
			if e != nil {
				return in, nil, invalid()
			}
			key = date.Format(time.DateOnly)
		} else {
			instant, e := time.Parse(time.RFC3339Nano, x.RecurrenceID)
			if e != nil || instant.Nanosecond() != 0 {
				return in, nil, invalid()
			}
			key = instant.UTC().Format(time.RFC3339Nano)
		}
		if _, exists := exceptions[key]; exists || x.Cancelled && (x.Start != "" || x.End != "") {
			return in, nil, invalid()
		}
		x.RecurrenceID = key
		if !x.Cancelled {
			replacement := in
			replacement.Start = x.Start
			replacement.End = x.End
			replacement.RRule = ""
			replacement.Exceptions = nil
			normalized, replacementStart, replacementEnd, e := validate(replacement)
			if e != nil {
				return in, nil, e
			}
			if replacementStart.Nanosecond() != 0 || replacementEnd.Nanosecond() != 0 {
				return in, nil, invalid()
			}
			x.Start, x.End = normalized.Start, normalized.End
		}
		in.Exceptions[i] = x
		exceptions[key] = x
	}
	sort.Slice(in.Exceptions, func(i, j int) bool { return in.Exceptions[i].RecurrenceID < in.Exceptions[j].RecurrenceID })
	out := []models.Occurrence{}
	duration := end.Sub(start)
	startDate, _ := time.Parse(time.DateOnly, in.Start)
	endDate, _ := time.Parse(time.DateOnly, in.End)
	days := int(endDate.Sub(startDate) / (24 * time.Hour))
	next := r.Iterator()
	generated := 0
	for {
		if err := ctx.Err(); err != nil {
			return in, nil, err
		}
		w, ok := next()
		if !ok {
			break
		}
		var a, b time.Time
		if in.AllDay {
			a, err = time.ParseInLocation(time.DateOnly, w.Format(time.DateOnly), loc)
			if err != nil || a.Format(time.DateOnly) != w.Format(time.DateOnly) {
				continue
			}
			endDate := w.AddDate(0, 0, days).Format(time.DateOnly)
			b, err = time.ParseInLocation(time.DateOnly, endDate, loc)
			if err != nil || b.Format(time.DateOnly) != endDate {
				return in, nil, invalid()
			}
		} else {
			a, ok = resolveWall(w, loc)
			if !ok {
				continue
			}
			b = a.Add(duration)
		}
		if !until.IsZero() && a.After(until) {
			break
		}
		if generated == 0 && !a.Equal(start) {
			return in, nil, invalid()
		}
		generated++
		if generated > maxSeriesOccurrences || a.Year() > 2100 || b.Year() > 2100 || !b.After(a) {
			return in, nil, invalid()
		}
		key := occurrenceKey(in, a)
		item := models.Occurrence{RecurrenceID: key, Start: occurrenceKey(in, a), End: occurrenceKey(in, b), StartAt: a.UTC(), EndAt: b.UTC(), Busy: in.Busy}
		if x, exists := exceptions[key]; exists {
			delete(exceptions, key)
			if !x.Cancelled {
				replacement := in
				replacement.Start = x.Start
				replacement.End = x.End
				normalized, from, to, e := validate(replacement)
				if e != nil {
					return in, nil, e
				}
				item.Start, item.End, item.StartAt, item.EndAt = normalized.Start, normalized.End, from, to
				out = append(out, item)
			}
		} else {
			out = append(out, item)
		}
		if count > 0 && generated == count {
			break
		}
	}
	if generated == 0 || count > 0 && generated != count || len(exceptions) > 0 {
		return in, nil, invalid()
	}
	return in, out, nil
}
func (s *Module) replaceOccurrences(ctx context.Context, tx *gorm.DB, row models.Event, items []models.Occurrence) error {
	if err := tx.WithContext(ctx).Where("event_id=?", row.ID).Delete(&models.Occurrence{}).Error; err != nil {
		return dbError(err)
	}
	var count int64
	if err := tx.WithContext(ctx).Model(&models.Occurrence{}).Where("workspace_id=? AND acl_root_id=?", row.WorkspaceID, row.RootID).Count(&count).Error; err != nil {
		return dbError(err)
	}
	if count+int64(len(items)) > maxRootOccurrences {
		return invalid()
	}
	for i := range items {
		items[i].EventID = row.ID
		items[i].WorkspaceID = row.WorkspaceID
		items[i].RootID = row.RootID
	}
	if len(items) > 0 {
		return dbError(tx.WithContext(ctx).CreateInBatches(items, 100).Error)
	}
	return nil
}
func exceptionsJSON(in v1.Input) string {
	if len(in.Exceptions) == 0 {
		return "[]"
	}
	raw, _ := json.Marshal(in.Exceptions)
	return string(raw)
}
