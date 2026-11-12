package calendar

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	v1 "github.com/pavlith/arc/services/calendar/api/v1"
	"github.com/pavlith/arc/services/calendar/models"
	"gorm.io/gorm"
)

func validate(in v1.Input) (v1.Input, time.Time, time.Time, error) {
	in.Title = strings.TrimSpace(in.Title)
	var start, end time.Time
	if !utf8.ValidString(in.Title) || in.Title == "" || utf8.RuneCountInString(in.Title) > 256 || !utf8.ValidString(in.Description) || utf8.RuneCountInString(in.Description) > 8192 {
		return in, start, end, invalid()
	}
	loc, err := location(in.Timezone)
	if err != nil {
		return in, start, end, err
	}
	if in.AllDay {
		start, err = time.ParseInLocation(time.DateOnly, in.Start, loc)
		if err != nil || start.Format(time.DateOnly) != in.Start {
			return in, start, end, invalid()
		}
		end, err = time.ParseInLocation(time.DateOnly, in.End, loc)
		if err != nil || end.Format(time.DateOnly) != in.End {
			return in, start, end, invalid()
		}
	} else {
		start, err = time.Parse(time.RFC3339Nano, in.Start)
		if err != nil {
			return in, start, end, invalid()
		}
		end, err = time.Parse(time.RFC3339Nano, in.End)
		if err != nil {
			return in, start, end, invalid()
		}
		in.Start = start.UTC().Format(time.RFC3339Nano)
		in.End = end.UTC().Format(time.RFC3339Nano)
	}
	if start.Year() < 1900 || end.Year() > 2100 || !end.After(start) || end.Sub(start) > 367*24*time.Hour {
		return in, start, end, invalid()
	}
	return in, start.UTC(), end.UTC(), nil
}
func dto(r models.Event) v1.Event {
	var exceptions []v1.Exception
	_ = json.Unmarshal([]byte(r.Exceptions), &exceptions)
	return v1.Event{UID: r.UID, Scope: v1.Scope{WorkspaceID: r.WorkspaceID, RootID: r.RootID}, ID: r.ID, Input: v1.Input{Title: r.Title, Description: r.Description, Timezone: r.Timezone, AllDay: r.AllDay, Start: r.Start, End: r.End, Busy: r.Busy, RRule: r.RRule, Exceptions: exceptions}, Revision: r.Revision, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
}
func (s *Module) row(ctx context.Context, db *gorm.DB, q v1.EventRef) (models.Event, error) {
	var row models.Event
	err := db.WithContext(ctx).Where("id=? AND workspace_id=? AND acl_root_id=? AND deleted_at IS NULL", q.EventID, q.WorkspaceID, q.RootID).Take(&row).Error
	return row, dbError(err)
}
func (s *Module) create(ctx context.Context, tx *gorm.DB, q v1.Create) (v1.Event, error) {
	id := newID()
	return s.createStored(ctx, tx, q, id, id+"@arc", "")
}
func (s *Module) createStored(ctx context.Context, tx *gorm.DB, q v1.Create, id, uid, raw string) (v1.Event, error) {
	in, items, err := plan(ctx, q.Input)
	if err != nil {
		return v1.Event{}, err
	}
	_, start, end, _ := validate(in)
	var count int64
	if err := tx.Model(&models.Event{}).Where("workspace_id=? AND acl_root_id=?", q.WorkspaceID, q.RootID).Count(&count).Error; err != nil {
		return v1.Event{}, dbError(err)
	}
	if count >= 10000 {
		return v1.Event{}, invalid()
	}
	now := time.Now().UTC()
	row := models.Event{UID: uid, ICalRaw: raw, ID: id, WorkspaceID: q.WorkspaceID, RootID: q.RootID, Title: in.Title, Description: in.Description, Timezone: in.Timezone, AllDay: in.AllDay, Start: in.Start, End: in.End, StartAt: start, EndAt: end, Busy: in.Busy, RRule: in.RRule, Exceptions: exceptionsJSON(in), Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := tx.Create(&row).Error; err != nil {
		return v1.Event{}, dbError(err)
	}
	if err := s.replaceOccurrences(ctx, tx, row, items); err != nil {
		return v1.Event{}, err
	}
	return dto(row), s.changed(ctx, tx, q.Scope, row.ID, 1, "created")
}
func (s *Module) get(ctx context.Context, q v1.EventRef) (v1.Event, error) {
	row, err := s.row(ctx, s.db(ctx), q)
	return dto(row), err
}
func (s *Module) update(ctx context.Context, tx *gorm.DB, q v1.Update) (v1.Event, error) {
	return s.updateStored(ctx, tx, q, nil)
}
func (s *Module) updateStored(ctx context.Context, tx *gorm.DB, q v1.Update, raw *string) (v1.Event, error) {
	row, err := s.row(ctx, tx, q.EventRef)
	if err != nil {
		return v1.Event{}, err
	}
	if q.Revision < 1 || q.Revision != row.Revision {
		return v1.Event{}, conflict()
	}
	in, items, err := plan(ctx, q.Input)
	if err != nil {
		return v1.Event{}, err
	}
	_, start, end, _ := validate(in)
	now := time.Now().UTC()
	if !now.After(row.UpdatedAt) {
		now = row.UpdatedAt.Add(time.Nanosecond)
	}
	updates := map[string]any{"title": in.Title, "description": in.Description, "timezone": in.Timezone, "all_day": in.AllDay, "start": in.Start, "end": in.End, "start_at": start, "end_at": end, "busy": in.Busy, "r_rule": in.RRule, "exceptions": exceptionsJSON(in), "revision": q.Revision + 1, "updated_at": now}
	if raw != nil {
		updates["i_cal_raw"] = *raw
	}
	res := tx.Model(&models.Event{}).Where("id=? AND workspace_id=? AND acl_root_id=? AND revision=? AND deleted_at IS NULL", row.ID, q.WorkspaceID, q.RootID, q.Revision).Updates(updates)
	if res.Error != nil {
		return v1.Event{}, dbError(res.Error)
	}
	if res.RowsAffected != 1 {
		return v1.Event{}, conflict()
	}
	row.Title = in.Title
	row.Description = in.Description
	row.Timezone = in.Timezone
	row.AllDay = in.AllDay
	row.Start = in.Start
	row.End = in.End
	row.StartAt = start
	row.EndAt = end
	row.Busy = in.Busy
	row.RRule = in.RRule
	row.Exceptions = exceptionsJSON(in)
	if raw != nil {
		row.ICalRaw = *raw
	}
	row.Revision++
	row.UpdatedAt = now
	if err := s.replaceOccurrences(ctx, tx, row, items); err != nil {
		return v1.Event{}, err
	}
	return dto(row), s.changed(ctx, tx, q.Scope, row.ID, row.Revision, "updated")
}
func (s *Module) delete(ctx context.Context, tx *gorm.DB, q v1.Delete) (v1.Mutation, error) {
	row, err := s.row(ctx, tx, q.EventRef)
	if err != nil {
		return v1.Mutation{}, err
	}
	if q.Revision < 1 || q.Revision != row.Revision {
		return v1.Mutation{}, conflict()
	}
	now := time.Now().UTC()
	res := tx.Model(&models.Event{}).Where("id=? AND workspace_id=? AND acl_root_id=? AND revision=? AND deleted_at IS NULL", row.ID, q.WorkspaceID, q.RootID, q.Revision).Updates(map[string]any{"deleted_at": now, "updated_at": now, "revision": q.Revision + 1})
	if res.Error != nil {
		return v1.Mutation{}, dbError(res.Error)
	}
	if res.RowsAffected != 1 {
		return v1.Mutation{}, conflict()
	}
	if err := tx.Where("event_id=?", row.ID).Delete(&models.Occurrence{}).Error; err != nil {
		return v1.Mutation{}, dbError(err)
	}
	return v1.Mutation{ID: row.ID, Revision: q.Revision + 1, Deleted: true}, s.changed(ctx, tx, q.Scope, row.ID, q.Revision+1, "deleted")
}
func validRange(q v1.Range) bool {
	return !q.From.IsZero() && q.From.Year() >= 1900 && q.Until.Year() <= 2100 && q.Until.After(q.From) && q.Until.Sub(q.From) <= 31*24*time.Hour
}
func (s *Module) ranged(ctx context.Context, q v1.Range) *gorm.DB {
	return s.db(ctx).Model(&models.Occurrence{}).Where("workspace_id=? AND acl_root_id=? AND start_at<? AND end_at>?", q.WorkspaceID, q.RootID, q.Until.UTC(), q.From.UTC())
}
func (s *Module) list(ctx context.Context, q v1.List) (v1.EventList, error) {
	out := v1.EventList{Events: []v1.EventSummary{}}
	if !validRange(q.Range) || q.Limit < 1 || q.Limit > 100 || q.Cursor != "" && !idPattern.MatchString(q.Cursor) {
		return out, invalid()
	}
	var rows []models.Event
	if err := s.db(ctx).Model(&models.Event{}).Where("workspace_id=? AND acl_root_id=? AND deleted_at IS NULL AND id>?", q.WorkspaceID, q.RootID, q.Cursor).Where("EXISTS(SELECT 1 FROM event_occurrences o WHERE o.event_id=calendar_events.id AND o.workspace_id=calendar_events.workspace_id AND o.acl_root_id=calendar_events.acl_root_id AND o.start_at<? AND o.end_at>?)", q.Until.UTC(), q.From.UTC()).Order("id").Limit(q.Limit + 1).Find(&rows).Error; err != nil {
		return out, dbError(err)
	}
	if len(rows) > q.Limit {
		rows = rows[:q.Limit]
		out.NextCursor = rows[len(rows)-1].ID
	}
	for _, r := range rows {
		out.Events = append(out.Events, v1.EventSummary{Scope: q.Scope, ID: r.ID, Title: r.Title, Timezone: r.Timezone, AllDay: r.AllDay, Start: r.Start, End: r.End, Busy: r.Busy, Revision: r.Revision, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt})
	}
	return out, nil
}
func (s *Module) freeBusy(ctx context.Context, q v1.Range) (v1.BusyResult, error) {
	out := v1.BusyResult{Intervals: []v1.Interval{}}
	if !validRange(q) {
		return out, invalid()
	}
	// No event identifiers, descriptions or titles are selected or returned.
	var rows []struct {
		StartAt time.Time
		EndAt   time.Time
	}
	if err := s.ranged(ctx, q).Select("start_at,end_at").Where("busy=1").Order("start_at,end_at").Limit(maxRootOccurrences + 1).Scan(&rows).Error; err != nil {
		return out, dbError(err)
	}
	if len(rows) > maxRootOccurrences {
		return out, invalid()
	}
	for _, r := range rows {
		a, b := r.StartAt.UTC(), r.EndAt.UTC()
		if a.Before(q.From) {
			a = q.From.UTC()
		}
		if b.After(q.Until) {
			b = q.Until.UTC()
		}
		n := len(out.Intervals)
		if n > 0 && !a.After(out.Intervals[n-1].End) {
			if b.After(out.Intervals[n-1].End) {
				out.Intervals[n-1].End = b
			}
		} else {
			out.Intervals = append(out.Intervals, v1.Interval{Start: a, End: b})
		}
	}
	if len(out.Intervals) > 1000 {
		return v1.BusyResult{Intervals: []v1.Interval{}}, invalid()
	}
	return out, nil
}

func (s *Module) occurrences(ctx context.Context, q v1.OccurrenceQuery) (v1.OccurrenceList, error) {
	out := v1.OccurrenceList{Occurrences: []v1.Occurrence{}}
	var cursor int64
	if q.Cursor != "" {
		n, err := strconv.ParseInt(q.Cursor, 10, 64)
		if err != nil || n < 1 || strconv.FormatInt(n, 10) != q.Cursor {
			return out, invalid()
		}
		cursor = n
	}
	if !validRange(q.Range) || q.Limit < 1 || q.Limit > 100 {
		return out, invalid()
	}
	var rows []struct {
		ID           int64
		EventID      string
		RecurrenceID string
		Start        string
		End          string
		Title        string
		Timezone     string
		AllDay       bool
		Busy         bool
		Revision     int64
	}
	err := s.db(ctx).Table("event_occurrences o").Select("o.id,o.event_id,o.recurrence_id,o.start,o.end,e.title,e.timezone,e.all_day,o.busy,e.revision").Joins("JOIN calendar_events e ON e.id=o.event_id AND e.workspace_id=o.workspace_id AND e.acl_root_id=o.acl_root_id").Where("o.workspace_id=? AND o.acl_root_id=? AND e.deleted_at IS NULL AND o.start_at<? AND o.end_at>? AND o.id>?", q.WorkspaceID, q.RootID, q.Until.UTC(), q.From.UTC(), cursor).Order("o.id").Limit(q.Limit + 1).Scan(&rows).Error
	if err != nil {
		return out, dbError(err)
	}
	if len(rows) > q.Limit {
		rows = rows[:q.Limit]
		out.NextCursor = strconv.FormatInt(rows[len(rows)-1].ID, 10)
	}
	for _, r := range rows {
		out.Occurrences = append(out.Occurrences, v1.Occurrence{Scope: q.Scope, EventID: r.EventID, RecurrenceID: r.RecurrenceID, Start: r.Start, End: r.End, Title: r.Title, Timezone: r.Timezone, AllDay: r.AllDay, Busy: r.Busy, Revision: r.Revision})
	}
	return out, nil
}
