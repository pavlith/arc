package calendar

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	ical "github.com/emersion/go-ical"
	v1 "github.com/pavlith/arc/services/calendar/api/v1"
)

const maxICalBytes = 96 << 10

// Bound recursion before calling the third-party component decoder. Nothing in
// the document is fetched or executed, including URLs, alarms and attendee data.
func decodeCalendar(raw string) (*ical.Calendar, error) {
	if len(raw) == 0 || len(raw) > maxICalBytes || !utf8.ValidString(raw) {
		return nil, invalid()
	}
	for _, r := range raw {
		if r < 32 && r != '\r' && r != '\n' && r != '\t' || r == 127 {
			return nil, invalid()
		}
	}
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	if strings.ContainsRune(normalized, '\r') {
		return nil, invalid()
	}
	var unfolded []string
	for _, line := range strings.Split(normalized, "\n") {
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if len(unfolded) == 0 {
				return nil, invalid()
			}
			unfolded[len(unfolded)-1] += line[1:]
		} else if line != "" {
			unfolded = append(unfolded, line)
		}
	}
	depth, components := 0, 0
	for _, line := range unfolded {
		header, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, invalid()
		}
		name := strings.ToUpper(strings.Split(header, ";")[0])
		if name == "BEGIN" || name == "END" {
			if strings.Contains(header, ";") || value == "" {
				return nil, invalid()
			}
			if name == "BEGIN" {
				depth++
				components++
			} else {
				depth--
			}
			if depth < 0 || depth > 4 || components > 1024 {
				return nil, invalid()
			}
		}
	}
	if depth != 0 || len(unfolded) > 8192 {
		return nil, invalid()
	}
	dec := ical.NewDecoder(strings.NewReader(strings.Join(unfolded, "\r\n") + "\r\n"))
	cal, err := dec.Decode()
	if err != nil {
		return nil, invalid()
	}
	if _, err = dec.Decode(); err != io.EOF {
		return nil, invalid()
	}
	var validTree func(*ical.Component) bool
	validTree = func(comp *ical.Component) bool {
		for _, child := range comp.Children {
			allowed := comp.Name == "VCALENDAR" && (child.Name == "VEVENT" || child.Name == "VTIMEZONE") ||
				comp.Name == "VEVENT" && child.Name == "VALARM" ||
				comp.Name == "VTIMEZONE" && (child.Name == "STANDARD" || child.Name == "DAYLIGHT")
			if !allowed || !validTree(child) {
				return false
			}
		}
		if comp.Name == "VEVENT" {
			p := comp.Props.Get("DTSTAMP")
			if p == nil || len(p.Params) != 0 {
				return false
			}
			if _, err := time.Parse("20060102T150405Z", p.Value); err != nil {
				return false
			}
			if sequence := comp.Props.Get("SEQUENCE"); sequence != nil {
				n, err := strconv.ParseInt(sequence.Value, 10, 32)
				if err != nil || n < 0 {
					return false
				}
			}
		}
		return true
	}
	if !validTree(cal.Component) {
		return nil, invalid()
	}
	if cal.Name != "VCALENDAR" || value(cal.Props, "VERSION") != "2.0" || len(cal.Props["VERSION"]) != 1 || len(cal.Props["PRODID"]) != 1 || len(cal.Props["METHOD"]) != 0 || len(cal.Props["CALSCALE"]) > 1 || value(cal.Props, "CALSCALE") != "" && value(cal.Props, "CALSCALE") != "GREGORIAN" {
		return nil, invalid()
	}
	// Check structural constraints (duplicate singleton properties, etc.) as well
	// as decoder syntax. Encoding is bounded by the already bounded input tree.
	var check bytes.Buffer
	if ical.NewEncoder(&check).Encode(cal) != nil {
		return nil, invalid()
	}
	return cal, nil
}
func value(props ical.Props, name string) string {
	if p := props.Get(name); p != nil {
		return p.Value
	}
	return ""
}
func text(props ical.Props, name string) (string, error) {
	p := props.Get(name)
	if p == nil {
		return "", nil
	}
	values, err := p.TextList()
	if err != nil || len(values) != 1 {
		return "", invalid()
	}
	return values[0], nil
}
func validUID(uid string) bool {
	if uid == "" || len(uid) > 255 || strings.TrimSpace(uid) != uid || !utf8.ValidString(uid) {
		return false
	}
	for _, r := range uid {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

// Calendar dates have an explicit value type. Floating times and custom TZIDs
// are rejected; the owner always resolves IANA zones from its embedded tzdb.
func dateProp(p *ical.Prop, zone string) (string, bool, string, error) {
	if p == nil {
		return "", false, "", invalid()
	}
	for name, values := range p.Params {
		if (name != "VALUE" && name != "TZID") || len(values) != 1 {
			return "", false, "", invalid()
		}
	}
	typ, tz := p.Params.Get("VALUE"), p.Params.Get("TZID")
	if typ == "DATE" {
		if tz != "" {
			return "", false, "", invalid()
		}
		t, err := time.Parse("20060102", p.Value)
		if err != nil {
			return "", false, "", invalid()
		}
		return t.Format(time.DateOnly), true, zone, nil
	}
	if typ != "" && typ != "DATE-TIME" {
		return "", false, "", invalid()
	}
	if strings.HasSuffix(p.Value, "Z") {
		if tz != "" {
			return "", false, "", invalid()
		}
		t, err := time.Parse("20060102T150405Z", p.Value)
		if err != nil {
			return "", false, "", invalid()
		}
		return t.Format(time.RFC3339), false, "UTC", nil
	}
	if tz == "" {
		return "", false, "", invalid()
	}
	loc, err := location(tz)
	if err != nil {
		return "", false, "", err
	}
	w, err := time.Parse("20060102T150405", p.Value)
	if err != nil {
		return "", false, "", invalid()
	}
	t, ok := resolveWall(w, loc)
	if !ok {
		return "", false, "", invalid()
	}
	return t.UTC().Format(time.RFC3339), false, tz, nil
}
func eventInput(comp *ical.Component, defaultZone string) (v1.Input, error) {
	if comp.Name != "VEVENT" || len(comp.Props["DTSTART"]) != 1 || len(comp.Props["DTEND"]) != 1 {
		return v1.Input{}, invalid()
	}
	for _, field := range []string{"DURATION", "RDATE", "EXRULE"} {
		if len(comp.Props[field]) != 0 {
			return v1.Input{}, invalid()
		}
	}
	if status := value(comp.Props, "STATUS"); status != "" && status != "CONFIRMED" && status != "TENTATIVE" {
		return v1.Input{}, invalid()
	}
	title, err := text(comp.Props, "SUMMARY")
	if err != nil {
		return v1.Input{}, err
	}
	description, err := text(comp.Props, "DESCRIPTION")
	if err != nil {
		return v1.Input{}, err
	}
	start, day, zone, err := dateProp(comp.Props.Get("DTSTART"), defaultZone)
	if err != nil {
		return v1.Input{}, err
	}
	end, endDay, endZone, err := dateProp(comp.Props.Get("DTEND"), zone)
	if err != nil || day != endDay || day && zone != endZone {
		return v1.Input{}, invalid()
	}
	busy := true
	switch value(comp.Props, "TRANSP") {
	case "", "OPAQUE":
	case "TRANSPARENT":
		busy = false
	default:
		return v1.Input{}, invalid()
	}
	return v1.Input{Title: title, Description: description, Start: start, End: end, AllDay: day, Timezone: zone, Busy: busy, RRule: value(comp.Props, "RRULE")}, nil
}
func parseICal(ctx context.Context, raw string) (string, v1.Input, error) {
	cal, err := decodeCalendar(raw)
	if err != nil {
		return "", v1.Input{}, err
	}
	var master *ical.Component
	var detached, zones []*ical.Component
	for _, comp := range cal.Children {
		switch comp.Name {
		case "VTIMEZONE":
			zones = append(zones, comp)
		case "VEVENT":
			if len(comp.Props["RECURRENCE-ID"]) > 1 {
				return "", v1.Input{}, invalid()
			}
			if comp.Props.Get("RECURRENCE-ID") == nil {
				if master != nil {
					return "", v1.Input{}, invalid()
				}
				master = comp
			} else {
				detached = append(detached, comp)
			}
		default:
			return "", v1.Input{}, invalid()
		}
	}
	if master == nil || len(detached) > 128 {
		return "", v1.Input{}, invalid()
	}
	uid, err := text(master.Props, "UID")
	if err != nil || !validUID(uid) {
		return "", v1.Input{}, invalid()
	}
	defaultZone := "UTC"
	// DATE values have no TZID; our extension retains the owner's all-day zone.
	if name, err := text(master.Props, "X-ARC-TIMEZONE"); err != nil {
		return "", v1.Input{}, err
	} else if name != "" {
		if _, err := location(name); err != nil {
			return "", v1.Input{}, err
		}
		defaultZone = name
	}
	in, err := eventInput(master, defaultZone)
	if err != nil {
		return "", in, err
	}
	if !in.AllDay && defaultZone != "UTC" && defaultZone != in.Timezone {
		return "", in, invalid()
	}
	for _, prop := range master.Props["EXDATE"] {
		for _, part := range strings.Split(prop.Value, ",") {
			p := prop
			p.Value = part
			key, day, _, err := dateProp(&p, in.Timezone)
			if err != nil || day != in.AllDay {
				return "", in, invalid()
			}
			in.Exceptions = append(in.Exceptions, v1.Exception{RecurrenceID: key, Cancelled: true})
		}
	}
	for _, comp := range detached {
		otherUID, err := text(comp.Props, "UID")
		if err != nil || otherUID != uid {
			return "", in, invalid()
		}
		for _, field := range []string{"RRULE", "RDATE", "EXDATE", "EXRULE", "DURATION"} {
			if len(comp.Props[field]) != 0 {
				return "", in, invalid()
			}
		}
		key, day, _, err := dateProp(comp.Props.Get("RECURRENCE-ID"), in.Timezone)
		if err != nil || day != in.AllDay {
			return "", in, invalid()
		}
		x := v1.Exception{RecurrenceID: key, Cancelled: value(comp.Props, "STATUS") == "CANCELLED"}
		if x.Cancelled {
			if comp.Props.Get("DTSTART") != nil || comp.Props.Get("DTEND") != nil {
				return "", in, invalid()
			}
		} else {
			copy := ical.NewComponent("VEVENT")
			copy.Props = cloneProps(comp.Props)
			if copy.Props.Get("SUMMARY") == nil {
				copy.Props.SetText("SUMMARY", in.Title)
			}
			if copy.Props.Get("DESCRIPTION") == nil {
				copy.Props.SetText("DESCRIPTION", in.Description)
			}
			if copy.Props.Get("TRANSP") == nil {
				setRaw(copy.Props, "TRANSP", map[bool]string{true: "OPAQUE", false: "TRANSPARENT"}[in.Busy])
			}
			replacement, err := eventInput(copy, in.Timezone)
			if err != nil || replacement.AllDay != in.AllDay || replacement.Title != in.Title || replacement.Description != in.Description || replacement.Busy != in.Busy {
				return "", in, invalid()
			}
			x.Start, x.End = replacement.Start, replacement.End
		}
		in.Exceptions = append(in.Exceptions, x)
	}
	in, _, err = plan(ctx, in)
	if err != nil {
		return "", in, err
	}
	// Only our canonical IANA transition form is accepted when a VTIMEZONE is
	// supplied. Arbitrary client timezone programs are never executed or ignored.
	if len(zones) > 1 {
		return "", in, invalid()
	}
	for _, zone := range zones {
		if value(zone.Props, "TZID") != in.Timezone {
			return "", in, invalid()
		}
		expected, err := timezoneComponent(in.Timezone)
		if err != nil || expected == nil {
			return "", in, invalid()
		}
		a, _ := json.Marshal(zone)
		b, _ := json.Marshal(expected)
		if !bytes.Equal(a, b) {
			return "", in, invalid()
		}
	}
	return uid, in, nil
}
func cloneProps(props ical.Props) ical.Props {
	out := ical.Props{}
	for key, values := range props {
		out[key] = append([]ical.Prop(nil), values...)
	}
	return out
}
func setRaw(props ical.Props, name, value string) {
	p := ical.NewProp(name)
	p.Value = value
	props.Set(p)
}
func timeProp(props ical.Props, name, value string, in v1.Input) error {
	p := ical.NewProp(name)
	if in.AllDay {
		date, err := time.Parse(time.DateOnly, value)
		if err != nil {
			return invalid()
		}
		p.Params.Set("VALUE", "DATE")
		p.Value = date.Format("20060102")
	} else {
		instant, err := time.Parse(time.RFC3339Nano, value)
		if err != nil || instant.Nanosecond() != 0 {
			return invalid()
		}
		if in.Timezone == "UTC" {
			p.Value = instant.UTC().Format("20060102T150405Z")
		} else {
			loc, err := location(in.Timezone)
			if err != nil {
				return err
			}
			local := instant.In(loc)
			// iCalendar's local form selects the first fold instant. Do not silently
			// export a second-fold native timestamp as a different instant.
			first, ok := resolveWall(wall(local), loc)
			if !ok || !first.Equal(instant) {
				return invalid()
			}
			p.Params.Set("TZID", in.Timezone)
			p.Value = local.Format("20060102T150405")
		}
	}
	props.Set(p)
	return nil
}

// timezoneComponent emits explicit IANA transitions for the entire supported
// horizon. No external TZURL, RRULE or arbitrary timezone definition is evaluated.
func timezoneComponent(name string) (*ical.Component, error) {
	if name == "UTC" {
		return nil, nil
	}
	loc, err := location(name)
	if err != nil {
		return nil, err
	}
	zone := ical.NewComponent("VTIMEZONE")
	zone.Props.SetText("TZID", name)
	begin := time.Date(1899, 1, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2102, 1, 1, 0, 0, 0, 0, time.UTC)
	current := begin
	for count := 0; current.Before(until); count++ {
		if count > 512 {
			return nil, invalid()
		}
		_, offset := current.In(loc).Zone()
		_, end := current.In(loc).ZoneBounds()
		before := offset
		if current.After(begin) {
			_, before = current.Add(-time.Second).In(loc).Zone()
		}
		kind := "STANDARD"
		if current.In(loc).IsDST() {
			kind = "DAYLIGHT"
		}
		comp := ical.NewComponent(kind)
		local := current.Add(time.Duration(before) * time.Second)
		setRaw(comp.Props, "DTSTART", local.Format("20060102T150405"))
		setRaw(comp.Props, "TZOFFSETFROM", utcOffset(before))
		setRaw(comp.Props, "TZOFFSETTO", utcOffset(offset))
		zone.Children = append(zone.Children, comp)
		if end.IsZero() || !end.After(current) {
			break
		}
		current = end
	}
	return zone, nil
}
func utcOffset(seconds int) string {
	sign := "+"
	if seconds < 0 {
		sign = "-"
		seconds = -seconds
	}
	if seconds%60 != 0 {
		return fmt.Sprintf("%s%02d%02d%02d", sign, seconds/3600, seconds/60%60, seconds%60)
	}
	return fmt.Sprintf("%s%02d%02d", sign, seconds/3600, seconds/60%60)
}

var managedProps = []string{"UID", "DTSTAMP", "LAST-MODIFIED", "SEQUENCE", "SUMMARY", "DESCRIPTION", "DTSTART", "DTEND", "RRULE", "EXDATE", "RECURRENCE-ID", "STATUS", "TRANSP", "X-ARC-TIMEZONE"}

func renderICal(in v1.Input, uid string, revision int64, stamp time.Time, template string) (string, error) {
	if !validUID(uid) {
		return "", invalid()
	}
	cal := ical.NewCalendar()
	cal.Props.SetText("PRODID", "-//Arc//Calendar 0.3//EN")
	setRaw(cal.Props, "VERSION", "2.0")
	master := ical.NewComponent("VEVENT")
	oldExceptions := map[string]*ical.Component{}
	if template != "" {
		previous, err := decodeCalendar(template)
		if err != nil {
			return "", err
		}
		cal.Props = cloneProps(previous.Props)
		for _, comp := range previous.Children {
			if comp.Name == "VEVENT" {
				if comp.Props.Get("RECURRENCE-ID") == nil {
					master.Props = cloneProps(comp.Props)
					master.Children = comp.Children
				} else {
					key, _, _, err := dateProp(comp.Props.Get("RECURRENCE-ID"), in.Timezone)
					if err != nil {
						return "", err
					}
					oldExceptions[key] = comp
				}
			}
		}
	}
	fill := func(comp *ical.Component) {
		status := value(comp.Props, "STATUS")
		for _, name := range managedProps {
			comp.Props.Del(name)
		}
		if status == "CONFIRMED" || status == "TENTATIVE" {
			setRaw(comp.Props, "STATUS", status)
		}
		comp.Props.SetText("UID", uid)
		setRaw(comp.Props, "DTSTAMP", stamp.UTC().Format("20060102T150405Z"))
		setRaw(comp.Props, "LAST-MODIFIED", stamp.UTC().Format("20060102T150405Z"))
		setRaw(comp.Props, "SEQUENCE", strconv.FormatInt(revision-1, 10))
	}
	fill(master)
	master.Props.SetText("SUMMARY", in.Title)
	master.Props.SetText("DESCRIPTION", in.Description)
	master.Props.SetText("X-ARC-TIMEZONE", in.Timezone)
	setRaw(master.Props, "TRANSP", map[bool]string{true: "OPAQUE", false: "TRANSPARENT"}[in.Busy])
	if err := timeProp(master.Props, "DTSTART", in.Start, in); err != nil {
		return "", err
	}
	if err := timeProp(master.Props, "DTEND", in.End, in); err != nil {
		return "", err
	}
	if in.RRule != "" {
		setRaw(master.Props, "RRULE", in.RRule)
	}
	cal.Children = append(cal.Children, master)
	exceptions := append([]v1.Exception(nil), in.Exceptions...)
	sort.Slice(exceptions, func(i, j int) bool { return exceptions[i].RecurrenceID < exceptions[j].RecurrenceID })
	for _, x := range exceptions {
		comp := ical.NewComponent("VEVENT")
		if old := oldExceptions[x.RecurrenceID]; old != nil {
			comp.Props = cloneProps(old.Props)
			comp.Children = old.Children
		}
		fill(comp)
		if err := timeProp(comp.Props, "RECURRENCE-ID", x.RecurrenceID, in); err != nil {
			return "", err
		}
		if x.Cancelled {
			setRaw(comp.Props, "STATUS", "CANCELLED")
		} else {
			comp.Props.SetText("SUMMARY", in.Title)
			comp.Props.SetText("DESCRIPTION", in.Description)
			setRaw(comp.Props, "TRANSP", map[bool]string{true: "OPAQUE", false: "TRANSPARENT"}[in.Busy])
			if err := timeProp(comp.Props, "DTSTART", x.Start, in); err != nil {
				return "", err
			}
			if err := timeProp(comp.Props, "DTEND", x.End, in); err != nil {
				return "", err
			}
		}
		cal.Children = append(cal.Children, comp)
	}
	if !in.AllDay {
		zone, err := timezoneComponent(in.Timezone)
		if err != nil {
			return "", err
		}
		if zone != nil {
			cal.Children = append(cal.Children, zone)
		}
	}
	var buffer bytes.Buffer
	if ical.NewEncoder(&buffer).Encode(cal) != nil {
		return "", invalid()
	}
	// RFC5545 folding counts octets and never splits a UTF-8 code point.
	var folded strings.Builder
	for _, line := range strings.Split(strings.TrimSuffix(buffer.String(), "\r\n"), "\r\n") {
		for len(line) > 75 {
			cut := 75
			for !utf8.RuneStart(line[cut]) {
				cut--
			}
			folded.WriteString(line[:cut])
			folded.WriteString("\r\n ")
			line = line[cut:]
			// Continuation whitespace counts toward the following 75-octet line.
			for len(line) > 74 {
				cut = 74
				for !utf8.RuneStart(line[cut]) {
					cut--
				}
				folded.WriteString(line[:cut])
				folded.WriteString("\r\n ")
				line = line[cut:]
			}
		}
		folded.WriteString(line)
		folded.WriteString("\r\n")
	}
	result := folded.String()
	encoded, _ := json.Marshal(result)
	if len(result) > maxICalBytes || len(encoded) > 180<<10 {
		return "", invalid()
	}
	return result, nil
}
