package contacts

import (
	"context"
	"encoding/json"
	"net/mail"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/contacts/api/v1"
	"github.com/pavlith/arc/services/contacts/models"
	"gorm.io/gorm"
)

// text bounds Unicode characters and excludes controls from single-line fields.
func text(s string, max int, multiline bool) (string, error) {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return "", invalid()
	}
	for _, r := range s {
		if unicode.IsControl(r) && !(multiline && (r == '\n' || r == '\t')) {
			return "", invalid()
		}
	}
	return strings.TrimSpace(s), nil
}
func validate(in v1.Input) (v1.Input, string, error) {
	out := in
	for _, f := range []struct {
		p     *string
		max   int
		multi bool
	}{
		{&out.DisplayName, 256, false}, {&out.GivenName, 128, false}, {&out.FamilyName, 128, false}, {&out.AdditionalName, 128, false}, {&out.Prefix, 128, false}, {&out.Suffix, 128, false}, {&out.Organization, 256, false}, {&out.Role, 128, false}, {&out.Notes, 8192, true},
	} {
		val, err := text(*f.p, f.max, f.multi)
		if err != nil {
			return out, "", err
		}
		*f.p = val
	}
	if out.DisplayName == "" || len(in.Phones) > 32 || len(in.Emails) > 32 || len(in.Addresses) > 16 || len(in.CustomFields) > 32 {
		return out, "", invalid()
	}
	out.Phones = append([]v1.LabelledValue(nil), in.Phones...)
	out.Emails = append([]v1.LabelledValue(nil), in.Emails...)
	for _, set := range []struct {
		items []v1.LabelledValue
		max   int
		email bool
	}{{out.Phones, 128, false}, {out.Emails, 254, true}} {
		for i := range set.items {
			item := &set.items[i]
			var err error
			item.Label, err = text(item.Label, 32, false)
			if err != nil {
				return out, "", err
			}
			item.Value, err = text(item.Value, set.max, false)
			if err != nil || item.Value == "" {
				return out, "", invalid()
			}
			if set.email {
				a, err := mail.ParseAddress(item.Value)
				if err != nil || a.Address != item.Value || a.Name != "" {
					return out, "", invalid()
				}
			}
		}
	}
	out.Addresses = append([]v1.Address(nil), in.Addresses...)
	for i := range out.Addresses {
		a := &out.Addresses[i]
		for _, f := range []struct {
			p     *string
			max   int
			multi bool
		}{{&a.Label, 32, false}, {&a.Street, 512, true}, {&a.Locality, 128, false}, {&a.Region, 128, false}, {&a.PostalCode, 128, false}, {&a.Country, 128, false}} {
			val, err := text(*f.p, f.max, f.multi)
			if err != nil {
				return out, "", err
			}
			*f.p = val
		}
		if a.Street == "" && a.Locality == "" && a.Region == "" && a.PostalCode == "" && a.Country == "" {
			return out, "", invalid()
		}
	}
	out.CustomFields = nil
	if len(in.CustomFields) > 0 {
		out.CustomFields = make(map[string]string, len(in.CustomFields))
	}
	for k, v := range in.CustomFields {
		key, err := text(k, 64, false)
		if err != nil || key == "" {
			return out, "", invalid()
		}
		val, err := text(v, 512, false)
		if err != nil {
			return out, "", err
		}
		if _, exists := out.CustomFields[key]; exists {
			return out, "", invalid()
		}
		out.CustomFields[key] = val
	}
	data, err := json.Marshal(out)
	if err != nil || len(data) > 48*1024 {
		return out, "", invalid()
	}
	return out, string(data), nil
}
func searchText(in v1.Input) string {
	parts := []string{in.DisplayName, in.GivenName, in.FamilyName, in.AdditionalName, in.Prefix, in.Suffix, in.Organization, in.Role, in.Notes}
	for _, set := range [][]v1.LabelledValue{in.Phones, in.Emails} {
		for _, v := range set {
			parts = append(parts, v.Label, v.Value)
		}
	}
	for _, v := range in.Addresses {
		parts = append(parts, v.Label, v.Street, v.Locality, v.Region, v.PostalCode, v.Country)
	}
	keys := make([]string, 0, len(in.CustomFields))
	for k := range in.CustomFields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, in.CustomFields[k])
	}
	return strings.ToLower(strings.Join(parts, "\n"))
}
func dto(r models.Contact) (v1.Contact, error) {
	var in v1.Input
	if json.Unmarshal([]byte(r.Fields), &in) != nil {
		return v1.Contact{}, security.ErrUnavailable
	}
	return v1.Contact{Scope: v1.Scope{WorkspaceID: r.WorkspaceID, RootID: r.RootID}, ID: r.ID, UID: r.UID, Input: in, Revision: r.Revision, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}, nil
}
func (s *Module) row(ctx context.Context, db *gorm.DB, q v1.ContactRef) (models.Contact, error) {
	var row models.Contact
	err := db.WithContext(ctx).Where("id=? AND workspace_id=? AND acl_root_id=? AND deleted_at IS NULL", q.ContactID, q.WorkspaceID, q.RootID).Take(&row).Error
	return row, dbError(err)
}
func (s *Module) create(ctx context.Context, tx *gorm.DB, q v1.Create) (v1.Contact, error) {
	id := newID()
	return s.createStored(ctx, tx, q, id, id+"@arc", "")
}
func (s *Module) createStored(ctx context.Context, tx *gorm.DB, q v1.Create, id, uid, raw string) (v1.Contact, error) {
	in, fields, err := validate(q.Input)
	if err != nil {
		return v1.Contact{}, err
	}
	// Bound local collection scans, including tombstones retained for future DAV.
	var count int64
	if err := tx.Model(&models.Contact{}).Where("workspace_id=? AND acl_root_id=?", q.WorkspaceID, q.RootID).Count(&count).Error; err != nil {
		return v1.Contact{}, dbError(err)
	}
	if count >= 10000 {
		return v1.Contact{}, invalid()
	}
	now := time.Now().UTC()
	row := models.Contact{ID: id, UID: uid, WorkspaceID: q.WorkspaceID, RootID: q.RootID, DisplayName: in.DisplayName, Organization: in.Organization, Role: in.Role, Fields: fields, SearchText: searchText(in), Revision: 1, CreatedAt: now, UpdatedAt: now}
	if raw == "" {
		raw, err = renderVCard(in, uid, "")
		if err != nil {
			return v1.Contact{}, err
		}
	}
	row.VCardRaw = raw

	if err := tx.Create(&row).Error; err != nil {
		return v1.Contact{}, dbError(err)
	}
	if err := s.changed(ctx, tx, q.Scope, id, 1, "created"); err != nil {
		return v1.Contact{}, err
	}
	return dto(row)
}
func (s *Module) get(ctx context.Context, q v1.ContactRef) (v1.Contact, error) {
	row, err := s.row(ctx, s.db(ctx), q)
	if err != nil {
		return v1.Contact{}, err
	}
	return dto(row)
}
func (s *Module) update(ctx context.Context, tx *gorm.DB, q v1.Update) (v1.Contact, error) {
	return s.updateStored(ctx, tx, q, nil)
}
func (s *Module) updateStored(ctx context.Context, tx *gorm.DB, q v1.Update, raw *string) (v1.Contact, error) {
	row, err := s.row(ctx, tx, q.ContactRef)
	if err != nil {
		return v1.Contact{}, err
	}
	if q.Revision < 1 || q.Revision != row.Revision {
		return v1.Contact{}, conflict()
	}
	in, fields, err := validate(q.Input)
	if err != nil {
		return v1.Contact{}, err
	}
	nextRaw := ""
	if raw != nil {
		nextRaw = *raw
	} else {
		nextRaw, err = renderVCard(in, row.UID, row.VCardRaw)
		if err != nil {
			return v1.Contact{}, err
		}
	}

	now := time.Now().UTC()
	if !now.After(row.UpdatedAt) {
		now = row.UpdatedAt.Add(time.Nanosecond)
	}
	res := tx.Model(&models.Contact{}).Where("id=? AND workspace_id=? AND acl_root_id=? AND revision=? AND deleted_at IS NULL", row.ID, q.WorkspaceID, q.RootID, q.Revision).Updates(map[string]any{"v_card_raw": nextRaw, "display_name": in.DisplayName, "organization": in.Organization, "role": in.Role, "fields": fields, "search_text": searchText(in), "revision": q.Revision + 1, "updated_at": now})
	if res.Error != nil {
		return v1.Contact{}, dbError(res.Error)
	}
	if res.RowsAffected != 1 {
		return v1.Contact{}, conflict()
	}
	row.DisplayName = in.DisplayName
	row.Organization = in.Organization
	row.Role = in.Role
	row.VCardRaw = nextRaw
	row.Fields = fields
	row.Revision++
	row.UpdatedAt = now
	if err := s.changed(ctx, tx, q.Scope, row.ID, row.Revision, "updated"); err != nil {
		return v1.Contact{}, err
	}
	return dto(row)
}
func (s *Module) delete(ctx context.Context, tx *gorm.DB, q v1.Delete) (v1.Mutation, error) {
	row, err := s.row(ctx, tx, q.ContactRef)
	if err != nil {
		return v1.Mutation{}, err
	}
	if q.Revision < 1 || q.Revision != row.Revision {
		return v1.Mutation{}, conflict()
	}
	now := time.Now().UTC()
	if !now.After(row.UpdatedAt) {
		now = row.UpdatedAt.Add(time.Nanosecond)
	}
	res := tx.Model(&models.Contact{}).Where("id=? AND workspace_id=? AND acl_root_id=? AND revision=? AND deleted_at IS NULL", row.ID, q.WorkspaceID, q.RootID, q.Revision).Updates(map[string]any{"deleted_at": now, "updated_at": now, "revision": q.Revision + 1})
	if res.Error != nil {
		return v1.Mutation{}, dbError(res.Error)
	}
	if res.RowsAffected != 1 {
		return v1.Mutation{}, conflict()
	}
	return v1.Mutation{ID: row.ID, Revision: q.Revision + 1, Deleted: true}, s.changed(ctx, tx, q.Scope, row.ID, q.Revision+1, "deleted")
}
func (s *Module) list(ctx context.Context, q v1.List) (v1.ContactList, error) {
	out := v1.ContactList{Contacts: []v1.Summary{}}
	query, err := text(q.Query, 256, false)
	if err != nil || q.Limit < 1 || q.Limit > 100 || q.Cursor != "" && !idPattern.MatchString(q.Cursor) {
		return out, invalid()
	}
	var rows []models.Contact
	db := s.db(ctx).Select("id", "uid", "display_name", "organization", "role", "revision", "updated_at").Where("workspace_id=? AND acl_root_id=? AND deleted_at IS NULL AND id>?", q.WorkspaceID, q.RootID, q.Cursor)
	if query != "" {
		db = db.Where("instr(search_text,?)>0", strings.ToLower(query))
	}
	if err := db.Order("id").Limit(q.Limit + 1).Find(&rows).Error; err != nil {
		return out, dbError(err)
	}
	for i, r := range rows {
		if i == q.Limit {
			out.NextCursor = out.Contacts[len(out.Contacts)-1].ID
			break
		}
		item := v1.Summary{Scope: q.Scope, ID: r.ID, UID: r.UID, DisplayName: r.DisplayName, Organization: r.Organization, Role: r.Role, Revision: r.Revision, UpdatedAt: r.UpdatedAt}
		out.Contacts = append(out.Contacts, item)
		// Reserve a cursor even for the final candidate when measuring wire size.
		probe := out
		probe.NextCursor = r.ID
		data, err := json.Marshal(probe)
		if err != nil {
			return out, security.ErrUnavailable
		}
		if len(data) > 200*1024 {
			out.Contacts = out.Contacts[:len(out.Contacts)-1]
			if len(out.Contacts) == 0 {
				return out, security.ErrUnavailable
			}
			out.NextCursor = out.Contacts[len(out.Contacts)-1].ID
			break
		}
	}
	return out, nil
}
