package identity

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/contract"
)

type WorkflowSortOverride struct {
	Mode  string   `json:"mode"`
	Order []string `json:"workflow_sort_order,omitempty"`
}
type PreferencesData struct {
	FontSize          string                          `json:"font_size"`
	PointerCursors    bool                            `json:"pointer_cursors"`
	ThemeMode         string                          `json:"theme_mode"`
	LightTheme        string                          `json:"light_theme"`
	DarkTheme         string                          `json:"dark_theme"`
	WorkflowSortMode  string                          `json:"workflow_sort_mode"`
	WorkflowSortOrder []string                        `json:"workflow_sort_order"`
	TeamOverrides     map[string]WorkflowSortOverride `json:"team_workflow_sort_overrides"`
	RecentDueDates    []string                        `json:"recent_due_dates"`
	IssuesGroupBy     string                          `json:"issues_group_by"`
}
type AccountPreferences struct {
	PreferencesData
	Revision int64 `json:"revision"`
}
type PreferencesUpdate struct {
	Revision int64                      `json:"revision"`
	Changes  map[string]json.RawMessage `json:"changes"`
}

func defaultPreferences() AccountPreferences {
	return AccountPreferences{PreferencesData: PreferencesData{FontSize: "default", PointerCursors: true, ThemeMode: "system", LightTheme: "light", DarkTheme: "dark", WorkflowSortMode: "default", WorkflowSortOrder: []string{"backlog", "unstarted", "started", "completed", "cancelled"}, TeamOverrides: map[string]WorkflowSortOverride{}, RecentDueDates: []string{}, IssuesGroupBy: "status"}}
}
func preferenceChoice(value string, options ...string) bool {
	for _, option := range options {
		if value == option {
			return true
		}
	}
	return false
}
func validWorkflowOrder(order []string) bool {
	if len(order) != 5 {
		return false
	}
	seen := map[string]bool{}
	for _, v := range order {
		if !preferenceChoice(v, "backlog", "unstarted", "started", "completed", "cancelled") || seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}
func validPreferences(q PreferencesData) bool {
	if !preferenceChoice(q.FontSize, "small", "default", "large") || !preferenceChoice(q.ThemeMode, "system", "light", "dark") || !preferenceChoice(q.LightTheme, "light", "rose-light", "blue-light") || !preferenceChoice(q.DarkTheme, "dark", "dark-gray", "amethyst-dark", "emerald-dark", "cyber-77", "blade-49", "pipboy") || !preferenceChoice(q.WorkflowSortMode, "default", "active-first", "custom") || !preferenceChoice(q.IssuesGroupBy, "status", "priority", "assignee", "project", "none") || !validWorkflowOrder(q.WorkflowSortOrder) || len(q.TeamOverrides) > 100 || len(q.RecentDueDates) > 20 || q.TeamOverrides == nil || q.RecentDueDates == nil {
		return false
	}
	for id, v := range q.TeamOverrides {
		if !productID.MatchString(id) || !preferenceChoice(v.Mode, "default", "active-first", "custom", "inherit") || (len(v.Order) > 0 || v.Mode == "custom") && !validWorkflowOrder(v.Order) {
			return false
		}
	}
	for _, v := range q.RecentDueDates {
		if _, err := time.Parse("2006-01-02", v); err != nil {
			return false
		}
	}
	return true
}
func (c *Core) preferences(ctx context.Context, user string, _ Empty) (AccountPreferences, error) {
	out := defaultPreferences()
	var raw string
	err := c.db(ctx).WithContext(ctx).Raw(`SELECT data,revision FROM identity_user_preferences WHERE user_id=?`, user).Row().Scan(&raw, &out.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return AccountPreferences{}, ErrUnavailable
	}
	if contract.Strict([]byte(raw), &out.PreferencesData) != nil || !validPreferences(out.PreferencesData) {
		return AccountPreferences{}, ErrUnavailable
	}
	return out, nil
}
func (c *Core) bindPreferences(s *sdk.Service) error {
	if err := bindProductRead(s, c, "account.preferences.get", c.preferences); err != nil {
		return err
	}
	return bindOperation(s, c, "product.account.preferences.update", true, func(ctx context.Context, req ProductRequest[PreferencesUpdate]) (AccountPreferences, error) {
		user, err := c.user(ctx, req.Session)
		if err != nil {
			return AccountPreferences{}, err
		}
		if req.Input.Revision < 0 || len(req.Input.Changes) == 0 || len(req.Input.Changes) > 11 {
			return AccountPreferences{}, productInvalid()
		}
		return runCommand(ctx, c, user, "identity.v1.product.account.preferences.update", nil, func(ctx context.Context) (AccountPreferences, error) {
			out, err := c.preferences(ctx, user.UserID, Empty{})
			if err != nil {
				return out, err
			}
			if out.Revision != req.Input.Revision {
				return AccountPreferences{}, ErrConflict
			}
			raw, _ := json.Marshal(out.PreferencesData)
			var data map[string]json.RawMessage
			if json.Unmarshal(raw, &data) != nil {
				return AccountPreferences{}, ErrUnavailable
			}
			for key, value := range req.Input.Changes {
				if _, ok := data[key]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
					return AccountPreferences{}, productInvalid()
				}
				data[key] = value
			}
			raw, err = json.Marshal(data)
			if err != nil || len(raw) > 32768 || contract.Strict(raw, &out.PreferencesData) != nil || !validPreferences(out.PreferencesData) {
				return AccountPreferences{}, productInvalid()
			}
			out.Revision++
			db := c.db(ctx).WithContext(ctx)
			if err := db.Exec(`INSERT INTO identity_user_preferences(user_id,data,revision,updated_at) VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET data=excluded.data,revision=excluded.revision,updated_at=excluded.updated_at`, user.UserID, string(raw), out.Revision, c.now()).Error; err != nil {
				return AccountPreferences{}, ErrUnavailable
			}
			return out, audit(ctx, db, "user:"+user.UserID, "users.preferences", user.UserID, "ok")
		})
	})
}
