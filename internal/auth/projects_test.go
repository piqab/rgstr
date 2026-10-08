package auth

import (
	"net/http"
	"testing"

	"rgstr/internal/meta"
)

// projectHandler: users alice (env admin), bob, carol, dave (env users,
// RGSTR_ADMINS=alice so bob/carol/dave have role "user"); project "team"
// with bob=developer, carol=guest; public project "pub".
func projectHandler(t *testing.T) *Handler {
	t.Helper()
	cfg := bootstrapCfg(t)
	hash := cfg.Users["alice"]
	cfg.Users["bob"], cfg.Users["carol"], cfg.Users["dave"] = hash, hash, hash
	h := handlerFor(cfg)
	m, _ := meta.Open("")
	m.Update(func(d *meta.Data) error {
		d.Projects = map[string]meta.Project{
			"team": {Name: "team", Members: map[string]string{"bob": meta.ProjectDeveloper, "carol": meta.ProjectGuest}},
			"pub":  {Name: "pub", Public: true},
		}
		return nil
	})
	h.SetMeta(m)
	return h
}

func TestProjectPermissions(t *testing.T) {
	h := projectHandler(t)
	cases := []struct {
		user, repo, action string
		want               bool
	}{
		{"bob", "team/app", "push", true},
		{"bob", "team/app", "delete", false},
		{"carol", "team/app", "pull", true},
		{"carol", "team/app", "push", false},
		{"dave", "team/app", "pull", false}, // not a member
		{"alice", "team/app", "delete", true},
		{"", "team/app", "pull", false},
		{"", "pub/app", "pull", true}, // public project
		{"", "pub/app", "push", false},
		{"dave", "other/app", "push", true}, // no project "other": global role
		{"dave", "single", "push", true},
		{"admin", "team/app", "pull", true}, // bootstrap admin
	}
	for _, c := range cases {
		if got := h.Can(c.user, c.repo, c.action); got != c.want {
			t.Errorf("Can(%q, %q, %q) = %v, want %v", c.user, c.repo, c.action, got, c.want)
		}
	}
	if !h.IsProjectAdmin("alice", "team") || h.IsProjectAdmin("bob", "team") {
		t.Error("IsProjectAdmin")
	}
}

func TestProjectTokenGrant(t *testing.T) {
	h := projectHandler(t)
	// dave asks for team/app — he is no member, so nothing is granted.
	tok := token(t, h, "dave", "repository:team/app:pull,push")
	if code := serve(t, h, http.MethodGet, "/v2/team/app/manifests/1", tok); code != http.StatusUnauthorized {
		t.Errorf("non-member pull: got %d want 401", code)
	}
	tok = token(t, h, "bob", "repository:team/app:pull,push,delete")
	if code := serve(t, h, http.MethodPut, "/v2/team/app/manifests/1", tok); code != http.StatusOK {
		t.Errorf("developer push: got %d want 200", code)
	}
	if code := serve(t, h, http.MethodDelete, "/v2/team/app/manifests/1", tok); code != http.StatusUnauthorized {
		t.Errorf("developer delete: got %d want 401", code)
	}
	// Anonymous pull from the public project.
	if code := serve(t, h, http.MethodGet, "/v2/pub/app/manifests/1", nil); code != http.StatusOK {
		t.Errorf("anonymous public pull: got %d want 200", code)
	}
}
