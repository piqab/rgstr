package auth

import (
	"net/http"
	"testing"
	"time"

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

func addRobot(h *Handler, r meta.Robot, secret string) {
	r.SecretHash = HashSecret(secret)
	h.meta.Update(func(d *meta.Data) error {
		if d.Robots == nil {
			d.Robots = map[string]meta.Robot{}
		}
		d.Robots[r.Name] = r
		return nil
	})
}

func TestRobots(t *testing.T) {
	h := projectHandler(t)
	past := time.Now().Add(-time.Hour)
	addRobot(h, meta.Robot{Name: "robot$ci", Permissions: []meta.RobotPermission{{Project: "team", Actions: []string{"pull", "push"}}}}, "s3cret")
	addRobot(h, meta.Robot{Name: "robot$all", Permissions: []meta.RobotPermission{{Project: "*", Actions: []string{"pull"}}}}, "s3cret")
	addRobot(h, meta.Robot{Name: "robot$old", ExpiresAt: &past, Permissions: []meta.RobotPermission{{Project: "*", Actions: []string{"pull"}}}}, "s3cret")
	addRobot(h, meta.Robot{Name: "robot$off", Disabled: true, Permissions: []meta.RobotPermission{{Project: "*", Actions: []string{"pull"}}}}, "s3cret")

	cases := []struct {
		user, repo, action string
		want               bool
	}{
		{"robot$ci", "team/app", "push", true},
		{"robot$ci", "team/app", "delete", false},
		{"robot$ci", "other/app", "pull", false},
		{"robot$ci", "single", "pull", false}, // no project: only "*" applies
		{"robot$all", "single", "pull", true},
		{"robot$all", "team/app", "push", false},
		{"robot$old", "single", "pull", false},
		{"robot$off", "single", "pull", false},
		{"robot$none", "single", "pull", false},
	}
	for _, c := range cases {
		if got := h.Can(c.user, c.repo, c.action); got != c.want {
			t.Errorf("Can(%q, %q, %q) = %v, want %v", c.user, c.repo, c.action, got, c.want)
		}
	}
	if h.IsAdmin("robot$all") {
		t.Error("robot is admin")
	}

	// docker flow: Basic and token with the secret.
	basicCI := basicAuthPw("robot$ci", "s3cret")
	if code := serve(t, h, http.MethodPut, "/v2/team/app/manifests/1", basicCI); code != http.StatusOK {
		t.Errorf("robot push with Basic: got %d", code)
	}
	if code := serve(t, h, http.MethodGet, "/v2/team/app/manifests/1", basicAuthPw("robot$ci", "wrong")); code != http.StatusUnauthorized {
		t.Errorf("wrong secret: got %d", code)
	}
	if code := serve(t, h, http.MethodGet, "/v2/x/manifests/1", basicAuthPw("robot$old", "s3cret")); code != http.StatusUnauthorized {
		t.Errorf("expired robot: got %d want 401", code)
	}
	if _, err := h.Login("robot$ci", "s3cret"); err != ErrInvalidCredentials {
		t.Errorf("robot web login: got %v", err)
	}
}

func basicAuthPw(user, pass string) map[string]string {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth(user, pass)
	return map[string]string{"Authorization": req.Header.Get("Authorization")}
}

func TestRepositoryGrants(t *testing.T) {
	h := projectHandler(t)
	h.meta.Update(func(d *meta.Data) error {
		p := d.Projects["team"]
		p.Grants = []meta.RepoGrant{
			{User: "carol", Repos: "app-*", Role: meta.ProjectDeveloper}, // guest elsewhere
			{User: "dave", Repos: "db/**", Role: meta.ProjectMaintainer}, // no project role
			{User: "bob", Repos: "app-web", Role: meta.ProjectGuest},     // below his role: no effect
		}
		d.Projects["team"] = p
		return nil
	})
	cases := []struct {
		user, repo, action string
		want               bool
	}{
		{"carol", "team/app-web", "push", true},
		{"carol", "team/app-web", "delete", false},
		{"carol", "team/other", "push", false},
		{"carol", "team/other", "pull", true}, // her project role
		{"dave", "team/db/main", "delete", true},
		{"dave", "team/db", "pull", true}, // ** matches no segment too, as in RGSTR_PUBLIC_REPOS
		{"dave", "team/app-web", "pull", false},
		{"bob", "team/app-web", "push", true}, // grants only add
	}
	for _, c := range cases {
		if got := h.Can(c.user, c.repo, c.action); got != c.want {
			t.Errorf("Can(%q, %q, %q) = %v, want %v", c.user, c.repo, c.action, got, c.want)
		}
	}
	if h.IsProjectAdmin("dave", "team") {
		t.Error("a repository grant made dave a project admin")
	}
	// Tokens are narrowed to the granted repositories.
	got := h.grantForUser("carol", []Access{
		{Type: "repository", Name: "team/app-api", Actions: []string{"pull", "push"}},
		{Type: "repository", Name: "team/other", Actions: []string{"pull", "push"}},
	})
	if len(got) != 2 || len(got[0].Actions) != 2 || len(got[1].Actions) != 1 {
		t.Errorf("token grant: %+v", got)
	}
}

func TestRobotRepositoryPatterns(t *testing.T) {
	h := projectHandler(t)
	addRobot(h, meta.Robot{Name: "robot$web", Permissions: []meta.RobotPermission{
		{Project: "team", Repos: "web/**", Actions: []string{"pull", "push"}},
		{Project: "*", Repos: "team/base-*", Actions: []string{"pull"}}, // full names with "*"
	}}, "s3cret")
	cases := []struct {
		repo, action string
		want         bool
	}{
		{"team/web/frontend", "push", true},
		{"team/api", "pull", false},
		{"team/base-alpine", "pull", true},
		{"team/other", "pull", false},
	}
	for _, c := range cases {
		if got := h.Can("robot$web", c.repo, c.action); got != c.want {
			t.Errorf("robot Can(%q, %q) = %v, want %v", c.repo, c.action, got, c.want)
		}
	}
}
