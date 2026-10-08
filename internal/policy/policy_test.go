package policy

import (
	"reflect"
	"testing"
	"time"

	"rgstr/internal/meta"
	"rgstr/internal/storage"
)

var now = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func tags(ages map[string]int) []storage.TagInfo {
	var out []storage.TagInfo
	for name, days := range ages {
		out = append(out, storage.TagInfo{Name: name, PushedAt: now.Add(-time.Duration(days) * 24 * time.Hour)})
	}
	return out
}

func TestExpired(t *testing.T) {
	ts := tags(map[string]int{"v1": 30, "v2": 20, "v3": 10, "v4": 1, "dev-a": 40, "dev-b": 2, "latest": 50})
	cases := []struct {
		name      string
		rules     []meta.RetentionRule
		immutable []meta.ImmutableRule
		repo      string
		want      []string
	}{
		{"keep last 2 of v*", []meta.RetentionRule{{Repos: "**", Tags: "v*", KeepLast: 2}}, nil, "app",
			[]string{"v1", "v2"}},
		{"keep 15 days of dev-*", []meta.RetentionRule{{Repos: "**", Tags: "dev-*", KeepDays: 15}}, nil, "app",
			[]string{"dev-a"}},
		{"last or days", []meta.RetentionRule{{Repos: "**", Tags: "v*", KeepLast: 1, KeepDays: 15}}, nil, "app",
			[]string{"v1", "v2"}},
		{"another rule keeps it", []meta.RetentionRule{
			{Repos: "**", Tags: "*", KeepLast: 1},
			{Repos: "**", Tags: "v*", KeepLast: 10}}, nil, "app",
			[]string{"dev-a", "dev-b", "latest"}},
		{"repo not matched", []meta.RetentionRule{{Repos: "team/**", Tags: "*", KeepLast: 1}}, nil, "other/app", nil},
		{"disabled rule", []meta.RetentionRule{{Repos: "**", Tags: "*", KeepLast: 1, Disabled: true}}, nil, "app", nil},
		{"immutable never expires", []meta.RetentionRule{{Repos: "**", Tags: "v*", KeepLast: 1}},
			[]meta.ImmutableRule{{Repos: "**", Tags: "v1"}}, "app", []string{"v2", "v3"}},
	}
	for _, c := range cases {
		got := Expired(c.rules, c.immutable, c.repo, ts, now)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestValidate(t *testing.T) {
	bad := [][]meta.RetentionRule{
		{{Repos: "", Tags: "*", KeepLast: 1}},
		{{Repos: "**", Tags: "[", KeepLast: 1}},
		{{Repos: "**", Tags: "*"}},
		{{Repos: "**", Tags: "*", KeepLast: -1}},
	}
	for _, rules := range bad {
		if ValidateRetention(rules) == nil {
			t.Errorf("accepted %+v", rules)
		}
	}
	if err := ValidateRetention([]meta.RetentionRule{{Repos: "team/**", Tags: "v*", KeepDays: 7}}); err != nil {
		t.Errorf("rejected valid rule: %v", err)
	}
	if ValidateImmutable([]meta.ImmutableRule{{Repos: "**", Tags: ""}}) == nil {
		t.Error("accepted empty tag pattern")
	}
}
