// Package policy evaluates tag retention and immutability rules.
package policy

import (
	"fmt"
	"sort"
	"time"

	"rgstr/internal/glob"
	"rgstr/internal/meta"
	"rgstr/internal/storage"
)

// Immutable reports whether an enabled rule protects repo:tag.
func Immutable(rules []meta.ImmutableRule, repo, tag string) bool {
	for _, r := range rules {
		if !r.Disabled && glob.Match(r.Repos, repo) && glob.Match(r.Tags, tag) {
			return true
		}
	}
	return false
}

// ValidateRetention checks rules before they are saved.
func ValidateRetention(rules []meta.RetentionRule) error {
	for i, r := range rules {
		if !glob.Valid(r.Repos) || !glob.Valid(r.Tags) {
			return fmt.Errorf("rule %d: invalid repository or tag pattern", i+1)
		}
		if r.KeepLast < 0 || r.KeepDays < 0 {
			return fmt.Errorf("rule %d: values must not be negative", i+1)
		}
		if r.KeepLast == 0 && r.KeepDays == 0 {
			return fmt.Errorf("rule %d: set \"keep last\" and/or \"keep days\"", i+1)
		}
	}
	return nil
}

// ValidateImmutable checks rules before they are saved.
func ValidateImmutable(rules []meta.ImmutableRule) error {
	for i, r := range rules {
		if !glob.Valid(r.Repos) || !glob.Valid(r.Tags) {
			return fmt.Errorf("rule %d: invalid repository or tag pattern", i+1)
		}
	}
	return nil
}

// Expired returns the tags of repo that retention deletes: tags covered by
// at least one enabled rule and kept by none. Immutable tags are never
// returned.
func Expired(rules []meta.RetentionRule, immutable []meta.ImmutableRule,
	repo string, tags []storage.TagInfo, now time.Time) []string {

	covered := make(map[string]bool)
	kept := make(map[string]bool)
	for _, r := range rules {
		if r.Disabled || !glob.Match(r.Repos, repo) {
			continue
		}
		var cand []storage.TagInfo
		for _, t := range tags {
			if glob.Match(r.Tags, t.Name) {
				cand = append(cand, t)
				covered[t.Name] = true
			}
		}
		// Newest first; ties broken by name for a stable result.
		sort.Slice(cand, func(i, j int) bool {
			if !cand[i].PushedAt.Equal(cand[j].PushedAt) {
				return cand[i].PushedAt.After(cand[j].PushedAt)
			}
			return cand[i].Name < cand[j].Name
		})
		for i, t := range cand {
			if (r.KeepLast > 0 && i < r.KeepLast) ||
				(r.KeepDays > 0 && now.Sub(t.PushedAt) < time.Duration(r.KeepDays)*24*time.Hour) {
				kept[t.Name] = true
			}
		}
	}

	var out []string
	for _, t := range tags {
		if covered[t.Name] && !kept[t.Name] && !Immutable(immutable, repo, t.Name) {
			out = append(out, t.Name)
		}
	}
	sort.Strings(out)
	return out
}
