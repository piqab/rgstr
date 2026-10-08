// Package glob matches slash-separated names (repositories, tags) against
// patterns used in configuration and policies.
package glob

import (
	"path"
	"strings"
)

// Match matches name against a glob pattern where:
//   - "*"  matches any sequence of characters except "/"
//   - "**" matches any sequence of path segments (zero or more), including "/"
//   - "?"  matches any single character except "/"
//
// Examples:
//
//	Match("public/**",    "public/myimage")      → true
//	Match("public/**",    "public/ns/myimage")   → true
//	Match("**/public/**", "alex/public/alpine")  → true
//	Match("library/*",    "library/ubuntu")      → true
//	Match("library/*",    "library/ns/ubuntu")   → false
//	Match("alpine",       "alpine")              → true
func Match(pattern, name string) bool {
	return matchSegments(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

// matchSegments recursively matches pattern segments against name segments.
// "**" consumes zero or more name segments.
func matchSegments(pat, name []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			pat = pat[1:]
			if len(pat) == 0 {
				return true // ** at end matches everything remaining
			}
			// Try consuming 0, 1, 2, … name segments for **.
			for i := 0; i <= len(name); i++ {
				if matchSegments(pat, name[i:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		ok, err := path.Match(pat[0], name[0])
		if err != nil || !ok {
			return false
		}
		pat = pat[1:]
		name = name[1:]
	}
	return len(name) == 0
}

// Valid reports whether pattern is well-formed.
func Valid(pattern string) bool {
	if pattern == "" {
		return false
	}
	for _, seg := range strings.Split(pattern, "/") {
		if seg == "**" {
			continue
		}
		if _, err := path.Match(seg, ""); err != nil {
			return false
		}
	}
	return true
}
