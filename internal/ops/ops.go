// Package ops implements registry operations shared by the Docker API and
// the web UI, so both apply the same policies, audit and notifications.
// Callers check permissions before calling.
package ops

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"rgstr/internal/audit"
	"rgstr/internal/meta"
	"rgstr/internal/policy"
	"rgstr/internal/storage"
)

// Actor identifies who performs an operation.
type Actor struct {
	Name string // "" for anonymous
	IP   string
}

// DisplayName is the actor's name for logs, "anonymous" when unset.
func (a Actor) DisplayName() string {
	if a.Name == "" {
		return "anonymous"
	}
	return a.Name
}

// Ops performs registry operations.
type Ops struct {
	store *storage.Filesystem
	meta  *meta.Store
	audit *audit.Log
}

// New creates Ops over store, with policies from m, recording to log
// (nil disables auditing).
func New(store *storage.Filesystem, m *meta.Store, log *audit.Log) *Ops {
	return &Ops{store: store, meta: m, audit: log}
}

// Audit records an action by a.
func (o *Ops) Audit(a Actor, action, resource, detail string, err error) {
	e := audit.Entry{User: a.Name, IP: a.IP, Action: action, Resource: resource, Detail: detail}
	if err != nil {
		e.Error = err.Error()
	}
	o.audit.Add(e)
}

// AuditLog returns the audit log.
func (o *Ops) AuditLog() *audit.Log { return o.audit }

// Errors returned by operations.
var (
	ErrNotFound  = errors.New("not found")
	ErrImmutable = errors.New("tag is immutable")
)

// immutableErr names the protected tags.
func immutableErr(repo string, tags []string) error {
	return fmt.Errorf("%w: %s:%s", ErrImmutable, repo, strings.Join(tags, ", "+repo+":"))
}

// IsImmutable reports whether a policy protects repo:tag.
func (o *Ops) IsImmutable(repo, tag string) bool {
	var rules []meta.ImmutableRule
	o.meta.View(func(d *meta.Data) { rules = append(rules, d.Immutable...) })
	return policy.Immutable(rules, repo, tag)
}

// immutableTags returns which of tags are protected.
func (o *Ops) immutableTags(repo string, tags []string) []string {
	var out []string
	for _, t := range tags {
		if o.IsImmutable(repo, t) {
			out = append(out, t)
		}
	}
	return out
}

// PutManifest stores a manifest under ref (tag or digest). Overwriting an
// immutable tag with a different image is refused.
func (o *Ops) PutManifest(a Actor, repo, ref string, m *storage.Manifest) (err error) {
	sum := sha256.Sum256(m.Content)
	digest := storage.DigestFromHex(hex.EncodeToString(sum[:]))
	defer func() { o.Audit(a, audit.Push, refName(repo, ref), string(digest), err) }()

	if d := storage.Digest(ref); !d.Valid() && o.IsImmutable(repo, ref) {
		if cur, err := o.store.GetManifest(repo, ref); err == nil && cur.Digest != digest {
			return immutableErr(repo, []string{ref})
		}
	}
	return o.store.PutManifest(repo, ref, m)
}

// RecordPull audits a manifest download.
func (o *Ops) RecordPull(a Actor, repo, ref string, digest storage.Digest) {
	o.Audit(a, audit.Pull, refName(repo, ref), string(digest), nil)
}

// refName formats repo:tag or repo@digest.
func refName(repo, ref string) string {
	if storage.Digest(ref).Valid() {
		return repo + "@" + ref
	}
	return repo + ":" + ref
}

// DeleteTag removes one tag. The image stays available under its other
// tags; GC removes its data once no tag references it.
func (o *Ops) DeleteTag(a Actor, repo, tag string) (err error) {
	defer func() {
		if !errors.Is(err, ErrNotFound) {
			o.Audit(a, audit.DeleteTag, repo+":"+tag, "", err)
		}
	}()
	tags, err := o.store.RepoTags(repo)
	if err != nil {
		return err
	}
	if _, ok := findTag(tags, tag); !ok {
		return ErrNotFound
	}
	if o.IsImmutable(repo, tag) {
		return immutableErr(repo, []string{tag})
	}
	return o.store.DeleteManifest(repo, tag)
}

// DeleteImage removes the manifest digest and every tag pointing to it.
// Returns the removed tags.
func (o *Ops) DeleteImage(a Actor, repo string, digest storage.Digest) (removed []string, err error) {
	defer func() {
		if !errors.Is(err, ErrNotFound) {
			detail := ""
			if len(removed) > 0 {
				detail = "tags: " + strings.Join(removed, ", ")
			}
			o.Audit(a, audit.DeleteImage, repo+"@"+string(digest), detail, err)
		}
	}()
	if !digest.Valid() {
		return nil, fmt.Errorf("invalid digest %q", digest)
	}
	if _, err := o.store.GetManifest(repo, string(digest)); err != nil {
		if errors.Is(err, storage.ErrManifestNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	tags, err := o.store.RepoTags(repo)
	if err != nil {
		return nil, err
	}
	removed = tagsOf(tags, digest)
	if locked := o.immutableTags(repo, removed); len(locked) > 0 {
		return nil, immutableErr(repo, locked)
	}
	if err := o.store.DeleteManifest(repo, string(digest)); err != nil {
		return nil, err
	}
	return removed, nil
}

// DeleteRepository removes the repository with all its tags.
func (o *Ops) DeleteRepository(a Actor, repo string) (err error) {
	defer func() {
		if !errors.Is(err, ErrNotFound) {
			o.Audit(a, audit.DeleteRepo, repo, "", err)
		}
	}()
	tags, err := o.store.RepoTags(repo)
	if err != nil {
		return err
	}
	var names []string
	for _, t := range tags {
		names = append(names, t.Name)
	}
	if locked := o.immutableTags(repo, names); len(locked) > 0 {
		return immutableErr(repo, locked)
	}
	if err := o.store.DeleteRepository(repo); err != nil {
		if errors.Is(err, storage.ErrRepoNotFound) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

func findTag(tags []storage.TagInfo, name string) (storage.TagInfo, bool) {
	for _, t := range tags {
		if t.Name == name {
			return t, true
		}
	}
	return storage.TagInfo{}, false
}

func tagsOf(tags []storage.TagInfo, digest storage.Digest) []string {
	var out []string
	for _, t := range tags {
		if t.Digest == digest {
			out = append(out, t.Name)
		}
	}
	return out
}

// ActorFrom builds an Actor for an HTTP request made by name. Behind a
// reverse proxy the first X-Forwarded-For address is used.
func ActorFrom(r *http.Request, name string) Actor {
	return Actor{Name: name, IP: audit.ClientIP(r)}
}

// System is the actor for scheduled jobs.
var System = Actor{Name: "system"}

// ApplyRetention deletes the tags that retention rules let go (or, for a
// dry run, only lists them). Returns repo:tag entries, sorted.
func (o *Ops) ApplyRetention(a Actor, dryRun bool) ([]string, error) {
	var rules []meta.RetentionRule
	var immutable []meta.ImmutableRule
	o.meta.View(func(d *meta.Data) {
		rules = append(rules, d.Retention...)
		immutable = append(immutable, d.Immutable...)
	})
	if len(rules) == 0 {
		return nil, nil
	}
	repos, err := o.store.ListRepositories()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var out []string
	for _, repo := range repos {
		tags, err := o.store.RepoTags(repo)
		if err != nil {
			return out, err
		}
		for _, tag := range policy.Expired(rules, immutable, repo, tags, now) {
			if !dryRun {
				if err := o.DeleteTag(a, repo, tag); err != nil && !errors.Is(err, ErrNotFound) {
					return out, err
				}
			}
			out = append(out, repo+":"+tag)
		}
	}
	sort.Strings(out)
	return out, nil
}

// ProjectUsage returns the bytes of data the project's repositories keep:
// distinct blobs reachable from their tags.
func (o *Ops) ProjectUsage(project string) int64 {
	repos, err := o.store.ListRepositories()
	if err != nil {
		return 0
	}
	blobs := map[storage.Digest]int64{}
	for _, repo := range repos {
		if meta.ProjectOf(repo) == project {
			o.store.ReachableBlobs(repo, blobs)
		}
	}
	var total int64
	for _, size := range blobs {
		total += size
	}
	return total
}
