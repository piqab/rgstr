// Package ops implements registry operations shared by the Docker API and
// the web UI, so both apply the same policies, audit and notifications.
// Callers check permissions before calling.
package ops

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

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
}

// New creates Ops over store.
func New(store *storage.Filesystem) *Ops {
	return &Ops{store: store}
}

// ErrNotFound is returned when the tag, image or repository does not exist.
var ErrNotFound = errors.New("not found")

// DeleteTag removes one tag. The image stays available under its other
// tags; GC removes its data once no tag references it.
func (o *Ops) DeleteTag(a Actor, repo, tag string) error {
	tags, err := o.store.RepoTags(repo)
	if err != nil {
		return err
	}
	if _, ok := findTag(tags, tag); !ok {
		return ErrNotFound
	}
	return o.store.DeleteManifest(repo, tag)
}

// DeleteImage removes the manifest digest and every tag pointing to it.
// Returns the removed tags.
func (o *Ops) DeleteImage(a Actor, repo string, digest storage.Digest) ([]string, error) {
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
	removed := tagsOf(tags, digest)
	if err := o.store.DeleteManifest(repo, string(digest)); err != nil {
		return nil, err
	}
	return removed, nil
}

// DeleteRepository removes the repository with all its tags.
func (o *Ops) DeleteRepository(a Actor, repo string) error {
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
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ip = strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	return Actor{Name: name, IP: ip}
}
