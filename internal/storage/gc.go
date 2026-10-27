package storage

import (
	"encoding/json"
	"log"
	"path"
	"strings"
	"time"
)

// GCOptions control a garbage collection run.
type GCOptions struct {
	// DryRun reports what would be removed without removing anything.
	DryRun bool
	// IgnoreGrace also removes recent unreferenced uploads and manifests.
	// This frees space immediately but can break a push in progress.
	IgnoreGrace bool
	// Expire lifts the grace period only for these just-deleted manifests
	// and blobs (hex), per repository, so their space is freed now while
	// other recent uploads stay protected.
	Expire map[string]ExpireSet
}

// ExpireSet lists manifests and blobs (hex) of one repository.
type ExpireSet struct {
	Manifests []string
	Blobs     []string
}

func (e ExpireSet) has(list []string, h string) bool {
	for _, x := range list {
		if x == h {
			return true
		}
	}
	return false
}

// GCResult reports what a run removed (or, for a dry run, would remove).
type GCResult struct {
	BlobsRemoved     int
	BytesFreed       int64
	ManifestsRemoved int
	UploadsRemoved   int
	Manifests        []string // repo@sha256:…, at most MaxGCListed
}

// MaxGCListed caps GCResult.Manifests.
const MaxGCListed = 200

// RunGC runs a regular garbage collection pass.
func (fs *Store) RunGC() error {
	_, err := fs.CollectGarbage(GCOptions{})
	return err
}

// CollectGarbage performs a mark-and-sweep garbage collection pass.
//
// The algorithm:
//  1. Acquire the global write lock so no blobs can be linked or manifests
//     written concurrently during the sweep — in this process, and through
//     the Locker in every process sharing the storage.
//  2. Mark: in each repository, start from the manifests its tags point to
//     and follow every digest they reference (child manifests of an index,
//     config, layers). Everything reached is in use.
//  3. Sweep: delete blobs that were not marked, then by-digest manifests that
//     no tag reaches in their repository.
//  4. Clean stale upload sessions (older than cfg.UploadTTL).
//
// Grace period: a push uploads blobs and child manifests before the manifest
// or tag that references them. Blobs linked to a repository and by-digest
// manifests written within cfg.UploadTTL are therefore kept even when nothing
// references them yet, so GC never deletes the pieces of an in-progress push.
func (fs *Store) CollectGarbage(opts GCOptions) (GCResult, error) {
	var res GCResult
	log.Printf("gc: starting (dry run: %v, ignore grace: %v)", opts.DryRun, opts.IgnoreGrace)

	// ── Phase 0: Lock ─────────────────────────────────────────────────────
	// A dry run changes nothing, so it only needs to keep GC runs out.
	if opts.DryRun {
		fs.gcMu.RLock()
		defer fs.gcMu.RUnlock()
	} else {
		fs.gcMu.Lock()
		defer fs.gcMu.Unlock()
		if fs.dist != nil {
			release, err := fs.dist.Exclusive(bg)
			if err != nil {
				return res, err
			}
			defer release()
		}
	}

	// ── Phase 1: Mark ─────────────────────────────────────────────────────
	referenced := make(map[string]bool) // blob hex hash → in use
	recent := func(info FileInfo) bool {
		return !opts.IgnoreGrace && time.Since(info.ModTime) < fs.cfg.UploadTTL
	}

	type repoState struct {
		roots     []string          // manifest hex hashes that are in use
		manifests map[string]string // by-digest hex → file path
	}
	repos := make(map[string]*repoState) // repo name → state
	repo := func(name string) *repoState {
		st, ok := repos[name]
		if !ok {
			st = &repoState{manifests: make(map[string]string)}
			repos[name] = st
		}
		return st
	}

	// Layout: <repo>/manifests/by-digest/<hex>, <repo>/manifests/tags/<tag>,
	// <repo>/layers/<hex>.
	var links []string // layer link paths, for phase 2b
	if err := fs.d.Walk(bg, "repositories", func(p string, info FileInfo) error {
		dir, name := path.Split(p)
		dir = strings.TrimSuffix(dir, "/")
		parent := path.Dir(dir)
		switch {
		case path.Base(dir) == "by-digest" && path.Base(parent) == "manifests":
			repoName := strings.TrimPrefix(path.Dir(parent), "repositories/")
			st := repo(repoName)
			st.manifests[name] = p
			if recent(info) {
				if exp := opts.Expire[repoName]; !exp.has(exp.Manifests, name) {
					st.roots = append(st.roots, name)
				}
			}

		case path.Base(dir) == "tags" && path.Base(parent) == "manifests":
			b, err := fs.d.GetContent(bg, p)
			if err != nil {
				return nil
			}
			if hexHash := strings.TrimSpace(string(b)); len(hexHash) == 64 {
				st := repo(strings.TrimPrefix(path.Dir(parent), "repositories/"))
				st.roots = append(st.roots, hexHash)
			}

		case path.Base(dir) == "layers":
			links = append(links, p)
			if recent(info) {
				repoName := strings.TrimPrefix(parent, "repositories/")
				if exp := opts.Expire[repoName]; !exp.has(exp.Blobs, name) {
					referenced[name] = true
				}
			}
		}
		return nil
	}); err != nil {
		return res, err
	}

	// Follow references from the roots. A digest that names a manifest in
	// the same repository (e.g. a platform manifest of an index) is followed
	// further; any other digest is a blob.
	reachable := make(map[string]bool) // by-digest file path → in use
	for _, st := range repos {
		stack := append([]string(nil), st.roots...)
		for len(stack) > 0 {
			hexHash := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			p, ok := st.manifests[hexHash]
			if !ok || reachable[p] {
				continue
			}
			reachable[p] = true
			// Some clients also upload the manifest as a blob; keep it.
			referenced[hexHash] = true

			raw, err := fs.d.GetContent(bg, p)
			if err != nil {
				continue
			}
			var mf manifestFile
			if err := json.Unmarshal(raw, &mf); err != nil {
				continue
			}
			for _, dig := range extractDigests(mf.Content) {
				referenced[dig.Hex()] = true
				stack = append(stack, dig.Hex())
			}
		}
	}

	// ── Phase 2: Sweep unreferenced blobs ─────────────────────────────────
	removed := map[string]bool{}
	present := map[string]bool{} // every blob found
	var unreferenced []string
	if err := fs.d.Walk(bg, "blobs/sha256", func(p string, info FileInfo) error {
		// Reconstruct the full hex hash from the 2-char parent dir + filename.
		dir, suffix := path.Split(p)
		prefix := path.Base(dir)
		hexHash := prefix + suffix
		if len(prefix) != 2 || len(hexHash) != 64 {
			return nil
		}
		present[hexHash] = true
		if referenced[hexHash] {
			return nil
		}
		unreferenced = append(unreferenced, p)
		res.BlobsRemoved++
		res.BytesFreed += info.Size
		return nil
	}); err != nil {
		return res, err
	}
	if !opts.DryRun {
		for _, p := range unreferenced {
			if err := fs.d.Delete(bg, p); err != nil {
				continue
			}
			dir, suffix := path.Split(p)
			removed[path.Base(dir)+suffix] = true
			log.Printf("gc: removed blob sha256:%s", path.Base(dir)+suffix)
		}
	}

	// ── Phase 2b: Drop repository links to removed blobs ──────────────────
	// Otherwise a repo would regain access if the same content were later
	// uploaded to a different repository.
	if !opts.DryRun {
		for _, p := range links {
			hexHash := path.Base(p)
			if removed[hexHash] || !present[hexHash] {
				fs.d.Delete(bg, p)
			}
		}
	}

	// ── Phase 3: Remove unreachable by-digest manifests ──────────────────
	for name, st := range repos {
		for hexHash, p := range st.manifests {
			if reachable[p] {
				continue
			}
			if !opts.DryRun {
				if err := fs.d.Delete(bg, p); err != nil {
					continue
				}
				log.Printf("gc: removed manifest %s@sha256:%s", name, hexHash)
			}
			res.ManifestsRemoved++
			if len(res.Manifests) < MaxGCListed {
				res.Manifests = append(res.Manifests, name+"@sha256:"+hexHash)
			}
		}
	}

	// ── Phase 4: Clean stale upload sessions ──────────────────────────────
	entries, _ := fs.d.List(bg, "uploads")
	for _, e := range entries {
		if !e.IsDir {
			continue
		}
		info, err := fs.loadUploadInfo(e.Name)
		if err != nil {
			continue
		}
		if time.Since(info.StartedAt) > fs.cfg.UploadTTL {
			res.UploadsRemoved++
			if opts.DryRun {
				continue
			}
			fs.d.Delete(bg, fs.uploadDir(e.Name))
			fs.uploadMu.Delete(e.Name)
			log.Printf("gc: removed stale upload %s (repo=%s, age=%s)",
				e.Name, info.Repo, time.Since(info.StartedAt).Round(time.Second))
		}
	}

	log.Printf("gc: done — blobs removed: %d (%d bytes), manifests removed: %d, stale uploads: %d",
		res.BlobsRemoved, res.BytesFreed, res.ManifestsRemoved, res.UploadsRemoved)
	return res, nil
}
