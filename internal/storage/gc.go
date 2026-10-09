package storage

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
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
func (fs *Filesystem) RunGC() error {
	_, err := fs.CollectGarbage(GCOptions{})
	return err
}

// CollectGarbage performs a mark-and-sweep garbage collection pass.
//
// The algorithm:
//  1. Acquire the global write lock so no blobs can be written or deleted
//     concurrently during the sweep.
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
//
// Because the write lock is held throughout, the window where a blob could be
// concurrently deleted or written is closed, so there are no TOCTOU races.
func (fs *Filesystem) CollectGarbage(opts GCOptions) (GCResult, error) {
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
	}

	// ── Phase 1: Mark ─────────────────────────────────────────────────────
	referenced := make(map[string]bool) // blob hex hash → in use
	recent := func(d os.DirEntry) bool {
		if opts.IgnoreGrace {
			return false
		}
		info, err := d.Info()
		return err == nil && time.Since(info.ModTime()) < fs.cfg.UploadTTL
	}

	type repoState struct {
		roots     []string          // manifest hex hashes that are in use
		manifests map[string]string // by-digest hex → file path
	}
	repos := make(map[string]*repoState) // repo dir → state
	repo := func(dir string) *repoState {
		st, ok := repos[dir]
		if !ok {
			st = &repoState{manifests: make(map[string]string)}
			repos[dir] = st
		}
		return st
	}

	// Layout: <repo>/manifests/by-digest/<hex>, <repo>/manifests/tags/<tag>,
	// <repo>/layers/<hex>.
	reposDir := filepath.Join(fs.root, "repositories")
	expired := func(repoDir string) ExpireSet {
		name, _ := filepath.Rel(reposDir, repoDir)
		return opts.Expire[filepath.ToSlash(name)]
	}
	if err := filepath.WalkDir(reposDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		dir := filepath.Dir(path)
		parent := filepath.Dir(dir)
		switch {
		case filepath.Base(dir) == "by-digest" && filepath.Base(parent) == "manifests":
			st := repo(filepath.Dir(parent))
			st.manifests[d.Name()] = path
			if recent(d) {
				if exp := expired(filepath.Dir(parent)); !exp.has(exp.Manifests, d.Name()) {
					st.roots = append(st.roots, d.Name())
				}
			}

		case filepath.Base(dir) == "tags" && filepath.Base(parent) == "manifests":
			b, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			if hexHash := strings.TrimSpace(string(b)); len(hexHash) == 64 {
				st := repo(filepath.Dir(parent))
				st.roots = append(st.roots, hexHash)
			}

		case filepath.Base(dir) == "layers" && recent(d):
			if exp := expired(parent); !exp.has(exp.Blobs, d.Name()) {
				referenced[d.Name()] = true
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
			path, ok := st.manifests[hexHash]
			if !ok || reachable[path] {
				continue
			}
			reachable[path] = true
			// Some clients also upload the manifest as a blob; keep it.
			referenced[hexHash] = true

			raw, err := os.ReadFile(path)
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
	blobsRoot := filepath.Join(fs.root, "blobs", "sha256")

	if err := filepath.WalkDir(blobsRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		// Reconstruct the full hex hash from the 2-char parent dir + filename.
		prefix := filepath.Base(filepath.Dir(path))
		suffix := d.Name()
		if len(prefix) != 2 || strings.HasPrefix(suffix, ".") {
			return nil
		}
		hexHash := prefix + suffix
		if len(hexHash) != 64 {
			return nil
		}
		if referenced[hexHash] {
			return nil
		}
		var size int64
		if info, err := d.Info(); err == nil {
			size = info.Size()
		}
		if !opts.DryRun {
			if err := os.Remove(path); err != nil {
				return nil
			}
			log.Printf("gc: removed blob sha256:%s", hexHash)
		}
		res.BlobsRemoved++
		res.BytesFreed += size
		return nil
	}); err != nil {
		return res, err
	}

	// ── Phase 2b: Drop repository links to removed blobs ──────────────────
	// Otherwise a repo would regain access if the same content were later
	// uploaded to a different repository.
	filepath.WalkDir(reposDir, func(path string, d os.DirEntry, err error) error {
		if opts.DryRun {
			return filepath.SkipAll
		}
		if err != nil || d.IsDir() || filepath.Base(filepath.Dir(path)) != "layers" {
			return nil
		}
		blob := DigestFromHex(d.Name())
		if !blob.Valid() {
			return nil
		}
		if _, err := os.Stat(fs.blobPath(blob)); os.IsNotExist(err) {
			os.Remove(path)
		}
		return nil
	})

	// ── Phase 3: Remove unreachable by-digest manifests ──────────────────
	for dir, st := range repos {
		name, _ := filepath.Rel(reposDir, dir)
		for hexHash, path := range st.manifests {
			if reachable[path] {
				continue
			}
			if !opts.DryRun {
				if err := os.Remove(path); err != nil {
					continue
				}
				log.Printf("gc: removed manifest %s@sha256:%s", filepath.ToSlash(name), hexHash)
			}
			res.ManifestsRemoved++
			if len(res.Manifests) < MaxGCListed {
				res.Manifests = append(res.Manifests, filepath.ToSlash(name)+"@sha256:"+hexHash)
			}
		}
	}

	// ── Phase 4: Clean stale upload sessions ──────────────────────────────
	uploadsDir := filepath.Join(fs.root, "uploads")
	entries, _ := os.ReadDir(uploadsDir)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		infoPath := filepath.Join(uploadsDir, e.Name(), "info.json")
		raw, err := os.ReadFile(infoPath)
		if err != nil {
			continue
		}
		var info UploadInfo
		if json.Unmarshal(raw, &info) != nil {
			continue
		}
		if time.Since(info.StartedAt) > fs.cfg.UploadTTL {
			res.UploadsRemoved++
			if opts.DryRun {
				continue
			}
			os.RemoveAll(filepath.Join(uploadsDir, e.Name()))
			fs.uploadMu.Delete(e.Name())
			log.Printf("gc: removed stale upload %s (repo=%s, age=%s)",
				e.Name(), info.Repo, time.Since(info.StartedAt).Round(time.Second))
		}
	}

	log.Printf("gc: done — blobs removed: %d (%d bytes), manifests removed: %d, stale uploads: %d",
		res.BlobsRemoved, res.BytesFreed, res.ManifestsRemoved, res.UploadsRemoved)
	return res, nil
}
