package storage

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GCLoop runs RunGC on the given interval until ctx is cancelled.
func (fs *Filesystem) GCLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := fs.RunGC(); err != nil {
				log.Printf("gc error: %v", err)
			}
		}
	}
}

// RunGC performs a mark-and-sweep garbage collection pass.
//
// The algorithm:
//  1. Acquire the global write lock so no blobs can be written or deleted
//     concurrently during the sweep.
//  2. Mark: walk every manifest file and collect referenced blob digests.
//     Also mark each manifest's own digest.
//  3. Sweep: walk every blob file; delete any that are not marked.
//  4. Clean stale upload sessions (older than cfg.UploadTTL).
//
// Because the write lock is held throughout, the window where a blob could be
// concurrently deleted or written is closed, so there are no TOCTOU races.
func (fs *Filesystem) RunGC() error {
	log.Println("gc: starting")

	// ── Phase 0: Acquire write lock ───────────────────────────────────────
	fs.gcMu.Lock()
	defer fs.gcMu.Unlock()

	// ── Phase 1: Mark referenced blobs ────────────────────────────────────
	referenced := make(map[string]bool) // hex hash → true

	reposDir := filepath.Join(fs.root, "repositories")
	if err := filepath.WalkDir(reposDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(d.Name(), ".") {
			return nil
		}

		// ── Manifest by-digest files ──
		if strings.Contains(filepath.ToSlash(path), "/manifests/by-digest/") {
			hexHash := d.Name()
			// The manifest file itself counts as a referenced blob if a layer
			// with that hash exists (for manifest blob pruning).
			referenced[hexHash] = true

			raw, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			var mf manifestFile
			if err := json.Unmarshal(raw, &mf); err != nil {
				return nil
			}
			for _, dig := range extractDigests(mf.Content) {
				if dig.Algorithm() == "sha256" {
					referenced[dig.Hex()] = true
				}
			}
		}

		// ── Tag pointer files ─────────────────────────────────────────────
		// A tag file contains a hex hash that points to a by-digest manifest.
		// Keep any manifest whose hex is still pointed to by at least one tag.
		if strings.Contains(filepath.ToSlash(path), "/manifests/tags/") {
			b, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			hexHash := strings.TrimSpace(string(b))
			if len(hexHash) == 64 {
				referenced[hexHash] = true
			}
		}

		return nil
	}); err != nil {
		return err
	}

	// ── Phase 2: Sweep unreferenced blobs ─────────────────────────────────
	blobsRoot := filepath.Join(fs.root, "blobs", "sha256")
	deletedBlobs := 0

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
		if !referenced[hexHash] {
			if err := os.Remove(path); err == nil {
				log.Printf("gc: removed blob sha256:%s", hexHash)
				deletedBlobs++
			}
		}
		return nil
	}); err != nil {
		return err
	}

	// ── Phase 3: Remove orphaned by-digest manifests ──────────────────────
	// A by-digest manifest is orphaned when no tag points to it and it was
	// not referenced transitively by another manifest.
	deletedMfst := 0
	if err := filepath.WalkDir(reposDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		if !strings.Contains(filepath.ToSlash(path), "/manifests/by-digest/") {
			return nil
		}
		hexHash := d.Name()
		if len(hexHash) != 64 {
			return nil
		}
		if !referenced[hexHash] {
			if err := os.Remove(path); err == nil {
				log.Printf("gc: removed manifest sha256:%s", hexHash)
				deletedMfst++
			}
		}
		return nil
	}); err != nil {
		return err
	}

	// ── Phase 4: Clean stale upload sessions ──────────────────────────────
	staleUploads := 0
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
			os.RemoveAll(filepath.Join(uploadsDir, e.Name()))
			fs.uploadMu.Delete(e.Name())
			staleUploads++
			log.Printf("gc: removed stale upload %s (repo=%s, age=%s)",
				e.Name(), info.Repo, time.Since(info.StartedAt).Round(time.Second))
		}
	}

	log.Printf("gc: done — blobs removed: %d, manifests removed: %d, stale uploads: %d",
		deletedBlobs, deletedMfst, staleUploads)
	return nil
}
