package backup

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// Restore unpacks backup name ("latest" = the newest) from t into root.
// root must be empty of registry data unless force: then the current data
// is moved to root/.before-restore-<time>/ (delete it once the restore is
// checked). The caller holds the storage lock, so no rgstr runs on root.
//
// Blob contents are verified against their digests while unpacking; a
// damaged archive leaves root unchanged.
func Restore(ctx context.Context, t Target, name, root string, force bool) (string, error) {
	if name == "" || name == "latest" {
		objs, err := List(ctx, t)
		if err != nil {
			return "", err
		}
		if len(objs) == 0 {
			return "", fmt.Errorf("no backups in %s", t)
		}
		name = objs[len(objs)-1].Name
	}
	existing, err := dataEntries(root)
	if err != nil {
		return "", err
	}
	if len(existing) > 0 && !force {
		return "", fmt.Errorf("%s already holds registry data (%s); restore into an empty directory or use -force",
			root, strings.Join(existing, ", "))
	}

	rc, err := t.Get(ctx, name)
	if err != nil {
		return "", err
	}
	defer rc.Close()

	stamp := time.Now().UTC().Format(nameTime)
	stage := filepath.Join(root, ".restore-"+stamp)
	if err := os.MkdirAll(stage, 0755); err != nil {
		return "", err
	}
	if err := unpack(rc, stage); err != nil {
		os.RemoveAll(stage)
		return "", fmt.Errorf("%s: %w", name, err)
	}

	if len(existing) > 0 {
		aside := filepath.Join(root, ".before-restore-"+stamp)
		if err := os.MkdirAll(aside, 0755); err != nil {
			return "", err
		}
		for _, e := range existing {
			if err := os.Rename(filepath.Join(root, e), filepath.Join(aside, e)); err != nil {
				return "", err
			}
		}
	}
	entries, err := os.ReadDir(stage)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if err := os.Rename(filepath.Join(stage, e.Name()), filepath.Join(root, e.Name())); err != nil {
			return "", err
		}
	}
	return name, os.Remove(stage)
}

// dataEntries lists top-level entries of root that belong to a registry.
func dataEntries(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.MkdirAll(root, 0755)
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if n == ".rgstr.lock" || strings.HasPrefix(n, ".restore-") || strings.HasPrefix(n, ".before-restore-") {
			continue
		}
		if e.IsDir() && (n == "blobs" || n == "repositories" || n == "uploads") {
			if empty, _ := isEmptyTree(filepath.Join(root, n)); empty {
				continue // created by a first start, holds nothing
			}
		}
		out = append(out, n)
	}
	return out, nil
}

func isEmptyTree(dir string) (bool, error) {
	empty := true
	err := filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			empty = false
			return filepath.SkipAll
		}
		return err
	})
	return empty, err
}

func unpack(r io.Reader, dest string) error {
	tr := tar.NewReader(r)
	first := true
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			if first {
				return errors.New("empty archive")
			}
			return nil
		}
		if err != nil {
			return err
		}
		if first {
			if hdr.Name != ManifestName {
				return errors.New("not an rgstr backup")
			}
			var m Manifest
			if err := json.NewDecoder(io.LimitReader(tr, 1<<20)).Decode(&m); err != nil || m.Format != 1 {
				return fmt.Errorf("unsupported backup format")
			}
			first = false
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("%s: unexpected entry type", hdr.Name)
		}
		clean := path.Clean(hdr.Name)
		if clean != hdr.Name || path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") ||
			strings.Contains(clean, "\\") {
			return fmt.Errorf("unsafe path %q", hdr.Name)
		}
		if err := writeEntry(tr, hdr, filepath.Join(dest, filepath.FromSlash(clean)), clean); err != nil {
			return err
		}
	}
}

func writeEntry(r io.Reader, hdr *tar.Header, target, rel string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(hdr.Mode&0o666)|0o600)
	if err != nil {
		return err
	}
	// Blobs live at blobs/sha256/<2 hex>/<62 hex>: check their content.
	var h hash.Hash
	var want string
	if parts := strings.Split(rel, "/"); len(parts) == 4 && parts[0] == "blobs" && parts[1] == "sha256" &&
		len(parts[2]) == 2 && len(parts[3]) == 62 {
		h, want = sha256.New(), parts[2]+parts[3]
	}
	w := io.Writer(f)
	if h != nil {
		w = io.MultiWriter(f, h)
	}
	_, err = io.Copy(w, r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if h != nil && hex.EncodeToString(h.Sum(nil)) != want {
		return fmt.Errorf("%s: content does not match its digest (damaged backup)", rel)
	}
	return os.Chtimes(target, hdr.ModTime, hdr.ModTime)
}
