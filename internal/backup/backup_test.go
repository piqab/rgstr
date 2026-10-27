package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rgstr/internal/config"
)

func TestSchedule(t *testing.T) {
	at := func(s string) time.Time { v, _ := time.Parse(time.RFC3339, s); return v }
	cases := []struct{ expr, from, want string }{
		{"0 3 * * *", "2026-10-27T02:59:00Z", "2026-10-27T03:00:00Z"},
		{"0 3 * * *", "2026-10-27T03:00:00Z", "2026-10-28T03:00:00Z"},
		{"*/15 * * * *", "2026-10-27T10:07:30Z", "2026-10-27T10:15:00Z"},
		{"30 2 * * 0", "2026-10-27T00:00:00Z", "2026-11-01T02:30:00Z"}, // Sunday
		{"30 2 * * 7", "2026-10-27T00:00:00Z", "2026-11-01T02:30:00Z"},
		{"0 0 1 1 *", "2026-10-27T00:00:00Z", "2027-01-01T00:00:00Z"},
		{"0 12 1-5/2 * *", "2026-10-27T00:00:00Z", "2026-11-01T12:00:00Z"},
		{"0 0 29 2 *", "2026-03-01T00:00:00Z", "2028-02-29T00:00:00Z"},
		{"0 6 13 * 5", "2026-10-27T00:00:00Z", "2026-10-30T06:00:00Z"}, // dom OR dow
	}
	for _, c := range cases {
		s, err := ParseSchedule(c.expr)
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		if got := s.Next(at(c.from)); !got.Equal(at(c.want)) {
			t.Errorf("%s after %s: got %s want %s", c.expr, c.from, got.Format(time.RFC3339), c.want)
		}
	}
	for _, bad := range []string{"", "* * * *", "60 * * * *", "* 24 * * *", "*/0 * * * *", "a * * * *", "5-1 * * * *"} {
		if _, err := ParseSchedule(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if s, _ := ParseSchedule("0 0 30 2 *"); !s.Next(time.Now()).IsZero() {
		t.Error("impossible date matched")
	}
}

// fakeRegistry writes a storage root with a blob, a manifest link, users
// and leftovers that must not be backed up.
func fakeRegistry(t *testing.T) (root, digest string) {
	root = t.TempDir()
	blob := []byte("layer data")
	sum := sha256.Sum256(blob)
	digest = hex.EncodeToString(sum[:])
	files := map[string]string{
		"blobs/sha256/" + digest[:2] + "/" + digest[2:]:    string(blob),
		"repositories/app/_manifests/tags/v1/current/link": "sha256:" + digest,
		"users.json":       `{"users":{}}`,
		"meta.json":        `{}`,
		"audit.log":        "{}\n",
		"uploads/abc/data": "partial upload",
		".rgstr.lock":      "pid 1",
		"users.json.tmp":   "half-written",
		"blobs/sha256/" + digest[:2] + "/.tmp-123": "temp",
	}
	for p, c := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		os.MkdirAll(filepath.Dir(full), 0755)
		if err := os.WriteFile(full, []byte(c), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root, digest
}

func TestBackupAndRestore(t *testing.T) {
	ctx := context.Background()
	root, digest := fakeRegistry(t)
	target := dirTarget(t.TempDir())

	obj, err := Create(ctx, root, "v1.8.0", target, time.Date(2026, 10, 27, 3, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if obj.Name != "rgstr-backup-20261027-030000.tar" || obj.Size == 0 {
		t.Fatalf("object: %+v", obj)
	}
	// Blobs come after everything else.
	f, _ := target.Get(ctx, obj.Name)
	tr := tar.NewReader(f)
	var names []string
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, h.Name)
	}
	f.Close()
	if names[0] != ManifestName || !strings.HasPrefix(names[len(names)-1], "blobs/") {
		t.Errorf("order: %v", names)
	}
	for _, n := range names {
		if strings.Contains(n, "uploads") || strings.Contains(n, "lock") || strings.Contains(n, "tmp") {
			t.Errorf("%s was backed up", n)
		}
	}

	dest := t.TempDir()
	if _, err := Restore(ctx, target, "latest", dest, false); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "blobs/sha256", digest[:2], digest[2:]))
	if err != nil || string(got) != "layer data" {
		t.Fatalf("restored blob: %q %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "users.json")); err != nil {
		t.Error("users.json not restored")
	}

	// A second restore needs -force and keeps the old data aside.
	if _, err := Restore(ctx, target, obj.Name, dest, false); err == nil {
		t.Error("restore over existing data without force")
	}
	if _, err := Restore(ctx, target, obj.Name, dest, true); err != nil {
		t.Fatal(err)
	}
	aside, _ := filepath.Glob(filepath.Join(dest, ".before-restore-*", "users.json"))
	if len(aside) != 1 {
		t.Errorf("old data not kept aside: %v", aside)
	}
}

func TestRestoreRejectsDamagedAndUnsafeArchives(t *testing.T) {
	ctx := context.Background()
	write := func(entries map[string]string, order []string) dirTarget {
		dir := dirTarget(t.TempDir())
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, n := range order {
			c := entries[n]
			tw.WriteHeader(&tar.Header{Name: n, Mode: 0644, Size: int64(len(c)), Typeflag: tar.TypeReg})
			tw.Write([]byte(c))
		}
		tw.Close()
		os.WriteFile(filepath.Join(string(dir), "rgstr-backup-20261027-030000.tar"), buf.Bytes(), 0644)
		return dir
	}
	man := `{"format":1}`
	bad := strings.Repeat("ab", 32)
	cases := map[string]dirTarget{
		"damaged blob": write(map[string]string{ManifestName: man, "blobs/sha256/ab/" + bad[2:]: "not it"},
			[]string{ManifestName, "blobs/sha256/ab/" + bad[2:]}),
		"path traversal": write(map[string]string{ManifestName: man, "../evil": "x"}, []string{ManifestName, "../evil"}),
		"absolute path":  write(map[string]string{ManifestName: man, "/etc/evil": "x"}, []string{ManifestName, "/etc/evil"}),
		"not a backup":   write(map[string]string{"users.json": "{}"}, []string{"users.json"}),
	}
	for name, target := range cases {
		dest := t.TempDir()
		if _, err := Restore(ctx, target, "latest", dest, false); err == nil {
			t.Errorf("%s: restored", name)
		}
		if entries, _ := dataEntries(dest); len(entries) > 0 {
			t.Errorf("%s: left %v behind", name, entries)
		}
	}
}

func TestRunnerKeepsNewest(t *testing.T) {
	root, _ := fakeRegistry(t)
	dir := t.TempDir()
	r, err := New(config.BackupConfig{Target: dir, Schedule: "0 3 * * *", Keep: 2}, root, "test")
	if err != nil {
		t.Fatal(err)
	}
	held := 0
	r.Hold = func() func() { held++; return func() {} }
	for i := 0; i < 3; i++ {
		if _, err := r.Run(context.Background(), ""); err != nil {
			t.Fatal(err)
		}
		time.Sleep(1100 * time.Millisecond) // names have second resolution
	}
	objs, _ := List(context.Background(), r.Target())
	if len(objs) != 2 || held != 3 {
		t.Errorf("kept %d backups, GC held %d times", len(objs), held)
	}
	if st := r.Status(); st.LastSuccess == nil || st.LastError != "" {
		t.Errorf("status: %+v", st)
	}
}
