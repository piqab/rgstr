package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"rgstr/internal/audit"
	"rgstr/internal/backup"
	"rgstr/internal/config"
	"rgstr/internal/db"
	"rgstr/internal/stats"
	"rgstr/internal/storage"
)

const usage = `rgstr — OCI/Docker container registry

Usage:
  rgstr                      run the registry (configured by RGSTR_* variables)
  rgstr backups              list the backups in RGSTR_BACKUP_TARGET
  rgstr backup               back up RGSTR_STORAGE now (rgstr must be stopped;
                             a running rgstr backs up on schedule or from the admin)
  rgstr restore [-force] NAME|latest
                             restore a backup into RGSTR_STORAGE (rgstr must be stopped)
  rgstr migrate [-force] -from DIR
                             copy a single-process registry (its data directory)
                             into the storage and database configured by
                             RGSTR_STORAGE_* and RGSTR_DATABASE_URL (cluster mode)
  rgstr version              print the version
`

// runCommand runs a subcommand; ok is false when args name none (then the
// registry starts).
func runCommand(args []string) (ok bool, code int) {
	if len(args) == 0 {
		return false, 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch args[0] {
	case "version", "-version", "--version", "-v":
		fmt.Println("rgstr", displayVersion(version))
		return true, 0
	case "help", "-h", "-help", "--help":
		fmt.Print(usage)
		return true, 0
	case "backups":
		return true, cmdBackups(ctx)
	case "backup":
		return true, cmdBackup(ctx)
	case "restore":
		return true, cmdRestore(ctx, args[1:])
	case "migrate":
		return true, cmdMigrate(ctx, args[1:])
	}
	fmt.Fprintf(os.Stderr, "rgstr: unknown command %q\n\n%s", args[0], usage)
	return true, 2
}

// singleProcess refuses commands that need the files of one process.
func singleProcess(cfg *config.Config) bool {
	if cfg.Cluster() || cfg.StorageDriver != "filesystem" {
		fmt.Fprintln(os.Stderr, "rgstr: backup and restore work on a single-process registry with the filesystem "+
			"driver; in a cluster back up the S3 bucket and PostgreSQL")
		return false
	}
	return true
}

func backupTarget(cfg *config.Config) (backup.Target, bool) {
	t, err := backup.NewTarget(cfg.Backup)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rgstr:", err)
		return nil, false
	}
	return t, true
}

func cmdBackups(ctx context.Context) int {
	t, ok := backupTarget(config.Load())
	if !ok {
		return 1
	}
	objs, err := backup.List(ctx, t)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rgstr:", err)
		return 1
	}
	for _, o := range objs {
		fmt.Printf("%s  %s  %d bytes\n", o.Name, o.Time.Format(time.RFC3339), o.Size)
	}
	if len(objs) == 0 {
		fmt.Fprintf(os.Stderr, "no backups in %s\n", t)
	}
	return 0
}

func cmdBackup(ctx context.Context) int {
	cfg := config.Load()
	if !singleProcess(cfg) {
		return 1
	}
	t, ok := backupTarget(cfg)
	if !ok {
		return 1
	}
	unlock, err := storage.Lock(cfg.StorageRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rgstr:", err)
		return 1
	}
	defer unlock()
	obj, err := backup.Create(ctx, cfg.StorageRoot, displayVersion(version), t, time.Now().UTC())
	if err != nil {
		fmt.Fprintln(os.Stderr, "rgstr: backup:", err)
		return 1
	}
	fmt.Printf("%s/%s  %d bytes\n", t, obj.Name, obj.Size)
	return 0
}

func cmdRestore(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	force := fs.Bool("force", false, "restore over existing data (moved to .before-restore-<time>/)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprint(os.Stderr, "usage: rgstr restore [-force] NAME|latest\n")
		return 2
	}
	cfg := config.Load()
	if !singleProcess(cfg) {
		return 1
	}
	t, ok := backupTarget(cfg)
	if !ok {
		return 1
	}
	if err := os.MkdirAll(cfg.StorageRoot, 0755); err != nil {
		fmt.Fprintln(os.Stderr, "rgstr:", err)
		return 1
	}
	unlock, err := storage.Lock(cfg.StorageRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rgstr:", err)
		return 1
	}
	defer unlock()
	name, err := backup.Restore(ctx, t, fs.Arg(0), cfg.StorageRoot, *force)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rgstr: restore:", err)
		return 1
	}
	fmt.Printf("restored %s into %s\n", name, cfg.StorageRoot)
	return 0
}

// cmdMigrate copies a single-process registry into a cluster: the files
// (blobs, manifests, tags, links) into the configured storage, and
// meta.json, users.json, stats.json and audit.log into PostgreSQL. It can
// be run again: files already copied are skipped.
func cmdMigrate(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("migrate", flag.ContinueOnError)
	from := flags.String("from", "", "data directory of the single-process registry (stopped)")
	force := flags.Bool("force", false, "replace metadata already in the database")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(os.Stderr, "rgstr: migrate: "+format+"\n", a...)
		return 1
	}
	cfg := config.Load()
	if *from == "" || !cfg.Cluster() {
		return fail("needs -from DIR and RGSTR_DATABASE_URL (and RGSTR_STORAGE_* for the target storage)")
	}
	unlock, err := storage.Lock(*from)
	if err != nil {
		return fail("%v", err)
	}
	defer unlock()
	database, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return fail("database: %v", err)
	}
	defer database.Close()

	// Metadata first: refuse to overwrite a cluster in use.
	for _, name := range []string{"meta", "users"} {
		if cur, err := database.Doc(name).Load(); err != nil {
			return fail("%v", err)
		} else if len(cur) > 2 && !*force {
			return fail("the database already holds %s; use -force to replace it", name)
		}
	}

	src := storage.NewFSDriver(*from)
	target, err := openStore(cfg)
	if err != nil {
		return fail("storage: %v", err)
	}
	dst := target.Driver()
	same := false
	if fd, ok := dst.(*storage.FSDriver); ok {
		a, _ := filepath.Abs(fd.Root())
		b, _ := filepath.Abs(*from)
		same = a == b // a shared volume used in place
	}
	if !same {
		var copied, skipped int
		var bytes int64
		for _, dir := range []string{"blobs", "repositories"} {
			err := src.Walk(ctx, dir, func(p string, info storage.FileInfo) error {
				if st, err := dst.Stat(ctx, p); err == nil && st.Size == info.Size {
					skipped++
					return nil
				}
				rc, err := src.Reader(ctx, p, 0)
				if err != nil {
					return err
				}
				defer rc.Close()
				w, err := dst.Writer(ctx, p)
				if err != nil {
					return err
				}
				if _, err := io.Copy(w, rc); err != nil {
					w.Cancel()
					return fmt.Errorf("%s: %w", p, err)
				}
				if err := w.Commit(); err != nil {
					return fmt.Errorf("%s: %w", p, err)
				}
				copied++
				bytes += info.Size
				if copied%500 == 0 {
					fmt.Printf("  %d files, %d bytes…\n", copied, bytes)
				}
				return nil
			})
			if err != nil {
				return fail("copy: %v", err)
			}
		}
		fmt.Printf("files: %d copied (%d bytes), %d already there\n", copied, bytes, skipped)
	}

	put := func(name, file string) error {
		raw, err := os.ReadFile(filepath.Join(*from, file))
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !json.Valid(raw) {
			return fmt.Errorf("%s is not valid JSON", file)
		}
		return database.Doc(name).Update(func([]byte) ([]byte, error) { return raw, nil })
	}
	if err := put("meta", "meta.json"); err != nil {
		return fail("%v", err)
	}
	if err := put("users", "users.json"); err != nil {
		return fail("%v", err)
	}
	if raw, err := os.ReadFile(filepath.Join(*from, "stats.json")); err == nil {
		var snap stats.Snapshot
		if json.Unmarshal(raw, &snap) == nil && len(snap.Pulls) > 0 {
			if err := database.SetPulls(ctx, snap.Pulls); err != nil {
				return fail("pull counts: %v", err)
			}
		}
	}
	alog, err := audit.Open(*from)
	if err != nil {
		return fail("audit log: %v", err)
	}
	entries, err := alog.Export()
	if err != nil {
		return fail("audit log: %v", err)
	}
	for i := 0; i < len(entries); i += 1000 {
		chunk := entries[i:min(i+1000, len(entries))]
		times := make([]time.Time, len(chunk))
		raws := make([][]byte, len(chunk))
		for j, e := range chunk {
			times[j] = e.Time
			raws[j], _ = json.Marshal(e)
		}
		if err := database.AddAudit(ctx, times, raws); err != nil {
			return fail("audit log: %v", err)
		}
	}
	fmt.Printf("metadata, users, pull counts and %d audit entries moved to the database\n", len(entries))
	fmt.Println("done: start the cluster with the same RGSTR_DATABASE_URL and RGSTR_STORAGE_* settings")
	return 0
}
