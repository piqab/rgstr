package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"rgstr/internal/backup"
	"rgstr/internal/config"
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
	}
	fmt.Fprintf(os.Stderr, "rgstr: unknown command %q\n\n%s", args[0], usage)
	return true, 2
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
