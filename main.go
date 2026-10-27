package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"rgstr/internal/auth"
	"rgstr/internal/config"
	"rgstr/internal/db"
	"rgstr/internal/registry"
	"rgstr/internal/s3"
	"rgstr/internal/stats"
	"rgstr/internal/storage"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if ok, code := runCommand(os.Args[1:]); ok {
		os.Exit(code)
	}
	cfg := config.Load()
	cfg.Version = displayVersion(version)

	var database *db.DB
	if cfg.Cluster() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		var err error
		database, err = db.Open(ctx, cfg.DatabaseURL)
		cancel()
		if err != nil {
			log.Fatalf("database: %v", err)
		}
		defer database.Close()
	} else if cfg.StorageDriver == "filesystem" {
		// One process per data directory; a cluster coordinates through
		// the database instead.
		unlock, err := storage.Lock(cfg.StorageRoot)
		if err != nil {
			log.Fatalf("storage: %v", err)
		}
		defer unlock()
	}

	store, err := openStore(cfg)
	if err != nil {
		log.Fatalf("storage: %v", err)
	}
	if cfg.StorageDriver == "s3" && database == nil {
		log.Printf("storage: s3 without RGSTR_DATABASE_URL: run only one rgstr on this bucket")
	}

	tokenSvc := auth.NewTokenService(cfg)
	var counter *stats.Counter
	if database != nil {
		counter = stats.NewShared(database)
	} else {
		counter = stats.New(cfg.StorageRoot)
	}
	reg := registry.NewCluster(store, tokenSvc, cfg, counter, database)

	mux := http.NewServeMux()
	reg.Mount(mux)

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      reg.Handler(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // streaming blobs must not time out
		IdleTimeout:  120 * time.Second,
	}

	gcCtx, gcCancel := context.WithCancel(context.Background())
	defer gcCancel()
	reg.Start(gcCtx)

	where := cfg.StorageRoot
	if cfg.StorageDriver == "s3" {
		where = "s3://" + cfg.StorageS3.Bucket + "/" + cfg.StorageS3.Prefix
	}
	log.Printf("rgstr %s listening on %s  storage=%s  auth=%v  cluster=%v",
		cfg.Version, cfg.ListenAddr, where, cfg.AuthEnabled, database != nil)

	go func() {
		var serveErr error
		if cfg.TLSCert != "" {
			serveErr = srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			serveErr = srv.ListenAndServe()
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			log.Fatalf("server: %v", serveErr)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	log.Println("stopped")
}

// openStore opens the storage driver of cfg.
func openStore(cfg *config.Config) (*storage.Store, error) {
	switch cfg.StorageDriver {
	case "filesystem":
		return storage.NewFilesystem(cfg.StorageRoot, cfg)
	case "s3":
		c, err := s3.New(cfg.StorageS3.S3, cfg.StorageS3.Bucket)
		if err != nil {
			return nil, fmt.Errorf("RGSTR_STORAGE_S3_*: %w", err)
		}
		return storage.New(storage.NewS3Driver(c, cfg.StorageS3.Prefix, cfg.StorageS3.Redirect), cfg), nil
	}
	return nil, fmt.Errorf("RGSTR_STORAGE_DRIVER %q: want filesystem or s3", cfg.StorageDriver)
}

// displayVersion adds the "v" prefix to numeric versions ("1.5.0" → "v1.5.0").
func displayVersion(v string) string {
	if v != "" && v[0] >= '0' && v[0] <= '9' {
		return "v" + v
	}
	return v
}
