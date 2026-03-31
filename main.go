package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"rgstr/internal/auth"
	"rgstr/internal/config"
	"rgstr/internal/registry"
	"rgstr/internal/stats"
	"rgstr/internal/storage"
)

func main() {
	cfg := config.Load()

	store, err := storage.NewFilesystem(cfg.StorageRoot, cfg)
	if err != nil {
		log.Fatalf("storage init: %v", err)
	}

	tokenSvc := auth.NewTokenService(cfg)
	counter := stats.New(cfg.StorageRoot)
	reg := registry.New(store, tokenSvc, cfg, counter)

	mux := http.NewServeMux()
	reg.Mount(mux)

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // streaming blobs must not time out
		IdleTimeout:  120 * time.Second,
	}

	gcCtx, gcCancel := context.WithCancel(context.Background())
	defer gcCancel()
	go store.GCLoop(gcCtx, cfg.GCInterval)

	log.Printf("rgstr listening on %s  storage=%s  auth=%v",
		cfg.ListenAddr, cfg.StorageRoot, cfg.AuthEnabled)

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
