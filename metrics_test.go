// Integration test for /metrics.
package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"rgstr/internal/auth"
	"rgstr/internal/config"
	"rgstr/internal/registry"
	"rgstr/internal/stats"
	"rgstr/internal/storage"
)

func TestMetrics(t *testing.T) {
	cfg := &config.Config{
		AuthSecret: "s", AuthRealm: "http://localhost/v2/auth", AuthService: "test", AuthIssuer: "test",
		TokenTTL: time.Hour, GCInterval: time.Hour, UploadTTL: time.Hour, Users: map[string]string{},
		StorageRoot: t.TempDir(), Version: "v9.9.9", MetricsEnabled: true,
	}
	store, _ := storage.NewFilesystem(cfg.StorageRoot, cfg)
	reg := registry.New(store, auth.NewTokenService(cfg), cfg, stats.New(cfg.StorageRoot))
	mux := http.NewServeMux()
	reg.Mount(mux)
	srv := httptest.NewServer(reg.Handler(mux))
	defer srv.Close()

	pushImage(t, srv.URL, "app", "1", "amd64")
	status(t, "GET", srv.URL+"/v2/app/manifests/1", nil)
	// A ranged blob download goes through the instrumented writer.
	layer := pushBlob(t, srv.URL, "app", []byte("0123456789"))
	resp := do(t, "GET", srv.URL+"/v2/app/blobs/"+layer, nil, map[string]string{"Range": "bytes=2-4"})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent || string(body) != "234" {
		t.Errorf("range download through metrics: %d %q", resp.StatusCode, body)
	}
	postJSON(t, srv.URL+"/ui/api/gc/run", `{}`, nil).Body.Close()

	resp = do(t, "GET", srv.URL+"/metrics", nil, nil)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	out := string(raw)
	for _, want := range []string{
		`rgstr_build_info{version="v9.9.9"} 1`,
		`rgstr_events_total{action="push"} 1`,
		`rgstr_events_total{action="pull"} 1`,
		`rgstr_http_requests_total{method="GET",code="206"} 1`,
		`rgstr_repositories 1`,
		`rgstr_gc_runs_total{result="success"} 1`,
		"# TYPE rgstr_storage_bytes gauge",
		"rgstr_disk_free_bytes ",
		"rgstr_gc_last_run_timestamp_seconds ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q\n%s", want, out)
		}
	}
}

func TestMetricsDisabledByDefault(t *testing.T) {
	srv, _ := newTestServer(t)
	if code := status(t, "GET", srv.URL+"/metrics", nil); code == http.StatusOK {
		t.Errorf("/metrics served without RGSTR_METRICS_ENABLED")
	}
}
