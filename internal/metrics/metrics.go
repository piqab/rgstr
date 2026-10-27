// Package metrics exposes registry metrics in the Prometheus text format
// (RGSTR_METRICS_ENABLED). It has no dependencies: a handful of counters
// and gauges is all rgstr needs.
package metrics

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// counterVec is a counter with one label set per key.
type counterVec struct {
	mu     sync.Mutex
	values map[string]float64 // rendered label set → value
}

func (c *counterVec) add(labels string, v float64) {
	c.mu.Lock()
	if c.values == nil {
		c.values = map[string]float64{}
	}
	c.values[labels] += v
	c.mu.Unlock()
}

func (c *counterVec) snapshot() map[string]float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]float64, len(c.values))
	for k, v := range c.values {
		out[k] = v
	}
	return out
}

// Gauges reports values computed at scrape time.
type Gauges struct {
	Repositories   int
	StorageBytes   int64
	DiskTotalBytes uint64
	DiskFreeBytes  uint64
	DiskSupported  bool
	Uploads        int
	LastGC         time.Time
	Backups        bool      // backups configured
	LastBackup     time.Time // last successful backup
}

// Registry holds the process metrics.
type Registry struct {
	version  string
	gauges   func() Gauges
	requests counterVec // method, code
	events   counterVec // action
	gcRuns   counterVec // result
	gcFreed  counterVec
	backups  counterVec // result
}

// New creates a metrics registry. gauges is called on every scrape.
func New(version string, gauges func() Gauges) *Registry {
	return &Registry{version: version, gauges: gauges}
}

// Event counts an audit event (push, pull, login_failed, …).
func (r *Registry) Event(action string) {
	if r != nil {
		r.events.add(label("action", action), 1)
	}
}

// GCRun records a finished garbage collection run.
func (r *Registry) GCRun(bytesFreed int64, err error) {
	if r == nil {
		return
	}
	result := "success"
	if err != nil {
		result = "error"
	}
	r.gcRuns.add(label("result", result), 1)
	r.gcFreed.add("", float64(bytesFreed))
}

// BackupRun records a finished backup.
func (r *Registry) BackupRun(err error) {
	if r == nil {
		return
	}
	result := "success"
	if err != nil {
		result = "error"
	}
	r.backups.add(label("result", result), 1)
}

func label(pairs ...string) string {
	var b strings.Builder
	for i := 0; i+1 < len(pairs); i += 2 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(pairs[i])
		b.WriteString(`="`)
		b.WriteString(strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(pairs[i+1]))
		b.WriteByte('"')
	}
	return b.String()
}

// ServeHTTP writes the metrics in the Prometheus text exposition format.
func (r *Registry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	bw := bufio.NewWriter(w)
	defer bw.Flush()

	g := r.gauges()
	write(bw, "rgstr_build_info", "gauge", "Build information.", map[string]float64{label("version", r.version): 1})
	write(bw, "rgstr_http_requests_total", "counter", "HTTP requests by method and status code.", r.requests.snapshot())
	write(bw, "rgstr_events_total", "counter", "Audit events (push, pull, deletions, sign-ins, …) by action.", r.events.snapshot())
	write(bw, "rgstr_gc_runs_total", "counter", "Garbage collection runs by result.", r.gcRuns.snapshot())
	write(bw, "rgstr_gc_freed_bytes_total", "counter", "Bytes freed by garbage collection.", r.gcFreed.snapshot())
	write(bw, "rgstr_repositories", "gauge", "Repositories.", map[string]float64{"": float64(g.Repositories)})
	write(bw, "rgstr_storage_bytes", "gauge", "Bytes of blob data on disk.", map[string]float64{"": float64(g.StorageBytes)})
	write(bw, "rgstr_uploads_in_progress", "gauge", "Upload sessions not finished yet.", map[string]float64{"": float64(g.Uploads)})
	if g.DiskSupported {
		write(bw, "rgstr_disk_total_bytes", "gauge", "Size of the storage filesystem.", map[string]float64{"": float64(g.DiskTotalBytes)})
		write(bw, "rgstr_disk_free_bytes", "gauge", "Free space on the storage filesystem.", map[string]float64{"": float64(g.DiskFreeBytes)})
	}
	if g.Backups {
		write(bw, "rgstr_backup_runs_total", "counter", "Backups by result.", r.backups.snapshot())
		last := 0.0
		if !g.LastBackup.IsZero() {
			last = float64(g.LastBackup.Unix())
		}
		write(bw, "rgstr_backup_last_success_timestamp_seconds", "gauge", "Time of the last successful backup (0: none yet).",
			map[string]float64{"": last})
	}
	if !g.LastGC.IsZero() {
		write(bw, "rgstr_gc_last_run_timestamp_seconds", "gauge", "Start of the last garbage collection run.",
			map[string]float64{"": float64(g.LastGC.Unix())})
	}
}

func write(w io.Writer, name, typ, help string, values map[string]float64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := strconv.FormatFloat(values[k], 'f', -1, 64)
		if k == "" {
			fmt.Fprintf(w, "%s %s\n", name, v)
		} else {
			fmt.Fprintf(w, "%s{%s} %s\n", name, k, v)
		}
	}
}

// Instrument counts the requests next serves.
func (r *Registry) Instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rec := &recorder{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(rec, req)
		r.requests.add(label("method", method(req.Method), "code", strconv.Itoa(rec.code)), 1)
	})
}

// method bounds label cardinality to the methods a registry uses.
func method(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return m
	}
	return "OTHER"
}

// recorder captures the status code. It keeps the optional interfaces blob
// downloads and uploads rely on (Flusher, ReaderFrom for sendfile, Hijacker).
type recorder struct {
	http.ResponseWriter
	code        int
	wroteHeader bool
}

func (r *recorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.code, r.wroteHeader = code, true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	r.wroteHeader = true
	return r.ResponseWriter.Write(b)
}

func (r *recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *recorder) ReadFrom(src io.Reader) (int64, error) {
	r.wroteHeader = true
	if rf, ok := r.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	return io.Copy(r.ResponseWriter, src)
}

func (r *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
