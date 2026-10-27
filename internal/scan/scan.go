// Package scan finds vulnerabilities in images with Trivy. rgstr runs
// `trivy image` against itself (a pull with a one-off token), keeps the
// report next to the data (shared by a cluster through S3), and the
// projects' policies refuse pulls of vulnerable images.
package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"rgstr/internal/auth"
	"rgstr/internal/config"
	"rgstr/internal/storage"
)

// Subject is the token subject of the scanner's pulls.
const Subject = auth.ScannerSubject

// Statuses of a scan.
const (
	StatusRunning = "running"
	StatusDone    = "done"
	StatusError   = "error"
)

// Severities as Trivy reports them, from the worst.
var Severities = []string{"critical", "high", "medium", "low", "unknown"}

// Summary is the result of one scan.
type Summary struct {
	Status   string         `json:"status"`
	Started  time.Time      `json:"started"`
	Finished time.Time      `json:"finished,omitempty"`
	Error    string         `json:"error,omitempty"`
	Counts   map[string]int `json:"counts,omitempty"` // severity → vulnerabilities
	Fixable  int            `json:"fixable,omitempty"`
	OS       string         `json:"os,omitempty"`
	Scanner  string         `json:"scanner,omitempty"`
}

// Worst returns the most severe level with findings ("" for none).
func (s Summary) Worst() string {
	for _, sev := range Severities {
		if s.Counts[sev] > 0 {
			return sev
		}
	}
	return ""
}

// AtLeast counts the vulnerabilities of severity min or worse.
func (s Summary) AtLeast(min string) int {
	n := 0
	for _, sev := range Severities {
		n += s.Counts[sev]
		if sev == min {
			break
		}
	}
	return n
}

// Vulnerability is one finding.
type Vulnerability struct {
	ID        string `json:"id"`
	Severity  string `json:"severity"`
	Package   string `json:"package"`
	Installed string `json:"installed"`
	Fixed     string `json:"fixed,omitempty"`
	Title     string `json:"title,omitempty"`
	URL       string `json:"url,omitempty"`
	Target    string `json:"target,omitempty"`
}

// Report is a summary with its findings.
type Report struct {
	Summary
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Token issues a pull token for repo for the scanner.
type Token func(repo string) (string, error)

// Scanner runs scans in the background.
type Scanner struct {
	cfg    config.ScanConfig
	store  *storage.Store
	token  Token
	target string // host:port of this rgstr for trivy

	// Claim, when set, decides whether this process rescans now (in a
	// cluster, one process per interval does).
	Claim func(job string, interval time.Duration) bool
	// OnScan is told about every finished scan (metrics).
	OnScan func(err error)

	queue chan job

	dbMu sync.Mutex
	dbAt time.Time // last download of Trivy's databases

	mu     sync.Mutex
	queued map[string]bool          // digest → queued or running
	cache  map[string]cachedSummary // digest → summary, for pull checks
}

type job struct {
	repo   string
	digest storage.Digest
}

type cachedSummary struct {
	s  *Summary
	at time.Time
}

// New creates a scanner for the registry listening on cfg.ListenAddr.
func New(cfg *config.Config, store *storage.Store, token Token) *Scanner {
	sc := cfg.Scan
	if sc.Concurrency < 1 {
		sc.Concurrency = 1
	}
	if sc.CacheDir == "" {
		if fd, ok := store.Driver().(*storage.FSDriver); ok {
			sc.CacheDir = filepath.Join(fd.Root(), ".trivy")
		} else {
			sc.CacheDir = filepath.Join(os.TempDir(), "rgstr-trivy")
		}
	}
	return &Scanner{cfg: sc, store: store, token: token, target: selfAddr(cfg.ListenAddr),
		queue:  make(chan job, 10000),
		queued: map[string]bool{}, cache: map[string]cachedSummary{}}
}

// selfAddr is how trivy reaches this process.
func selfAddr(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "127.0.0.1:5000"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// Start runs the workers and the periodic rescan until ctx ends.
func (s *Scanner) Start(ctx context.Context) {
	for i := 0; i < s.cfg.Concurrency; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case j := <-s.queue:
					s.run(ctx, j)
				}
			}
		}()
	}
	if s.cfg.Interval > 0 {
		go func() {
			tick := time.NewTicker(time.Hour)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					if s.Claim == nil || s.Claim("rescan", s.cfg.Interval) {
						s.rescan()
					}
				}
			}
		}()
	}
}

// OnPush reports whether new images are scanned automatically.
func (s *Scanner) OnPush() bool { return s != nil && s.cfg.OnPush }

// Enqueue schedules a scan of repo@digest (an index: of its platforms).
func (s *Scanner) Enqueue(repo string, d storage.Digest) {
	if s == nil {
		return
	}
	m, err := s.store.GetManifest(repo, string(d))
	if err != nil {
		return
	}
	for _, child := range children(m.Content) {
		// Platforms of an index are scanned when they are stored (a
		// pull-through cache stores only those a client pulled).
		if _, err := s.store.GetManifest(repo, string(child)); err == nil {
			s.Enqueue(repo, child)
		}
	}
	if isIndex(m) {
		return
	}
	s.mu.Lock()
	if s.queued[string(d)] {
		s.mu.Unlock()
		return
	}
	s.queued[string(d)] = true
	s.mu.Unlock()
	select {
	case s.queue <- job{repo: repo, digest: d}:
	default:
		s.mu.Lock()
		delete(s.queued, string(d))
		s.mu.Unlock()
		log.Printf("scan: queue full, %s@%s not scanned now", repo, d)
	}
}

func isIndex(m *storage.Manifest) bool {
	if strings.Contains(m.ContentType, "index") || strings.Contains(m.ContentType, "manifest.list") {
		return true
	}
	var probe struct {
		Manifests []json.RawMessage `json:"manifests"`
	}
	return json.Unmarshal(m.Content, &probe) == nil && len(probe.Manifests) > 0
}

// children lists the platform manifests of an index.
func children(content []byte) []storage.Digest {
	var idx struct {
		Manifests []struct {
			Digest    storage.Digest `json:"digest"`
			MediaType string         `json:"mediaType"`
			Platform  *struct {
				OS string `json:"os"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if json.Unmarshal(content, &idx) != nil {
		return nil
	}
	var out []storage.Digest
	for _, m := range idx.Manifests {
		// Attestations (platform unknown/unknown) are not images.
		if m.Digest.Valid() && (m.Platform == nil || m.Platform.OS != "unknown") {
			out = append(out, m.Digest)
		}
	}
	return out
}

func summaryPath(d storage.Digest) string { return path.Join("scans", d.Hex(), "summary.json") }
func reportPath(d storage.Digest) string  { return path.Join("scans", d.Hex(), "report.json") }

// Summary returns the latest scan of digest, or nil.
func (s *Scanner) Summary(d storage.Digest) *Summary {
	if s == nil || !d.Valid() {
		return nil
	}
	s.mu.Lock()
	if c, ok := s.cache[string(d)]; ok && time.Since(c.at) < 30*time.Second {
		s.mu.Unlock()
		return c.s
	}
	s.mu.Unlock()
	var sum *Summary
	if raw, err := s.store.Driver().GetContent(context.Background(), summaryPath(d)); err == nil {
		var v Summary
		if json.Unmarshal(raw, &v) == nil {
			sum = &v
		}
	}
	s.mu.Lock()
	s.cache[string(d)] = cachedSummary{s: sum, at: time.Now()}
	if len(s.cache) > 50000 {
		s.cache = map[string]cachedSummary{}
	}
	s.mu.Unlock()
	return sum
}

// ImageSummary is the summary of an image: of the manifest itself, or for
// an index the worst of its scanned platforms combined.
func (s *Scanner) ImageSummary(repo string, d storage.Digest) *Summary {
	if s == nil {
		return nil
	}
	m, err := s.store.GetManifest(repo, string(d))
	if err != nil || !isIndex(m) {
		return s.Summary(d)
	}
	var out *Summary
	for _, child := range children(m.Content) {
		cs := s.Summary(child)
		if cs == nil {
			continue
		}
		if out == nil {
			out = &Summary{Status: StatusDone, Counts: map[string]int{}}
		}
		if cs.Status != StatusDone {
			out.Status = cs.Status
		}
		for k, v := range cs.Counts {
			out.Counts[k] = max(out.Counts[k], v)
		}
		out.Fixable = max(out.Fixable, cs.Fixable)
		if cs.Finished.After(out.Finished) {
			out.Finished, out.Scanner = cs.Finished, cs.Scanner
		}
	}
	return out
}

// Report returns the findings of digest's latest scan.
func (s *Scanner) Report(d storage.Digest) (*Report, error) {
	raw, err := s.store.Driver().GetContent(context.Background(), reportPath(d))
	if err != nil {
		return nil, err
	}
	var r Report
	return &r, json.Unmarshal(raw, &r)
}

func (s *Scanner) save(d storage.Digest, sum Summary, vulns []Vulnerability) {
	ctx := context.Background()
	if vulns != nil {
		raw, _ := json.Marshal(Report{Summary: sum, Vulnerabilities: vulns})
		if err := s.store.Driver().PutContent(ctx, reportPath(d), raw); err != nil {
			log.Printf("scan: save report: %v", err)
		}
	}
	raw, _ := json.Marshal(sum)
	if err := s.store.Driver().PutContent(ctx, summaryPath(d), raw); err != nil {
		log.Printf("scan: save summary: %v", err)
	}
	s.mu.Lock()
	s.cache[string(d)] = cachedSummary{s: &sum, at: time.Now()}
	s.mu.Unlock()
}

// run scans one image manifest.
func (s *Scanner) run(ctx context.Context, j job) {
	defer func() {
		s.mu.Lock()
		delete(s.queued, string(j.digest))
		s.mu.Unlock()
	}()
	sum := Summary{Status: StatusRunning, Started: time.Now().UTC()}
	s.save(j.digest, sum, nil)
	vulns, meta, err := s.trivy(ctx, j)
	sum.Finished = time.Now().UTC()
	if err != nil {
		sum.Status, sum.Error = StatusError, err.Error()
		log.Printf("scan: %s@%s: %v", j.repo, j.digest, err)
		s.save(j.digest, sum, nil)
	} else {
		sum.Status, sum.OS, sum.Scanner = StatusDone, meta.os, meta.scanner
		sum.Counts = map[string]int{}
		for _, v := range vulns {
			sum.Counts[v.Severity]++
			if v.Fixed != "" {
				sum.Fixable++
			}
		}
		s.save(j.digest, sum, vulns)
	}
	if s.OnScan != nil {
		s.OnScan(err)
	}
}

type trivyMeta struct{ os, scanner string }

// trivy runs `trivy image` on repo@digest of this registry.
func (s *Scanner) trivy(ctx context.Context, j job) ([]Vulnerability, trivyMeta, error) {
	var meta trivyMeta
	if err := os.MkdirAll(s.cfg.CacheDir, 0755); err != nil {
		return nil, meta, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	if err := s.updateDB(ctx); err != nil {
		return nil, meta, err
	}
	tok, err := s.token(j.repo)
	if err != nil {
		return nil, meta, err
	}
	// The databases are already here: Trivy must not fetch them now, as it
	// would send the registry token (meant for rgstr) to their registries.
	args := []string{"image", "--format", "json", "--quiet", "--scanners", "vuln",
		"--image-src", "remote", "--cache-dir", s.cfg.CacheDir, "--timeout", s.cfg.Timeout.String(),
		"--skip-db-update", "--skip-java-db-update"}
	if s.cfg.Server != "" {
		args = append(args, "--server", s.cfg.Server)
	}
	// The local address: plain HTTP, or TLS with a certificate for the
	// public name.
	args = append(args, "--insecure")
	args = append(args, s.target+"/"+j.repo+"@"+string(j.digest))
	// The token goes through the environment, not the command line.
	stdout, err := s.runTrivy(ctx, args, "TRIVY_REGISTRY_TOKEN="+tok)
	if err != nil {
		return nil, meta, err
	}
	vulns, meta, err := parse(stdout)
	if err != nil {
		return nil, meta, fmt.Errorf("trivy output: %w", err)
	}
	return vulns, meta, nil
}

// dbRefresh is how often Trivy's databases are downloaded again (Trivy
// publishes the vulnerability database every 6 hours).
const dbRefresh = 6 * time.Hour

// updateDB downloads Trivy's vulnerability and Java databases when they
// are missing or older than dbRefresh — without the registry token, which
// is for rgstr only. In client/server mode the server keeps the database.
func (s *Scanner) updateDB(ctx context.Context) error {
	if s.cfg.Server != "" {
		return nil
	}
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	if time.Since(s.dbAt) < dbRefresh {
		return nil
	}
	for _, flag := range []string{"--download-db-only", "--download-java-db-only"} {
		if _, err := s.runTrivy(ctx, []string{"image", flag, "--quiet", "--cache-dir", s.cfg.CacheDir}); err != nil {
			if !s.dbAt.IsZero() {
				log.Printf("scan: updating Trivy's database: %v (using the old one)", err)
				return nil
			}
			return fmt.Errorf("downloading Trivy's database: %w", err)
		}
	}
	s.dbAt = time.Now()
	return nil
}

// runTrivy runs trivy with args and extra environment; its standard
// output is returned.
func (s *Scanner) runTrivy(ctx context.Context, args []string, env ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, s.cfg.Trivy, args...)
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 2000 {
			msg = msg[len(msg)-2000:]
		}
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("trivy not found (%s): install it or set RGSTR_SCAN_TRIVY", s.cfg.Trivy)
		}
		return nil, fmt.Errorf("trivy: %v: %s", err, msg)
	}
	return stdout.Bytes(), nil
}

// parse reads Trivy's JSON report.
func parse(raw []byte) ([]Vulnerability, trivyMeta, error) {
	var meta trivyMeta
	var r struct {
		Metadata struct {
			OS *struct{ Family, Name string } `json:"OS"`
		} `json:"Metadata"`
		Trivy struct {
			Version string `json:"Version"`
		} `json:"Trivy"`
		Results []struct {
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				VulnerabilityID  string `json:"VulnerabilityID"`
				PkgName          string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
				FixedVersion     string `json:"FixedVersion"`
				Severity         string `json:"Severity"`
				Title            string `json:"Title"`
				PrimaryURL       string `json:"PrimaryURL"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, meta, err
	}
	if r.Metadata.OS != nil {
		meta.os = strings.TrimSpace(r.Metadata.OS.Family + " " + r.Metadata.OS.Name)
	}
	meta.scanner = "Trivy"
	if r.Trivy.Version != "" {
		meta.scanner += " " + r.Trivy.Version
	}
	vulns := []Vulnerability{}
	for _, res := range r.Results {
		for _, v := range res.Vulnerabilities {
			sev := strings.ToLower(v.Severity)
			if sev == "" {
				sev = "unknown"
			}
			vulns = append(vulns, Vulnerability{ID: v.VulnerabilityID, Severity: sev, Package: v.PkgName,
				Installed: v.InstalledVersion, Fixed: v.FixedVersion, Title: v.Title, URL: v.PrimaryURL, Target: res.Target})
		}
	}
	rank := map[string]int{}
	for i, s := range Severities {
		rank[s] = i
	}
	sort.SliceStable(vulns, func(a, b int) bool { return rank[vulns[a].Severity] < rank[vulns[b].Severity] })
	return vulns, meta, nil
}

// rescan queues the tagged images whose last scan is older than the
// interval (the vulnerability database has news by then).
func (s *Scanner) rescan() {
	repos, err := s.store.ListRepositories()
	if err != nil {
		return
	}
	for _, repo := range repos {
		tags, _ := s.store.RepoTags(repo)
		seen := map[storage.Digest]bool{}
		for _, t := range tags {
			if seen[t.Digest] {
				continue
			}
			seen[t.Digest] = true
			if sum := s.ImageSummary(repo, t.Digest); sum == nil || time.Since(sum.Finished) > s.cfg.Interval {
				s.Enqueue(repo, t.Digest)
			}
		}
	}
}
