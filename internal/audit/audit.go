// Package audit records who did what in the registry, as JSON lines in
// <storage>/audit.log (rotated to audit.log.1 at MaxSize).
package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Actions recorded in the log.
const (
	Push           = "push"
	Pull           = "pull"
	DeleteTag      = "delete_tag"
	DeleteImage    = "delete_image"
	DeleteRepo     = "delete_repo"
	Login          = "login"
	LoginFailed    = "login_failed"
	PasswordChange = "password_change"
	UserCreate     = "user_create"
	UserDelete     = "user_delete"
	UserRole       = "user_role"
	UserPassword   = "user_password_reset"
	CLISecret      = "cli_secret"
	GCRun          = "gc_run"
	GCSettings     = "gc_settings"
	BackupRun      = "backup_run"
	RetentionRun   = "retention_run"
	PolicyChange   = "policy_change"
	ProjectCreate  = "project_create"
	ProjectUpdate  = "project_update"
	ProjectDelete  = "project_delete"
	ProjectMember  = "project_member"
	RobotCreate    = "robot_create"
	RobotUpdate    = "robot_update"
	RobotSecret    = "robot_secret"
	RobotDelete    = "robot_delete"
	WebhookChange  = "webhook_change"
	WebhookDelete  = "webhook_delete"
)

// Entry is one audit record.
type Entry struct {
	Time     time.Time `json:"time"`
	User     string    `json:"user"` // "" = anonymous; "system" for scheduled jobs
	IP       string    `json:"ip,omitempty"`
	Action   string    `json:"action"`
	Resource string    `json:"resource,omitempty"` // repo:tag, repo@digest, user name…
	Detail   string    `json:"detail,omitempty"`
	Error    string    `json:"error,omitempty"` // set when the action failed
}

// MaxSize is the size at which audit.log is rotated.
const MaxSize = 10 << 20

// Log appends entries to the audit log.
type Log struct {
	path string // empty: in memory (tests)

	onAdd func(action string) // metrics hook; set before use

	mu   sync.Mutex
	f    *os.File
	size int64
	mem  []Entry
}

// Open opens <root>/audit.log for appending. An empty root keeps entries in
// memory.
func Open(root string) (*Log, error) {
	l := &Log{}
	if root == "" {
		return l, nil
	}
	l.path = filepath.Join(root, "audit.log")
	if err := l.openLocked(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Log) openLocked() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.f, l.size = f, fi.Size()
	return nil
}

// Add records e. The time is set if zero. Failures are logged, not
// returned: auditing must not break the operation it records.
func (l *Log) Add(e Entry) {
	if l == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if l.onAdd != nil {
		l.onAdd(e.Action)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.path == "" {
		l.mem = append(l.mem, e)
		return
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return
	}
	raw = append(raw, '\n')
	if l.size+int64(len(raw)) > MaxSize {
		l.rotateLocked()
	}
	if l.f == nil {
		return
	}
	n, err := l.f.Write(raw)
	l.size += int64(n)
	if err != nil {
		log.Printf("audit: write: %v", err)
	}
}

func (l *Log) rotateLocked() {
	if l.f != nil {
		l.f.Close()
		l.f = nil
	}
	if err := os.Rename(l.path, l.path+".1"); err != nil && !os.IsNotExist(err) {
		log.Printf("audit: rotate: %v", err)
	}
	if err := l.openLocked(); err != nil {
		log.Printf("audit: reopen: %v", err)
	}
}

// OnAdd calls fn with the action of every recorded entry (for metrics).
func (l *Log) OnAdd(fn func(action string)) { l.onAdd = fn }

// Query filters entries.
type Query struct {
	User   string    // exact user ("anonymous" matches "")
	Action string    // exact action
	Text   string    // case-insensitive substring of resource, detail, error or IP
	Before time.Time // only entries strictly before (for paging)
	Limit  int       // default 200
}

func (q Query) match(e Entry) bool {
	if q.User != "" {
		u := e.User
		if u == "" {
			u = "anonymous"
		}
		if u != q.User {
			return false
		}
	}
	if q.Action != "" && e.Action != q.Action {
		return false
	}
	if !q.Before.IsZero() && !e.Time.Before(q.Before) {
		return false
	}
	if q.Text != "" {
		hay := strings.ToLower(e.Resource + " " + e.Detail + " " + e.Error + " " + e.IP)
		if !strings.Contains(hay, strings.ToLower(q.Text)) {
			return false
		}
	}
	return true
}

// Find returns matching entries, newest first.
func (l *Log) Find(q Query) ([]Entry, error) {
	if q.Limit <= 0 {
		q.Limit = 200
	}
	var all []Entry
	l.mu.Lock()
	if l.path == "" {
		all = append(all, l.mem...)
		l.mu.Unlock()
	} else {
		l.mu.Unlock()
		for _, p := range []string{l.path + ".1", l.path} {
			entries, err := readFile(p)
			if err != nil {
				return nil, err
			}
			all = append(all, entries...)
		}
	}
	var out []Entry
	for i := len(all) - 1; i >= 0 && len(out) < q.Limit; i-- {
		if q.match(all[i]) {
			out = append(out, all[i])
		}
	}
	return out, nil
}

func readFile(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Entry
	rd := bufio.NewReader(f)
	for {
		line, err := rd.ReadBytes('\n')
		var e Entry
		if len(line) > 0 && json.Unmarshal(line, &e) == nil {
			out = append(out, e)
		}
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
	}
}

// DefaultTrustedProxies are the networks a reverse proxy usually runs in:
// loopback, private and link-local addresses.
var DefaultTrustedProxies = []string{
	"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"fc00::/7", "169.254.0.0/16", "fe80::/10",
}

var trusted = mustParseNets(DefaultTrustedProxies)

// TrustProxies sets the networks whose X-Forwarded-For header is believed.
// An empty list ignores the header entirely.
func TrustProxies(cidrs []string) error {
	nets, err := parseNets(cidrs)
	if err != nil {
		return err
	}
	trusted = nets
	return nil
}

func parseNets(cidrs []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, c := range cidrs {
		if !strings.Contains(c, "/") {
			if strings.Contains(c, ":") {
				c += "/128"
			} else {
				c += "/32"
			}
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", c, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func mustParseNets(cidrs []string) []*net.IPNet {
	nets, err := parseNets(cidrs)
	if err != nil {
		panic(err)
	}
	return nets
}

func isTrusted(ip string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	for _, n := range trusted {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

// ClientIP returns the client address of r. X-Forwarded-For is used only
// when the request comes from a trusted proxy; then the client is the
// rightmost address not belonging to a trusted proxy, so a client cannot
// forge its address by sending the header itself.
func ClientIP(r *http.Request) string {
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	fwd := r.Header.Values("X-Forwarded-For")
	if len(fwd) == 0 || !isTrusted(ip) {
		return ip
	}
	var hops []string
	for _, v := range fwd {
		for _, h := range strings.Split(v, ",") {
			if h = strings.TrimSpace(h); h != "" {
				hops = append(hops, h)
			}
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		if net.ParseIP(hops[i]) == nil {
			break // garbage: stop believing the chain
		}
		if !isTrusted(hops[i]) {
			return hops[i]
		}
		ip = hops[i]
	}
	return ip
}
