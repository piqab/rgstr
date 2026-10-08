// Package audit records who did what in the registry, as JSON lines in
// <storage>/audit.log (rotated to audit.log.1 at MaxSize).
package audit

import (
	"bufio"
	"encoding/json"
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
	GCRun          = "gc_run"
	GCSettings     = "gc_settings"
	RetentionRun   = "retention_run"
	PolicyChange   = "policy_change"
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

// ClientIP returns the client address of r. Behind a reverse proxy the
// first X-Forwarded-For address is used.
func ClientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	return ip
}
