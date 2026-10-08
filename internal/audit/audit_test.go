package audit

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAddFind(t *testing.T) {
	l, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.Add(Entry{Time: base, User: "alice", Action: Push, Resource: "app:1"})
	l.Add(Entry{Time: base.Add(time.Second), Action: Pull, Resource: "app:1", IP: "10.0.0.5"})
	l.Add(Entry{Time: base.Add(2 * time.Second), User: "bob", Action: DeleteTag, Resource: "app:1", Error: "tag is immutable"})

	all, _ := l.Find(Query{})
	if len(all) != 3 || all[0].User != "bob" {
		t.Fatalf("newest first: %+v", all)
	}
	if got, _ := l.Find(Query{User: "anonymous"}); len(got) != 1 || got[0].Action != Pull {
		t.Errorf("anonymous filter: %+v", got)
	}
	if got, _ := l.Find(Query{Action: Push}); len(got) != 1 {
		t.Errorf("action filter: %+v", got)
	}
	if got, _ := l.Find(Query{Text: "IMMUTABLE"}); len(got) != 1 {
		t.Errorf("text filter on error: %+v", got)
	}
	if got, _ := l.Find(Query{Text: "10.0.0"}); len(got) != 1 {
		t.Errorf("text filter on IP: %+v", got)
	}
	if got, _ := l.Find(Query{Before: base.Add(2 * time.Second), Limit: 1}); len(got) != 1 || got[0].Action != Pull {
		t.Errorf("paging: %+v", got)
	}
}

func TestRotation(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(dir)
	big := strings.Repeat("x", 1<<20)
	for i := 0; i < 12; i++ {
		l.Add(Entry{Action: Push, Detail: big})
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.log.1")); err != nil {
		t.Fatalf("no rotated file: %v", err)
	}
	fi, _ := os.Stat(filepath.Join(dir, "audit.log"))
	if fi.Size() > MaxSize {
		t.Errorf("audit.log is %d bytes, over the limit", fi.Size())
	}
	if got, _ := l.Find(Query{Limit: 100}); len(got) != 12 {
		t.Errorf("entries across files: %d want 12", len(got))
	}
}

func TestNilLog(t *testing.T) {
	var l *Log
	l.Add(Entry{Action: Push}) // must not panic
}

func TestClientIP(t *testing.T) {
	defer TrustProxies(DefaultTrustedProxies)
	req := func(remote string, xff ...string) *http.Request {
		r, _ := http.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		for _, v := range xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		return r
	}
	cases := []struct {
		name string
		r    *http.Request
		want string
	}{
		{"direct", req("203.0.113.7:5555"), "203.0.113.7"},
		{"direct client forging the header", req("203.0.113.7:5555", "1.2.3.4"), "203.0.113.7"},
		{"behind proxy", req("172.17.0.1:5555", "198.51.100.9"), "198.51.100.9"},
		{"forged hop before the real client", req("127.0.0.1:1", "1.2.3.4, 198.51.100.9"), "198.51.100.9"},
		{"two proxies", req("10.0.0.2:1", "198.51.100.9, 10.0.0.1"), "198.51.100.9"},
		{"garbage", req("10.0.0.2:1", "not-an-ip"), "10.0.0.2"},
		{"ipv6", req("[::1]:1", "2001:db8::5"), "2001:db8::5"},
	}
	for _, c := range cases {
		if got := ClientIP(c.r); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
	TrustProxies(nil)
	if got := ClientIP(req("172.17.0.1:5555", "198.51.100.9")); got != "172.17.0.1" {
		t.Errorf("no trusted proxies: got %s", got)
	}
	if err := TrustProxies([]string{"bogus"}); err == nil {
		t.Error("accepted bogus CIDR")
	}
}
