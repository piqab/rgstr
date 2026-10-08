package webhook

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"rgstr/internal/meta"
)

type receiver struct {
	mu     sync.Mutex
	bodies []map[string]interface{}
	auth   []string
	fail   int // respond 500 to the first fail requests
	srv    *httptest.Server
}

func newReceiver(t *testing.T) *receiver {
	rc := &receiver{}
	rc.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc.mu.Lock()
		defer rc.mu.Unlock()
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		rc.bodies = append(rc.bodies, body)
		rc.auth = append(rc.auth, r.Header.Get("Authorization"))
		if rc.fail > 0 {
			rc.fail--
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(rc.srv.Close)
	return rc
}

func (rc *receiver) wait(t *testing.T, n int) []map[string]interface{} {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rc.mu.Lock()
		got := len(rc.bodies)
		rc.mu.Unlock()
		if got >= n {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([]map[string]interface{}{}, rc.bodies...)
}

func setup(t *testing.T, hooks ...meta.Webhook) *Notifier {
	m, _ := meta.Open("")
	m.Update(func(d *meta.Data) error { d.Webhooks = hooks; return nil })
	return New(m, "reg.example.com")
}

func TestNotifyDefaultFormat(t *testing.T) {
	rc := newReceiver(t)
	n := setup(t,
		meta.Webhook{ID: "a", URL: rc.srv.URL, Events: []string{meta.EventPush}, Format: "default", AuthHeader: "Bearer x"},
		meta.Webhook{ID: "b", URL: rc.srv.URL, Project: "other", Events: []string{meta.EventPush}},
		meta.Webhook{ID: "c", URL: rc.srv.URL, Events: []string{meta.EventPush}, Disabled: true},
	)
	n.Notify(Event{Type: meta.EventPull, Repo: "team/app", Tag: "1"}) // nobody subscribes
	n.Notify(Event{Type: meta.EventPush, Operator: "alice", Repo: "team/app", Tag: "1", Digest: "sha256:abc"})
	got := rc.wait(t, 1)
	time.Sleep(100 * time.Millisecond)
	if len(rc.wait(t, 1)) != 1 {
		t.Fatalf("deliveries: %d, want 1 (project and disabled filters)", len(rc.bodies))
	}
	b := got[0]
	if b["type"] != "PUSH_ARTIFACT" || b["operator"] != "alice" {
		t.Errorf("payload: %v", b)
	}
	res := b["event_data"].(map[string]interface{})["resources"].([]interface{})[0].(map[string]interface{})
	if res["resource_url"] != "reg.example.com/team/app:1" || res["tag"] != "1" {
		t.Errorf("resource: %v", res)
	}
	if rc.auth[0] != "Bearer x" {
		t.Errorf("auth header: %q", rc.auth[0])
	}
	if d := n.Deliveries("a"); len(d) != 1 || d[0].Status != 200 {
		t.Errorf("deliveries record: %+v", d)
	}
}

func TestNotifySlackAndRetry(t *testing.T) {
	rc := newReceiver(t)
	rc.fail = 1
	n := setup(t, meta.Webhook{ID: "s", URL: rc.srv.URL, Events: []string{meta.EventDelete}, Format: "slack"})
	n.Notify(Event{Type: meta.EventDelete, Operator: "bob", Repo: "team/app", Detail: "repository"})
	got := rc.wait(t, 2)
	if len(got) != 2 {
		t.Fatalf("attempts: %d, want 2 (one retry)", len(got))
	}
	if got[1]["text"] != "bob deleted repository `team/app`" {
		t.Errorf("slack text: %v", got[1]["text"])
	}
	d := n.Deliveries("s")
	if len(d) != 2 || d[0].Error != "" || d[1].Error == "" || d[0].Attempt != 2 {
		t.Errorf("deliveries: %+v", d)
	}
}

func TestPing(t *testing.T) {
	n := setup(t)
	d := n.Test(meta.Webhook{ID: "x", URL: "http://127.0.0.1:1/unreachable", Format: "default"}, "alice")
	if d.Error == "" {
		t.Error("unreachable endpoint reported success")
	}
}
