// Package webhook delivers registry events to configured HTTP endpoints.
package webhook

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"rgstr/internal/meta"
)

// Event is something that happened in the registry.
type Event struct {
	Type     string // meta.Event* or "ping"
	Time     time.Time
	Operator string
	Repo     string
	Tag      string
	Digest   string
	Detail   string // e.g. the quota error, or "repository" for a repository delete
}

// Delivery records one attempt to deliver an event.
type Delivery struct {
	Time       time.Time `json:"time"`
	Event      string    `json:"event"`
	Resource   string    `json:"resource,omitempty"`
	Status     int       `json:"status"`
	Error      string    `json:"error,omitempty"`
	Attempt    int       `json:"attempt"`
	DurationMs int64     `json:"duration_ms"`
}

const (
	maxDeliveries = 20
	attempts      = 3
	queueSize     = 1000
	workers       = 4
)

// Notifier queues events and posts them to matching webhooks.
type Notifier struct {
	meta *meta.Store
	host string // registry host for resource URLs, e.g. registry.example.com

	queue chan job

	mu         sync.Mutex
	deliveries map[string][]Delivery // webhook ID → newest first
}

type job struct {
	hook  meta.Webhook
	event Event
}

// New starts a notifier. host is how clients address the registry.
func New(m *meta.Store, host string) *Notifier {
	n := &Notifier{meta: m, host: host, queue: make(chan job, queueSize), deliveries: map[string][]Delivery{}}
	for i := 0; i < workers; i++ {
		go n.worker()
	}
	return n
}

// Notify queues e for every enabled webhook that subscribes to it. It
// never blocks: when the queue is full the event is dropped and logged.
func (n *Notifier) Notify(e Event) {
	if n == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	project := meta.ProjectOf(e.Repo)
	var hooks []meta.Webhook
	n.meta.View(func(d *meta.Data) {
		for _, h := range d.Webhooks {
			if !h.Disabled && (h.Project == "" || h.Project == project) && contains(h.Events, e.Type) {
				hooks = append(hooks, h)
			}
		}
	})
	for _, h := range hooks {
		select {
		case n.queue <- job{h, e}:
		default:
			log.Printf("webhook %s: queue full, dropped %s event", h.Name, e.Type)
		}
	}
}

// Test sends a ping event to hook now and returns the result.
func (n *Notifier) Test(hook meta.Webhook, operator string) Delivery {
	d := n.send(hook, Event{Type: "ping", Time: time.Now().UTC(), Operator: operator}, 1)
	n.record(hook.ID, d)
	return d
}

// Deliveries returns recent deliveries of a webhook, newest first.
func (n *Notifier) Deliveries(id string) []Delivery {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]Delivery{}, n.deliveries[id]...)
}

func (n *Notifier) worker() {
	for j := range n.queue {
		backoff := time.Second
		for attempt := 1; attempt <= attempts; attempt++ {
			d := n.send(j.hook, j.event, attempt)
			n.record(j.hook.ID, d)
			if d.Error == "" {
				break
			}
			time.Sleep(backoff)
			backoff *= 4
		}
	}
}

func (n *Notifier) record(id string, d Delivery) {
	n.mu.Lock()
	defer n.mu.Unlock()
	list := append([]Delivery{d}, n.deliveries[id]...)
	if len(list) > maxDeliveries {
		list = list[:maxDeliveries]
	}
	n.deliveries[id] = list
}

func (n *Notifier) send(h meta.Webhook, e Event, attempt int) Delivery {
	d := Delivery{Time: time.Now().UTC(), Event: e.Type, Resource: n.resource(e), Attempt: attempt}
	body, err := n.payload(h.Format, e)
	if err != nil {
		d.Error = err.Error()
		return d
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		d.Error = err.Error()
		return d
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "rgstr-webhook")
	if h.AuthHeader != "" {
		req.Header.Set("Authorization", h.AuthHeader)
	}
	client := http.DefaultClient
	if h.SkipVerify {
		client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	}
	start := time.Now()
	resp, err := client.Do(req)
	d.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		d.Error = err.Error()
		return d
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	d.Status = resp.StatusCode
	if resp.StatusCode >= 300 {
		d.Error = resp.Status
	}
	return d
}

// resource is the image reference an event is about.
func (n *Notifier) resource(e Event) string {
	if e.Repo == "" {
		return ""
	}
	ref := e.Repo
	switch {
	case e.Tag != "":
		ref += ":" + e.Tag
	case e.Digest != "":
		ref += "@" + e.Digest
	}
	if n.host != "" {
		ref = n.host + "/" + ref
	}
	return ref
}

var eventTypes = map[string]string{
	meta.EventPush:          "PUSH_ARTIFACT",
	meta.EventPull:          "PULL_ARTIFACT",
	meta.EventDelete:        "DELETE_ARTIFACT",
	meta.EventQuotaExceeded: "QUOTA_EXCEED",
	"ping":                  "PING",
}

func (n *Notifier) payload(format string, e Event) ([]byte, error) {
	if format == "slack" {
		return json.Marshal(map[string]string{"text": n.text(e)})
	}
	namespace, name := "", e.Repo
	if i := strings.IndexByte(e.Repo, '/'); i > 0 {
		namespace, name = e.Repo[:i], e.Repo[i+1:]
	}
	data := map[string]interface{}{}
	if e.Repo != "" {
		data["resources"] = []map[string]string{{
			"digest": e.Digest, "tag": e.Tag, "resource_url": n.resource(e),
		}}
		data["repository"] = map[string]string{
			"name": name, "namespace": namespace, "repo_full_name": e.Repo,
		}
	}
	if e.Detail != "" {
		data["detail"] = e.Detail
	}
	return json.Marshal(map[string]interface{}{
		"type":       eventTypes[e.Type],
		"occur_at":   e.Time.Unix(),
		"operator":   operator(e),
		"event_data": data,
	})
}

func (n *Notifier) text(e Event) string {
	who := operator(e)
	ref := "`" + n.resource(e) + "`"
	switch e.Type {
	case meta.EventPush:
		return fmt.Sprintf("%s pushed %s", who, ref)
	case meta.EventPull:
		return fmt.Sprintf("%s pulled %s", who, ref)
	case meta.EventDelete:
		if e.Detail == "repository" {
			return fmt.Sprintf("%s deleted repository `%s`", who, e.Repo)
		}
		return fmt.Sprintf("%s deleted %s", who, ref)
	case meta.EventQuotaExceeded:
		return fmt.Sprintf("Push of %s by %s was refused: %s", ref, who, e.Detail)
	default:
		return fmt.Sprintf("rgstr webhook test from %s", who)
	}
}

func operator(e Event) string {
	if e.Operator == "" {
		return "anonymous"
	}
	return e.Operator
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
