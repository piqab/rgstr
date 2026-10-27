// Package ha tests rgstr as a cluster: several processes on S3 and
// PostgreSQL, under push and pull load, while processes are killed and
// restarted.
//
//	RGSTR_TEST_S3=http://localhost:19000 RGSTR_TEST_S3_KEY=… RGSTR_TEST_S3_SECRET=… \
//	RGSTR_TEST_DATABASE_URL=postgres://…?sslmode=disable go test ./test/ha -v
package ha

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const (
	nodes    = 3
	basePort = 15400
	admin    = "admin"
	adminPW  = "cluster-Passw0rd"
)

type cluster struct {
	t    *testing.T
	bin  string
	env  []string
	mu   sync.Mutex
	proc [nodes]*exec.Cmd
	logs string
}

func (c *cluster) url(i int) string { return fmt.Sprintf("http://127.0.0.1:%d", basePort+i) }

func (c *cluster) start(i int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f, _ := os.OpenFile(filepath.Join(c.logs, fmt.Sprintf("node%d.log", i)), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	cmd := exec.Command(c.bin)
	cmd.Env = append(c.env, fmt.Sprintf("RGSTR_ADDR=127.0.0.1:%d", basePort+i))
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		c.t.Fatal(err)
	}
	c.proc[i] = cmd
	go cmd.Wait()
}

func (c *cluster) kill(i int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p := c.proc[i]; p != nil {
		p.Process.Signal(syscall.SIGKILL)
		c.proc[i] = nil
	}
}

func (c *cluster) waitReady(i int) {
	for j := 0; j < 100; j++ {
		if resp, err := http.Get(c.url(i) + "/readyz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	c.t.Fatalf("node %d not ready; see %s", i, c.logs)
}

// do sends a request to node i, or to the next ones if a node is down (as
// a load balancer would). Connection errors are retried; HTTP answers are
// returned as they are.
func (c *cluster) do(i int, method, path string, body []byte, hdr map[string]string) (*http.Response, []byte, error) {
	var lastErr error
	for attempt := 0; attempt < 30; attempt++ {
		node := (i + attempt) % nodes
		req, _ := http.NewRequest(method, c.url(node)+path, bytes.NewReader(body))
		req.SetBasicAuth(admin, adminPW)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			var op *net.OpError
			if errors.As(err, &op) || errors.Is(err, io.EOF) || strings.Contains(err.Error(), "connection reset") {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return nil, nil, err
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil { // the node died while answering
			lastErr = err
			continue
		}
		return resp, b, nil
	}
	return nil, nil, lastErr
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func TestCluster(t *testing.T) {
	s3url, dburl := os.Getenv("RGSTR_TEST_S3"), os.Getenv("RGSTR_TEST_DATABASE_URL")
	if s3url == "" || dburl == "" {
		t.Skip("RGSTR_TEST_S3 and RGSTR_TEST_DATABASE_URL not set")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "rgstr")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = "../.."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	logs := dir
	if d := os.Getenv("RGSTR_TEST_HA_LOGS"); d != "" { // keep the node logs
		logs = d
		os.MkdirAll(d, 0755)
	}
	c := &cluster{t: t, bin: bin, logs: logs, env: append(os.Environ(),
		"RGSTR_STORAGE_DRIVER=s3",
		"RGSTR_STORAGE_S3_BUCKET="+envOr("RGSTR_TEST_S3_BUCKET", "rgstr-test"),
		"RGSTR_STORAGE_S3_PREFIX=ha-"+run,
		"RGSTR_STORAGE_S3_ENDPOINT="+s3url,
		"RGSTR_STORAGE_S3_ACCESS_KEY="+envOr("RGSTR_TEST_S3_KEY", "minioadmin"),
		"RGSTR_STORAGE_S3_SECRET_KEY="+envOr("RGSTR_TEST_S3_SECRET", "minioadmin"),
		"RGSTR_DATABASE_URL="+dburl,
		"RGSTR_AUTH_ENABLED=true",
		"RGSTR_AUTH_SECRET=cluster-secret",
		"RGSTR_USERS="+admin+":"+mustHash(t, adminPW),
		"RGSTR_ADMINS="+admin,
		"RGSTR_GC_INTERVAL=2s",
	)}
	t.Logf("logs in %s", logs)
	for i := 0; i < nodes; i++ {
		c.start(i)
	}
	for i := 0; i < nodes; i++ {
		c.waitReady(i)
	}
	t.Cleanup(func() {
		for i := 0; i < nodes; i++ {
			c.kill(i)
		}
	})

	sharedState(t, c, "carol-"+run)

	// Load: pushers and pullers on random nodes; a killer restarts nodes.
	var pushed sync.Map // repo:tag → content digest of the layer
	var pushes, pulls, retries, dataErrors atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	fail := func(format string, a ...any) {
		dataErrors.Add(1)
		t.Errorf(format, a...)
	}
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for n := 0; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				repo := fmt.Sprintf("load/app%d", w)
				tag := fmt.Sprintf("v%d", n)
				// A node dying mid-request fails that request; clients
				// (docker, containerd) then retry the push.
				var err error
				for attempt := 0; attempt < 5; attempt++ {
					if err = push(c, repo, tag); err == nil {
						break
					}
					retries.Add(1)
				}
				if err != nil {
					fail("push %s:%s: %v", repo, tag, err)
					continue
				}
				pushed.Store(repo+":"+tag, true)
				pushes.Add(1)
			}
		}(w)
	}
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				var keys []string
				pushed.Range(func(k, _ any) bool { keys = append(keys, k.(string)); return len(keys) < 200 })
				if len(keys) == 0 {
					time.Sleep(50 * time.Millisecond)
					continue
				}
				k := keys[mrand.IntN(len(keys))]
				repo, tag, _ := strings.Cut(k, ":")
				if err := pull(c, repo, tag); err != nil {
					fail("pull %s: %v", k, err)
					continue
				}
				pulls.Add(1)
			}
		}()
	}
	wg.Add(1)
	go func() { // kill -9 a random node every few seconds, restart it
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Duration(1500+mrand.IntN(1500)) * time.Millisecond):
			}
			i := mrand.IntN(nodes)
			c.kill(i)
			time.Sleep(time.Duration(200+mrand.IntN(800)) * time.Millisecond)
			c.start(i)
		}
	}()

	time.Sleep(envDuration("RGSTR_TEST_HA_DURATION", 40*time.Second))
	close(stop)
	wg.Wait()
	for i := 0; i < nodes; i++ {
		c.mu.Lock()
		down := c.proc[i] == nil
		c.mu.Unlock()
		if down {
			c.start(i)
		}
		c.waitReady(i)
	}

	// Everything pushed is still complete, read from every node.
	var checked int
	pushed.Range(func(k, _ any) bool {
		repo, tag, _ := strings.Cut(k.(string), ":")
		if err := pull(c, repo, tag); err != nil {
			fail("after the load: %s: %v", k, err)
		}
		checked++
		return true
	})
	t.Logf("pushes %d (push retries after a node died %d), pulls %d, verified at the end %d, data errors %d",
		pushes.Load(), retries.Load(), pulls.Load(), checked, dataErrors.Load())
	if pushes.Load() < 20 {
		t.Errorf("only %d pushes succeeded", pushes.Load())
	}
}

// sharedState checks that users and sessions are shared between nodes.
func sharedState(t *testing.T, c *cluster, user string) {
	resp, b, err := c.do(0, "POST", "/ui/api/users/create", mustJSON(map[string]any{
		"name": user, "role": "user", "password": "carol-Passw0rd", "must_change": false}), map[string]string{
		"Content-Type": "application/json", "Authorization": "Bearer " + uiToken(t, c, 0, admin, adminPW)})
	if err != nil || resp.StatusCode != 204 {
		t.Fatalf("create user on node 0: %v %s", err, b)
	}
	// Signed in on node 1 right away.
	tok := uiToken(t, c, 1, user, "carol-Passw0rd")
	// Signed out on node 2 ends the session on node 0.
	req, _ := http.NewRequest("POST", c.url(2)+"/ui/api/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 204 {
		t.Fatalf("logout on node 2: %v", err)
	}
	time.Sleep(300 * time.Millisecond) // the change notification
	req, _ = http.NewRequest("GET", c.url(0)+"/ui/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var me struct{ User string }
	json.NewDecoder(resp.Body).Decode(&me)
	resp.Body.Close()
	if me.User != "" {
		t.Error("session ended on node 2 still valid on node 0")
	}
}

func uiToken(t *testing.T, c *cluster, node int, user, pw string) string {
	resp, err := http.Post(c.url(node)+"/ui/api/login", "application/json",
		bytes.NewReader(mustJSON(map[string]string{"username": user, "password": pw})))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct{ Token string }
	json.NewDecoder(resp.Body).Decode(&body)
	if body.Token == "" {
		t.Fatalf("sign-in of %s on node %d failed: %d", user, node, resp.StatusCode)
	}
	return body.Token
}

// push uploads a random layer in up to three chunks, each to a different
// node, then the manifest to yet another.
func push(c *cluster, repo, tag string) error {
	layer := make([]byte, 64<<10+mrand.IntN(3<<20))
	rand.Read(layer)
	d := digest(layer)
	node := mrand.IntN(nodes)
	resp, b, err := c.do(node, "POST", "/v2/"+repo+"/blobs/uploads/", nil, nil)
	if err != nil || resp.StatusCode != 202 {
		return fmt.Errorf("start upload: %v %v %s", err, status(resp), b)
	}
	loc := resp.Header.Get("Location")
	parts := 1 + mrand.IntN(3)
	size := len(layer) / parts
	for p := 0; p < parts-1; p++ {
		node++
		chunk := layer[p*size : (p+1)*size]
		resp, b, err = c.do(node, "PATCH", loc, chunk, map[string]string{
			"Content-Type":  "application/octet-stream",
			"Content-Range": fmt.Sprintf("%d-%d", p*size, (p+1)*size-1)})
		if err != nil {
			return err
		}
		if resp.StatusCode == 416 {
			// The node that took the chunk died after storing it, before
			// answering: the client asks where the upload stands.
			return fmt.Errorf("chunk %d: 416 %s", p, b)
		}
		if resp.StatusCode != 202 {
			return fmt.Errorf("chunk %d: %v %s", p, status(resp), b)
		}
		loc = resp.Header.Get("Location")
	}
	node++
	sep := "?"
	if strings.Contains(loc, "?") {
		sep = "&"
	}
	resp, b, err = c.do(node, "PUT", loc+sep+"digest="+d, layer[(parts-1)*size:], map[string]string{
		"Content-Type": "application/octet-stream"})
	if err != nil || resp.StatusCode != 201 {
		return fmt.Errorf("finish upload: %v %v %s", err, status(resp), b)
	}
	manifest := mustJSON(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.empty.v1+json", "digest": d, "size": len(layer)},
		"layers": []any{map[string]any{"mediaType": "application/octet-stream", "digest": d, "size": len(layer)}},
	})
	node++
	resp, b, err = c.do(node, "PUT", "/v2/"+repo+"/manifests/"+tag, manifest, map[string]string{
		"Content-Type": "application/vnd.oci.image.manifest.v1+json"})
	if err != nil || resp.StatusCode != 201 {
		return fmt.Errorf("manifest: %v %v %s", err, status(resp), b)
	}
	return nil
}

// pull reads the manifest and its layer from random nodes and checks them.
func pull(c *cluster, repo, tag string) error {
	resp, b, err := c.do(mrand.IntN(nodes), "GET", "/v2/"+repo+"/manifests/"+tag, nil, map[string]string{
		"Accept": "application/vnd.oci.image.manifest.v1+json"})
	if err != nil || resp.StatusCode != 200 {
		return fmt.Errorf("manifest: %v %v %s", err, status(resp), b)
	}
	var m struct {
		Layers []struct {
			Digest string
			Size   int
		}
	}
	if err := json.Unmarshal(b, &m); err != nil || len(m.Layers) != 1 {
		return fmt.Errorf("manifest content: %v", err)
	}
	resp, b, err = c.do(mrand.IntN(nodes), "GET", "/v2/"+repo+"/blobs/"+m.Layers[0].Digest, nil, nil)
	if err != nil || resp.StatusCode != 200 {
		return fmt.Errorf("blob: %v %v", err, status(resp))
	}
	if digest(b) != m.Layers[0].Digest || len(b) != m.Layers[0].Size {
		return fmt.Errorf("blob content differs from its digest (%d bytes)", len(b))
	}
	return nil
}

func status(r *http.Response) any {
	if r == nil {
		return "no response"
	}
	return r.StatusCode
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func mustHash(t *testing.T, pw string) string {
	out, err := exec.Command("go", "run", "../../cmd/mkpasswd", "x", pw).Output()
	if err != nil {
		t.Fatalf("mkpasswd: %v", err)
	}
	// "RGSTR_USERS=x:$2a$..." or "x:$2a$..."
	s := strings.TrimSpace(string(out))
	s = s[strings.LastIndex(s, "x:")+2:]
	return strings.Trim(s, "'\"")
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envDuration(k string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(os.Getenv(k)); err == nil {
		return d
	}
	return def
}
