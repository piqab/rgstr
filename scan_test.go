package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"rgstr/internal/config"
)

// fakeTrivy behaves like `trivy image` for the scanner: it pulls the
// manifest from rgstr with the token it was given and prints a report.
const fakeTrivy = `#!/bin/sh
case "$*" in *--download-db-only*|*--download-java-db-only*)
  # The databases come from other registries: the rgstr token must not be sent there.
  [ -z "$TRIVY_REGISTRY_TOKEN" ] || { echo "registry token leaked to the database download" >&2; exit 3; }
  exit 0;;
esac
for a; do last=$a; done
case "$*" in *"--image-src remote"*"--skip-db-update"*"--skip-java-db-update"*"--insecure"*) ;; *) echo "unexpected arguments: $*" >&2; exit 2;; esac
host=${last%%/*}; rest=${last#*/}; repo=${rest%@*}; dg=${rest#*@}
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TRIVY_REGISTRY_TOKEN" \
  -H 'Accept: application/vnd.oci.image.manifest.v1+json' "http://$host/v2/$repo/manifests/$dg")
[ "$code" = 200 ] || { echo "pull failed: $code" >&2; exit 1; }
cat <<JSON
{"SchemaVersion":2,"Trivy":{"Version":"0.0.0-fake"},"Metadata":{"OS":{"Family":"alpine","Name":"3.20.3"}},
 "Results":[{"Target":"img (alpine 3.20.3)","Vulnerabilities":[
  {"VulnerabilityID":"CVE-2024-0001","PkgName":"openssl","InstalledVersion":"3.0.0","FixedVersion":"3.0.1","Severity":"HIGH","Title":"bad","PrimaryURL":"https://avd.aquasec.com/nvd/cve-2024-0001"},
  {"VulnerabilityID":"CVE-2024-0002","PkgName":"zlib","InstalledVersion":"1.2","Severity":"LOW"}]}]}
JSON
`

func TestScanning(t *testing.T) {
	dir := t.TempDir()
	trivy := filepath.Join(dir, "trivy")
	if err := os.WriteFile(trivy, []byte(fakeTrivy), 0755); err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	srv, _ := newRegistry(t, func(c *config.Config) {
		c.AuthEnabled = true
		c.Users = map[string]string{"alice": string(hash)}
		c.Admins = []string{"alice"}
		c.Scan = config.ScanConfig{Enabled: true, Trivy: trivy, OnPush: true, Concurrency: 1,
			Timeout: time.Minute, CacheDir: filepath.Join(dir, "cache")}
	})
	basic := func(req *http.Request) { req.SetBasicAuth("alice", "pw") }
	call := func(method, path string, body []byte, hdr map[string]string) (*http.Response, []byte) {
		req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
		basic(req)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, b
	}
	// The project refuses images with high or critical vulnerabilities.
	if resp, b := call("POST", "/ui/api/projects/create", []byte(`{"name":"team","block_severity":"high"}`),
		map[string]string{"Content-Type": "application/json"}); resp.StatusCode != 204 {
		t.Fatalf("create project: %d %s", resp.StatusCode, b)
	}

	layer := []byte("vulnerable layer")
	resp, _ := call("POST", "/v2/team/app/blobs/uploads/", nil, nil)
	resp, _ = call("PUT", resp.Header.Get("Location")+"?digest="+digest(layer), layer, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("blob: %d", resp.StatusCode)
	}
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[{"digest":"` + digest(layer) + `","size":16}]}`)
	resp, _ = call("PUT", "/v2/team/app/manifests/1.0", manifest, map[string]string{"Content-Type": "application/vnd.oci.image.manifest.v1+json"})
	if resp.StatusCode != 201 {
		t.Fatalf("manifest: %d", resp.StatusCode)
	}
	md := resp.Header.Get("Docker-Content-Digest")

	// The push queued a scan; the fake trivy pulled with the scanner token.
	var scan struct {
		Summary *struct {
			Status string
			Error  string
			Counts map[string]int
			OS     string
		}
		Report *struct {
			Vulnerabilities []struct{ ID, Severity, Package, Fixed string }
		}
	}
	tok := uiLogin(t, srv.URL, "alice", "pw")
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", srv.URL+"/ui/api/scan?repo=team/app&ref=1.0", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		json.NewDecoder(r.Body).Decode(&scan)
		r.Body.Close()
		if scan.Summary != nil && scan.Summary.Status != "running" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if scan.Summary == nil || scan.Summary.Status != "done" {
		t.Fatalf("scan: %+v", scan.Summary)
	}
	if scan.Summary.Counts["high"] != 1 || scan.Summary.Counts["low"] != 1 || scan.Summary.OS != "alpine 3.20.3" ||
		len(scan.Report.Vulnerabilities) != 2 || scan.Report.Vulnerabilities[0].ID != "CVE-2024-0001" {
		t.Errorf("report: %+v %+v", scan.Summary, scan.Report)
	}

	// Pulls are refused by the policy; the message says why.
	resp, body := call("GET", "/v2/team/app/manifests/1.0", nil, nil)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "vulnerabilities") {
		t.Errorf("pull of a vulnerable image: %d %s", resp.StatusCode, body)
	}
	// Only critical refused now: the high one passes.
	setBlock(t, srv.URL, tok, "critical")
	time.Sleep(10 * time.Millisecond)
	if resp, _ = call("GET", "/v2/team/app/manifests/"+md, nil, nil); resp.StatusCode != 200 {
		t.Errorf("pull with a critical-only policy: %d", resp.StatusCode)
	}
}

func uiLogin(t *testing.T, url, user, pw string) string {
	resp, err := http.Post(url+"/ui/api/login", "application/json",
		strings.NewReader(`{"username":"`+user+`","password":"`+pw+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b struct{ Token string }
	json.NewDecoder(resp.Body).Decode(&b)
	return b.Token
}

func setBlock(t *testing.T, url, tok, sev string) {
	req, _ := http.NewRequest("POST", url+"/ui/api/projects/update",
		strings.NewReader(`{"name":"team","description":"","public":false,"block_severity":"`+sev+`"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 204 {
		t.Fatalf("set policy: %v %v", err, resp.StatusCode)
	}
	resp.Body.Close()
}
