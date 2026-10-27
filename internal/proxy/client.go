// Package proxy makes projects pull-through caches of other registries
// (Docker Hub, GHCR, Quay, …): a pull that misses the cache fetches the
// image from the upstream registry, stores it and serves it; later pulls
// are served locally.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrNotFound is the upstream's 404.
var ErrNotFound = errors.New("not found upstream")

// UpstreamError is an unexpected status from the upstream registry.
type UpstreamError struct {
	Status int
	Body   string
}

func (e *UpstreamError) Error() string {
	return fmt.Sprintf("upstream answered %d: %s", e.Status, e.Body)
}

// manifestTypes are accepted from the upstream on top of what the client
// asked for, so indexes (multi-platform images) are cached as such.
var manifestTypes = []string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}

// client talks to one upstream registry, following the Docker token
// authentication: a 401 with a Bearer challenge is answered by fetching a
// token (anonymously or with the configured credentials) from the realm.
type client struct {
	base     *url.URL // https://registry-1.docker.io
	user     string
	password string
	http     *http.Client

	mu     sync.Mutex
	tokens map[string]token // scope → token
}

type token struct {
	value   string
	expires time.Time
}

func newClient(upstream, user, password string) (*client, error) {
	u, err := url.Parse(strings.TrimSuffix(upstream, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("upstream %q: want https://host", upstream)
	}
	return &client{base: u, user: user, password: password, tokens: map[string]token{},
		http: &http.Client{Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConnsPerHost:   32,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: time.Minute,
			TLSHandshakeTimeout:   10 * time.Second,
		}}}, nil
}

// isDockerHub reports whether the upstream is Docker Hub, where
// single-segment names live under "library/".
func (c *client) isDockerHub() bool {
	h := c.base.Hostname()
	return h == "registry-1.docker.io" || h == "docker.io" || h == "index.docker.io" || h == "registry.hub.docker.com"
}

// remoteName maps the name within the project to the upstream name.
func (c *client) remoteName(name string) string {
	if c.isDockerHub() && !strings.Contains(name, "/") {
		return "library/" + name
	}
	return name
}

// do sends a request for repo (pull scope), authenticating as needed.
func (c *client) do(ctx context.Context, method, repo, path string, hdr http.Header) (*http.Response, error) {
	scope := "repository:" + repo + ":pull"
	send := func(auth string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, c.base.String()+path, nil)
		if err != nil {
			return nil, err
		}
		for k, v := range hdr {
			req.Header[k] = v
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		return c.http.Do(req)
	}
	resp, err := send(c.cachedAuth(scope))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	resp.Body.Close()
	auth, err := c.authenticate(ctx, challenge, scope)
	if err != nil {
		return nil, err
	}
	return send(auth)
}

func (c *client) cachedAuth(scope string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.tokens[scope]; ok && time.Now().Before(t.expires) {
		return "Bearer " + t.value
	}
	return "" // the first answer's challenge tells how to authenticate
}

// authenticate answers a WWW-Authenticate challenge.
func (c *client) authenticate(ctx context.Context, challenge, scope string) (string, error) {
	scheme, params := parseChallenge(challenge)
	switch strings.ToLower(scheme) {
	case "basic":
		if c.user == "" {
			return "", errors.New("upstream needs credentials")
		}
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		req.SetBasicAuth(c.user, c.password)
		return req.Header.Get("Authorization"), nil
	case "bearer":
	default:
		return "", fmt.Errorf("upstream authentication %q not supported", scheme)
	}
	realm, err := url.Parse(params["realm"])
	if err != nil || realm.Host == "" {
		return "", fmt.Errorf("bad token realm %q", params["realm"])
	}
	q := realm.Query()
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	q.Set("scope", scope)
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", err
	}
	if c.user != "" {
		req.SetBasicAuth(c.user, c.password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("upstream token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("upstream token: %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", fmt.Errorf("upstream token: %w", err)
	}
	t := body.Token
	if t == "" {
		t = body.AccessToken
	}
	if t == "" {
		return "", errors.New("upstream token: empty")
	}
	ttl := time.Duration(body.ExpiresIn) * time.Second
	if ttl < time.Minute {
		ttl = time.Minute // the spec's default is 60 s
	}
	c.mu.Lock()
	c.tokens[scope] = token{value: t, expires: time.Now().Add(ttl - 10*time.Second)}
	c.mu.Unlock()
	return "Bearer " + t, nil
}

// parseChallenge splits `Bearer realm="…",service="…"`.
func parseChallenge(h string) (string, map[string]string) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(h), " ")
	params := map[string]string{}
	for rest != "" {
		rest = strings.TrimLeft(rest, " ,")
		k, after, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		var v string
		if strings.HasPrefix(after, `"`) {
			end := strings.Index(after[1:], `"`)
			if end < 0 {
				break
			}
			v, rest = after[1:1+end], after[2+end:]
		} else {
			v, rest, _ = strings.Cut(after, ",")
		}
		params[strings.ToLower(strings.TrimSpace(k))] = v
	}
	return scheme, params
}

// manifest fetches a manifest; with head only its digest and type.
func (c *client) manifest(ctx context.Context, repo, ref string, accept []string, head bool) (body []byte, contentType, digest string, err error) {
	method := http.MethodGet
	if head {
		method = http.MethodHead
	}
	acc := append(append([]string(nil), accept...), manifestTypes...)
	resp, err := c.do(ctx, method, repo, "/v2/"+repo+"/manifests/"+ref, http.Header{"Accept": {strings.Join(acc, ", ")}})
	if err != nil {
		return nil, "", "", err
	}
	defer resp.Body.Close()
	if err := statusError(resp); err != nil {
		return nil, "", "", err
	}
	if !head {
		if body, err = io.ReadAll(io.LimitReader(resp.Body, 10<<20)); err != nil {
			return nil, "", "", err
		}
	}
	return body, resp.Header.Get("Content-Type"), resp.Header.Get("Docker-Content-Digest"), nil
}

// blob opens a blob; the registry may redirect to a CDN (followed).
func (c *client) blob(ctx context.Context, repo, digest string, head bool) (io.ReadCloser, int64, error) {
	method := http.MethodGet
	if head {
		method = http.MethodHead
	}
	resp, err := c.do(ctx, method, repo, "/v2/"+repo+"/blobs/"+digest, nil)
	if err != nil {
		return nil, 0, err
	}
	if err := statusError(resp); err != nil {
		resp.Body.Close()
		return nil, 0, err
	}
	return resp.Body, resp.ContentLength, nil
}

func statusError(resp *http.Response) error {
	switch {
	case resp.StatusCode == http.StatusOK:
		return nil
	case resp.StatusCode == http.StatusNotFound:
		return ErrNotFound
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return &UpstreamError{Status: resp.StatusCode, Body: strings.TrimSpace(string(b))}
}
