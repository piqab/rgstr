// Integration tests for per-repository blob isolation.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

func status(t *testing.T, method, u string, headers map[string]string) int {
	t.Helper()
	resp := do(t, method, u, nil, headers)
	resp.Body.Close()
	return resp.StatusCode
}

func TestBlobNotVisibleFromOtherRepo(t *testing.T) {
	srv, _ := newTestServer(t)
	d := pushBlob(t, srv.URL, "repoA", []byte("only in A"))

	for _, m := range []string{"HEAD", "GET"} {
		if code := status(t, m, fmt.Sprintf("%s/v2/repoA/blobs/%s", srv.URL, d), nil); code != http.StatusOK {
			t.Errorf("%s in owning repo: got %d want 200", m, code)
		}
		if code := status(t, m, fmt.Sprintf("%s/v2/repoB/blobs/%s", srv.URL, d), nil); code != http.StatusNotFound {
			t.Errorf("%s from other repo: got %d want 404", m, code)
		}
	}
}

func TestManifestReferencedBlobVisible(t *testing.T) {
	srv, _ := newTestServer(t)
	// Pushing an image links its config and layers to the repo.
	pushImage(t, srv.URL, "app", "latest", "amd64")
	resp := do(t, "GET", srv.URL+"/v2/app/manifests/latest", nil, nil)
	var m struct {
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	json.NewDecoder(resp.Body).Decode(&m)
	resp.Body.Close()
	if code := status(t, "GET", fmt.Sprintf("%s/v2/app/blobs/%s", srv.URL, m.Layers[0].Digest), nil); code != http.StatusOK {
		t.Errorf("layer of pushed image: got %d want 200", code)
	}
}

func TestMountRequiresSourceRepo(t *testing.T) {
	srv, _ := newTestServer(t)
	d := pushBlob(t, srv.URL, "repoA", []byte("mount me"))

	mount := func(target, query string) int {
		return status(t, "POST", fmt.Sprintf("%s/v2/%s/blobs/uploads/?mount=%s%s", srv.URL, target, d, query), nil)
	}
	if code := mount("repoB", ""); code != http.StatusAccepted {
		t.Errorf("mount without from: got %d want 202 (fresh upload)", code)
	}
	if code := mount("repoB", "&from=repoC"); code != http.StatusAccepted {
		t.Errorf("mount from repo without the blob: got %d want 202", code)
	}
	if code := status(t, "GET", fmt.Sprintf("%s/v2/repoB/blobs/%s", srv.URL, d), nil); code != http.StatusNotFound {
		t.Errorf("blob after refused mount: got %d want 404", code)
	}
	if code := mount("repoB", "&from=repoA"); code != http.StatusCreated {
		t.Errorf("mount from owning repo: got %d want 201", code)
	}
	if code := status(t, "GET", fmt.Sprintf("%s/v2/repoB/blobs/%s", srv.URL, d), nil); code != http.StatusOK {
		t.Errorf("blob after mount: got %d want 200", code)
	}
}

func TestDeleteBlobOnlyUnlinksRepo(t *testing.T) {
	srv, _ := newTestServer(t)
	d := pushBlob(t, srv.URL, "repoA", []byte("shared"))
	pushBlob(t, srv.URL, "repoB", []byte("shared"))

	if code := status(t, "DELETE", fmt.Sprintf("%s/v2/repoB/blobs/%s", srv.URL, d), nil); code != http.StatusAccepted {
		t.Fatalf("delete blob: got %d want 202", code)
	}
	if code := status(t, "GET", fmt.Sprintf("%s/v2/repoB/blobs/%s", srv.URL, d), nil); code != http.StatusNotFound {
		t.Errorf("deleted repo: got %d want 404", code)
	}
	if code := status(t, "GET", fmt.Sprintf("%s/v2/repoA/blobs/%s", srv.URL, d), nil); code != http.StatusOK {
		t.Errorf("other repo after delete: got %d want 200", code)
	}
}

// The original leak: anonymous read through a public repo path returned any
// blob in the store, including private ones.
func TestPrivateBlobNotReadableThroughPublicRepo(t *testing.T) {
	srv := newAuthTestServer(t, "public/**")
	alice := map[string]string{"Authorization": "Basic YWxpY2U6c2VjcmV0"} // alice:secret

	start := do(t, "POST", srv.URL+"/v2/private/app/blobs/uploads/", nil, alice)
	start.Body.Close()
	data := []byte("top secret")
	d := digest(data)
	put := do(t, "PUT", srv.URL+start.Header.Get("Location")+"?digest="+url.QueryEscape(d), data, alice)
	put.Body.Close()
	if put.StatusCode != http.StatusCreated {
		t.Fatalf("upload: got %d", put.StatusCode)
	}

	if code := status(t, "GET", fmt.Sprintf("%s/v2/public/anything/blobs/%s", srv.URL, d), nil); code != http.StatusNotFound {
		t.Errorf("anonymous read via public repo: got %d want 404", code)
	}
	if code := status(t, "GET", fmt.Sprintf("%s/v2/private/app/blobs/%s", srv.URL, d), alice); code != http.StatusOK {
		t.Errorf("owner read: got %d want 200", code)
	}
}

func TestMountRequiresPullOnSource(t *testing.T) {
	srv := newAuthTestServer(t)
	alice := map[string]string{"Authorization": "Basic YWxpY2U6c2VjcmV0"}
	start := do(t, "POST", srv.URL+"/v2/repoA/blobs/uploads/", nil, alice)
	start.Body.Close()
	data := []byte("A's layer")
	d := digest(data)
	put := do(t, "PUT", srv.URL+start.Header.Get("Location")+"?digest="+d, data, alice)
	put.Body.Close()

	// Token that may push to repoB but has no pull on repoA.
	resp := do(t, "GET", srv.URL+"/v2/auth?service=test&scope=repository:repoB:pull,push", nil, alice)
	var tok struct {
		Token string `json:"token"`
	}
	json.NewDecoder(resp.Body).Decode(&tok)
	resp.Body.Close()
	bearer := map[string]string{"Authorization": "Bearer " + tok.Token}

	u := fmt.Sprintf("%s/v2/repoB/blobs/uploads/?mount=%s&from=repoA", srv.URL, d)
	if code := status(t, "POST", u, bearer); code != http.StatusAccepted {
		t.Errorf("mount without pull on source: got %d want 202", code)
	}
}
