package proxy

import (
	"context"
	"io"
	"os"
	"testing"
	"time"
)

// TestDockerHub fetches a manifest and a layer from Docker Hub when
// RGSTR_TEST_HUB is set (needs internet).
func TestDockerHub(t *testing.T) {
	if os.Getenv("RGSTR_TEST_HUB") == "" {
		t.Skip("RGSTR_TEST_HUB not set")
	}
	c, _ := newClient("https://registry-1.docker.io", "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	start := time.Now()
	body, ct, dg, err := c.manifest(ctx, "library/busybox", "1.36.1", []string{"application/vnd.oci.image.manifest.v1+json"}, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("manifest %s %s (%d bytes) in %s", ct, dg, len(body), time.Since(start))
	start = time.Now()
	// A layer of busybox:1.36.1 linux/amd64.
	rc, size, err := c.blob(ctx, "library/busybox", os.Getenv("RGSTR_TEST_HUB"), false)
	if err != nil {
		t.Fatalf("blob after %s: %v", time.Since(start), err)
	}
	n, err := io.Copy(io.Discard, rc)
	rc.Close()
	t.Logf("blob %d/%d bytes in %s (%v)", n, size, time.Since(start), err)
}
