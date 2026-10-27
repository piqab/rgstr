// Package s3 is a small client for S3-compatible object stores (AWS S3,
// MinIO, Ceph RGW, SeaweedFS, Yandex Object Storage, Cloudflare R2, ...):
// the operations rgstr needs, signed with AWS Signature Version 4, without
// an SDK.
package s3

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"rgstr/internal/config"
)

// ErrNotFound is returned for a missing object.
var ErrNotFound = errors.New("s3: not found")

const (
	// MinPartSize is the smallest multipart part S3 accepts (except the last).
	MinPartSize = 5 << 20
	// MaxParts is the most parts of one multipart upload.
	MaxParts = 10000
	// maxCopyPart is the largest server-side copy of one part.
	maxCopyPart = 5 << 30
)

// Client talks to one bucket.
type Client struct {
	cfg    config.S3Config
	bucket string
	base   *url.URL // endpoint
	http   *http.Client
}

// New creates a client for bucket.
func New(cfg config.S3Config, bucket string) (*Client, error) {
	if bucket == "" {
		return nil, errors.New("s3: no bucket")
	}
	if cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, errors.New("s3: access key and secret key are required")
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://s3." + cfg.Region + ".amazonaws.com"
	}
	base, err := url.Parse(strings.TrimSuffix(endpoint, "/"))
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") {
		return nil, fmt.Errorf("s3 endpoint %q: want https://host[:port]", endpoint)
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	return &Client{cfg: cfg, bucket: bucket, base: base, http: &http.Client{
		// No overall timeout: blob downloads stream for as long as they take.
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConnsPerHost:   64,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 2 * time.Minute,
			TLSHandshakeTimeout:   10 * time.Second,
		},
	}}, nil
}

// String names the bucket, for logs (no credentials).
func (c *Client) String() string { return "s3://" + c.bucket }

// objectURL is the URL of key (empty: the bucket).
func (c *Client) objectURL(key string, q url.Values) *url.URL {
	u := *c.base
	if c.cfg.PathStyle {
		u.Path = "/" + c.bucket + "/" + key
	} else {
		u.Host = c.bucket + "." + u.Host
		u.Path = "/" + key
	}
	u.RawPath = uriEncode(u.Path, false)
	u.RawQuery = canonicalQuery(q)
	return &u
}

// do sends a signed request with an in-memory body.
func (c *Client) do(ctx context.Context, method, key string, q url.Values, body []byte, hdr http.Header) (*http.Response, error) {
	sum := sha256.Sum256(body)
	return c.send(ctx, method, key, q, bytes.NewReader(body), int64(len(body)), hex.EncodeToString(sum[:]), hdr)
}

func (c *Client) send(ctx context.Context, method, key string, q url.Values, body io.Reader, size int64,
	payloadHash string, hdr http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.objectURL(key, q).String(), body)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	req.ContentLength = size
	if size == 0 {
		req.Body = http.NoBody
	}
	c.sign(req, payloadHash, time.Now().UTC())
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotModified {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			return nil, fmt.Errorf("%w: %s", ErrNotFound, key)
		}
		return nil, apiError(method, key, resp)
	}
	return resp, nil
}

func apiError(method, key string, resp *http.Response) error {
	var e struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	xml.Unmarshal(raw, &e)
	if e.Code == "" {
		e.Code = resp.Status
	}
	return fmt.Errorf("s3 %s %s: %s %s", method, key, e.Code, e.Message)
}

// sign adds AWS Signature Version 4 headers.
func (c *Client) sign(req *http.Request, payloadHash string, now time.Time) {
	amzDate := now.Format("20060102T150405Z")
	day := now.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if c.cfg.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.cfg.SessionToken)
	}
	names := []string{"host"}
	values := map[string]string{"host": req.URL.Host}
	for k := range req.Header {
		lk := strings.ToLower(k)
		if lk == "content-type" || lk == "content-md5" || lk == "range" || strings.HasPrefix(lk, "x-amz-") {
			names = append(names, lk)
			values[lk] = strings.TrimSpace(req.Header.Get(k))
		}
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, n := range names {
		canonHeaders.WriteString(n + ":" + values[n] + "\n")
	}
	signed := strings.Join(names, ";")
	canonical := strings.Join([]string{
		req.Method, req.URL.EscapedPath(), req.URL.RawQuery, canonHeaders.String(), signed, payloadHash,
	}, "\n")
	scope := day + "/" + c.cfg.Region + "/s3/aws4_request"
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.cfg.AccessKey+"/"+scope+
		", SignedHeaders="+signed+", Signature="+c.signature(day, amzDate, scope, canonical))
}

func (c *Client) signature(day, amzDate, scope, canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
	mac := func(key []byte, data string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(data))
		return h.Sum(nil)
	}
	k := mac([]byte("AWS4"+c.cfg.SecretKey), day)
	k = mac(k, c.cfg.Region)
	k = mac(k, "s3")
	k = mac(k, "aws4_request")
	return hex.EncodeToString(mac(k, toSign))
}

// Presign returns a URL that GETs key without credentials until ttl passes.
func (c *Client) Presign(key string, ttl time.Duration) string {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	day := now.Format("20060102")
	scope := day + "/" + c.cfg.Region + "/s3/aws4_request"
	q := url.Values{
		"X-Amz-Algorithm":     {"AWS4-HMAC-SHA256"},
		"X-Amz-Credential":    {c.cfg.AccessKey + "/" + scope},
		"X-Amz-Date":          {amzDate},
		"X-Amz-Expires":       {strconv.Itoa(int(ttl.Seconds()))},
		"X-Amz-SignedHeaders": {"host"},
	}
	if c.cfg.SessionToken != "" {
		q.Set("X-Amz-Security-Token", c.cfg.SessionToken)
	}
	u := c.objectURL(key, q)
	canonical := strings.Join([]string{"GET", u.EscapedPath(), u.RawQuery, "host:" + u.Host + "\n", "host", "UNSIGNED-PAYLOAD"}, "\n")
	u.RawQuery += "&X-Amz-Signature=" + c.signature(day, amzDate, scope, canonical)
	return u.String()
}

// uriEncode encodes like AWS: everything but unreserved characters (and
// '/' in paths).
func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == '~' || (ch == '/' && !encodeSlash) {
			b.WriteByte(ch)
		} else {
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}

func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		for _, v := range q[k] {
			parts = append(parts, uriEncode(k, true)+"="+uriEncode(v, true))
		}
	}
	return strings.Join(parts, "&")
}

// ─── Objects ─────────────────────────────────────────────────────────────────

// Object describes a stored object.
type Object struct {
	Key     string
	Size    int64
	ModTime time.Time
}

// Head returns the object's size and modification time, or ErrNotFound.
func (c *Client) Head(ctx context.Context, key string) (Object, error) {
	resp, err := c.do(ctx, http.MethodHead, key, nil, nil, nil)
	if err != nil {
		return Object{}, err
	}
	resp.Body.Close()
	mod, _ := http.ParseTime(resp.Header.Get("Last-Modified"))
	return Object{Key: key, Size: resp.ContentLength, ModTime: mod}, nil
}

// Get reads key from offset on.
func (c *Client) Get(ctx context.Context, key string, offset int64) (io.ReadCloser, error) {
	var hdr http.Header
	if offset > 0 {
		hdr = http.Header{"Range": {fmt.Sprintf("bytes=%d-", offset)}}
	}
	resp, err := c.do(ctx, http.MethodGet, key, nil, nil, hdr)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// Put stores data under key.
func (c *Client) Put(ctx context.Context, key string, data []byte) error {
	resp, err := c.do(ctx, http.MethodPut, key, nil, data, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Delete removes key; a missing key is not an error.
func (c *Client) Delete(ctx context.Context, key string) error {
	resp, err := c.do(ctx, http.MethodDelete, key, nil, nil, nil)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Copy copies src to dst inside the bucket (server side).
func (c *Client) Copy(ctx context.Context, src, dst string) error {
	o, err := c.Head(ctx, src)
	if err != nil {
		return err
	}
	if o.Size > maxCopyPart {
		return c.Compose(ctx, dst, []Object{o})
	}
	resp, err := c.do(ctx, http.MethodPut, dst, nil, nil,
		http.Header{"X-Amz-Copy-Source": {"/" + c.bucket + "/" + uriEncode(src, false)}})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return checkXMLError(resp, "copy "+src)
}

// List calls fn for every object under prefix. With delimiter "/" it
// lists one level: objects directly under prefix, and the common prefixes
// ("directories", ending in "/") through dir.
func (c *Client) List(ctx context.Context, prefix, delimiter string, fn func(Object) error, dir func(prefix string) error) error {
	token := ""
	for {
		q := url.Values{"list-type": {"2"}, "prefix": {prefix}}
		if delimiter != "" {
			q.Set("delimiter", delimiter)
		}
		if token != "" {
			q.Set("continuation-token", token)
		}
		resp, err := c.do(ctx, http.MethodGet, "", q, nil, nil)
		if err != nil {
			return err
		}
		var res struct {
			Contents []struct {
				Key          string `xml:"Key"`
				Size         int64  `xml:"Size"`
				LastModified string `xml:"LastModified"`
			} `xml:"Contents"`
			CommonPrefixes []struct {
				Prefix string `xml:"Prefix"`
			} `xml:"CommonPrefixes"`
			IsTruncated bool   `xml:"IsTruncated"`
			Next        string `xml:"NextContinuationToken"`
		}
		err = xml.NewDecoder(resp.Body).Decode(&res)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("s3 list %s: %w", prefix, err)
		}
		for _, o := range res.Contents {
			mod, _ := time.Parse(time.RFC3339, o.LastModified)
			if err := fn(Object{Key: o.Key, Size: o.Size, ModTime: mod}); err != nil {
				return err
			}
		}
		if dir != nil {
			for _, p := range res.CommonPrefixes {
				if err := dir(p.Prefix); err != nil {
					return err
				}
			}
		}
		if !res.IsTruncated || res.Next == "" {
			return nil
		}
		token = res.Next
	}
}

// ─── Multipart uploads ───────────────────────────────────────────────────────

// Upload streams r to key as a multipart upload of partSize parts. The
// object appears only when complete; a failed upload is aborted.
func (c *Client) Upload(ctx context.Context, key string, r io.Reader, partSize int64) error {
	if partSize < MinPartSize {
		partSize = MinPartSize
	}
	buf := make([]byte, partSize)
	// Small objects (one part) are a plain PUT.
	n, rerr := io.ReadFull(r, buf)
	if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
		return rerr
	}
	if rerr != nil {
		return c.Put(ctx, key, buf[:n])
	}
	mp, err := c.startMultipart(ctx, key)
	if err != nil {
		return err
	}
	for {
		if err := mp.uploadPart(ctx, buf[:n]); err != nil {
			return mp.abort(err)
		}
		if rerr != nil {
			break
		}
		n, rerr = io.ReadFull(r, buf)
		if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
			return mp.abort(rerr)
		}
		if n == 0 {
			break
		}
	}
	return mp.complete(ctx)
}

// Compose writes dst from the concatenation of srcs, server side where
// S3 allows it: every part but the last must be at least MinPartSize, and
// a part copies at most 5 GiB, so large sources are split.
func (c *Client) Compose(ctx context.Context, dst string, srcs []Object) error {
	for i, s := range srcs {
		if i < len(srcs)-1 && s.Size < MinPartSize {
			return c.composeStreaming(ctx, dst, srcs)
		}
	}
	mp, err := c.startMultipart(ctx, dst)
	if err != nil {
		return err
	}
	for _, s := range srcs {
		for off := int64(0); off < s.Size; off += maxCopyPart { // empty sources add nothing
			end := min(off+maxCopyPart, s.Size)
			if err := mp.copyPart(ctx, s.Key, off, end-1); err != nil {
				return mp.abort(err)
			}
		}
	}
	if len(mp.parts) == 0 {
		mp.abort(nil)
		return c.Put(ctx, dst, nil)
	}
	return mp.complete(ctx)
}

// composeStreaming reads srcs in order and uploads them as dst.
func (c *Client) composeStreaming(ctx context.Context, dst string, srcs []Object) error {
	pr, pw := io.Pipe()
	go func() {
		for _, s := range srcs {
			rc, err := c.Get(ctx, s.Key, 0)
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			_, err = io.Copy(pw, rc)
			rc.Close()
			if err != nil {
				pw.CloseWithError(err)
				return
			}
		}
		pw.Close()
	}()
	var total int64
	for _, s := range srcs {
		total += s.Size
	}
	err := c.Upload(ctx, dst, pr, PartSizeFor(total))
	pr.CloseWithError(err)
	return err
}

// PartSizeFor picks a part size that keeps an upload of size bytes under
// MaxParts, with room to grow.
func PartSizeFor(size int64) int64 {
	p := int64(8 << 20)
	if q := size / (MaxParts * 9 / 10); q > p {
		p = q
	}
	return p
}

type multipart struct {
	c     *Client
	key   string
	id    string
	parts []part
}

type part struct {
	Number int    `xml:"PartNumber"`
	ETag   string `xml:"ETag"`
}

func (c *Client) startMultipart(ctx context.Context, key string) (*multipart, error) {
	resp, err := c.do(ctx, http.MethodPost, key, url.Values{"uploads": {""}}, nil, nil)
	if err != nil {
		return nil, err
	}
	var start struct {
		UploadID string `xml:"UploadId"`
	}
	err = xml.NewDecoder(resp.Body).Decode(&start)
	resp.Body.Close()
	if err != nil || start.UploadID == "" {
		return nil, fmt.Errorf("s3 start upload %s: %v", key, err)
	}
	return &multipart{c: c, key: key, id: start.UploadID}, nil
}

func (m *multipart) uploadPart(ctx context.Context, data []byte) error {
	n := len(m.parts) + 1
	if n > MaxParts {
		return errors.New("s3: more than 10000 parts")
	}
	q := url.Values{"partNumber": {strconv.Itoa(n)}, "uploadId": {m.id}}
	resp, err := m.c.do(ctx, http.MethodPut, m.key, q, data, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	m.parts = append(m.parts, part{Number: n, ETag: resp.Header.Get("ETag")})
	return nil
}

func (m *multipart) copyPart(ctx context.Context, src string, first, last int64) error {
	n := len(m.parts) + 1
	if n > MaxParts {
		return errors.New("s3: more than 10000 parts")
	}
	q := url.Values{"partNumber": {strconv.Itoa(n)}, "uploadId": {m.id}}
	resp, err := m.c.do(ctx, http.MethodPut, m.key, q, nil, http.Header{
		"X-Amz-Copy-Source":       {"/" + m.c.bucket + "/" + uriEncode(src, false)},
		"X-Amz-Copy-Source-Range": {fmt.Sprintf("bytes=%d-%d", first, last)},
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var res struct {
		ETag string `xml:"ETag"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if bytes.Contains(raw, []byte("<Error>")) {
		return fmt.Errorf("s3 copy part of %s: %s", src, raw)
	}
	if err := xml.Unmarshal(raw, &res); err != nil || res.ETag == "" {
		return fmt.Errorf("s3 copy part of %s: no ETag", src)
	}
	m.parts = append(m.parts, part{Number: n, ETag: res.ETag})
	return nil
}

func (m *multipart) complete(ctx context.Context) error {
	body, _ := xml.Marshal(struct {
		XMLName xml.Name `xml:"CompleteMultipartUpload"`
		Parts   []part   `xml:"Part"`
	}{Parts: m.parts})
	resp, err := m.c.do(ctx, http.MethodPost, m.key, url.Values{"uploadId": {m.id}}, body,
		http.Header{"Content-Type": {"application/xml"}})
	if err != nil {
		return m.abort(err)
	}
	defer resp.Body.Close()
	if err := checkXMLError(resp, "complete upload "+m.key); err != nil {
		return m.abort(err)
	}
	return nil
}

// abort cancels the upload (so no paid-for parts stay behind) and returns err.
func (m *multipart) abort(err error) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if resp, aerr := m.c.do(ctx, http.MethodDelete, m.key, url.Values{"uploadId": {m.id}}, nil, nil); aerr == nil {
		resp.Body.Close()
	}
	return err
}

// checkXMLError catches errors S3 reports with status 200 (copy, complete).
func checkXMLError(resp *http.Response, what string) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if bytes.Contains(raw, []byte("<Error>")) {
		return fmt.Errorf("s3 %s: %s", what, raw)
	}
	return nil
}
