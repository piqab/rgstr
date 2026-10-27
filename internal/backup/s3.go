package backup

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

// s3Target stores backups in an S3-compatible object store (AWS, MinIO,
// Ceph, Yandex Object Storage, ...). Requests are signed with AWS
// Signature Version 4; archives are sent as multipart uploads, a part at a
// time, so neither memory nor disk needs to hold a whole backup.
type s3Target struct {
	cfg            config.S3Config
	bucket, prefix string
	base           *url.URL // endpoint
	client         *http.Client
}

const (
	minPartSize = 16 << 20
	maxParts    = 10000
)

func newS3(cfg config.S3Config, bucket, prefix string) (*s3Target, error) {
	if cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, errors.New("S3 backups need RGSTR_BACKUP_S3_ACCESS_KEY and RGSTR_BACKUP_S3_SECRET_KEY (or AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)")
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://s3." + cfg.Region + ".amazonaws.com"
	}
	base, err := url.Parse(endpoint)
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") {
		return nil, fmt.Errorf("RGSTR_BACKUP_S3_ENDPOINT %q: want https://host[:port]", endpoint)
	}
	return &s3Target{cfg: cfg, bucket: bucket, prefix: prefix, base: base,
		client: &http.Client{Timeout: 30 * time.Minute}}, nil
}

func (s *s3Target) String() string { return "s3://" + s.bucket + "/" + s.prefix }

// objectURL is the URL of key (empty: the bucket).
func (s *s3Target) objectURL(key string, q url.Values) *url.URL {
	u := *s.base
	if s.cfg.PathStyle {
		u.Path = "/" + s.bucket + "/" + key
	} else {
		u.Host = s.bucket + "." + u.Host
		u.Path = "/" + key
	}
	u.RawQuery = canonicalQuery(q)
	return &u
}

func (s *s3Target) do(ctx context.Context, method, key string, q url.Values, body []byte, hdr http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, s.objectURL(key, q).String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	req.ContentLength = int64(len(body))
	s.sign(req, body, time.Now().UTC())
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		return nil, s3Error(method, key, resp)
	}
	return resp, nil
}

func s3Error(method, key string, resp *http.Response) error {
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
func (s *s3Target) sign(req *http.Request, body []byte, now time.Time) {
	payload := sha256.Sum256(body)
	payloadHex := hex.EncodeToString(payload[:])
	amzDate := now.Format("20060102T150405Z")
	day := now.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHex)
	if s.cfg.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", s.cfg.SessionToken)
	}

	names := []string{"host"}
	values := map[string]string{"host": req.URL.Host}
	for k := range req.Header {
		lk := strings.ToLower(k)
		if lk == "content-type" || lk == "content-md5" || strings.HasPrefix(lk, "x-amz-") {
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
		req.Method, uriEncode(req.URL.Path, false), req.URL.RawQuery,
		canonHeaders.String(), signed, payloadHex,
	}, "\n")
	scope := day + "/" + s.cfg.Region + "/s3/aws4_request"
	sum := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(sum[:])

	mac := func(key []byte, data string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(data))
		return h.Sum(nil)
	}
	k := mac([]byte("AWS4"+s.cfg.SecretKey), day)
	k = mac(k, s.cfg.Region)
	k = mac(k, "s3")
	k = mac(k, "aws4_request")
	sig := hex.EncodeToString(mac(k, toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s.cfg.AccessKey+"/"+scope+
		", SignedHeaders="+signed+", Signature="+sig)
}

// uriEncode encodes like AWS: everything but unreserved characters (and
// '/' in paths).
func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' || (c == '/' && !encodeSlash) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
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

func (s *s3Target) Put(ctx context.Context, name string, r io.Reader, sizeHint int64) error {
	key := s.prefix + name
	partSize := int64(minPartSize)
	if p := sizeHint / (maxParts * 9 / 10); p > partSize { // room for growth while backing up
		partSize = p
	}
	resp, err := s.do(ctx, http.MethodPost, key, url.Values{"uploads": {""}}, nil, nil)
	if err != nil {
		return err
	}
	var start struct {
		UploadID string `xml:"UploadId"`
	}
	err = xml.NewDecoder(resp.Body).Decode(&start)
	resp.Body.Close()
	if err != nil || start.UploadID == "" {
		return fmt.Errorf("s3 start upload %s: %v", key, err)
	}
	abort := func(err error) error {
		// A failed upload must not leave paid-for parts behind.
		actx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if resp, aerr := s.do(actx, http.MethodDelete, key, url.Values{"uploadId": {start.UploadID}}, nil, nil); aerr == nil {
			resp.Body.Close()
		}
		return err
	}

	type part struct {
		Number int    `xml:"PartNumber"`
		ETag   string `xml:"ETag"`
	}
	var parts []part
	buf := make([]byte, partSize)
	for n := 1; ; n++ {
		read, rerr := io.ReadFull(r, buf)
		if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
			return abort(rerr)
		}
		if read == 0 && n > 1 {
			break
		}
		if n > maxParts {
			return abort(errors.New("s3: backup larger than 10000 parts"))
		}
		q := url.Values{"partNumber": {strconv.Itoa(n)}, "uploadId": {start.UploadID}}
		resp, err := s.do(ctx, http.MethodPut, key, q, buf[:read], nil)
		if err != nil {
			return abort(err)
		}
		resp.Body.Close()
		parts = append(parts, part{Number: n, ETag: resp.Header.Get("ETag")})
		if rerr != nil { // EOF: that was the last part
			break
		}
	}

	body, _ := xml.Marshal(struct {
		XMLName xml.Name `xml:"CompleteMultipartUpload"`
		Parts   []part   `xml:"Part"`
	}{Parts: parts})
	resp, err = s.do(ctx, http.MethodPost, key, url.Values{"uploadId": {start.UploadID}}, body,
		http.Header{"Content-Type": {"application/xml"}})
	if err != nil {
		return abort(err)
	}
	defer resp.Body.Close()
	// S3 may report a failed completion with 200 and an <Error> body.
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if bytes.Contains(raw, []byte("<Error>")) {
		return abort(fmt.Errorf("s3 complete upload %s: %s", key, raw))
	}
	return nil
}

func (s *s3Target) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	resp, err := s.do(ctx, http.MethodGet, s.prefix+name, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (s *s3Target) Delete(ctx context.Context, name string) error {
	resp, err := s.do(ctx, http.MethodDelete, s.prefix+name, nil, nil, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (s *s3Target) list(ctx context.Context) ([]Object, error) {
	var out []Object
	token := ""
	for {
		q := url.Values{"list-type": {"2"}, "prefix": {s.prefix}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		resp, err := s.do(ctx, http.MethodGet, "", q, nil, nil)
		if err != nil {
			return nil, err
		}
		var res struct {
			Contents []struct {
				Key  string `xml:"Key"`
				Size int64  `xml:"Size"`
			} `xml:"Contents"`
			IsTruncated bool   `xml:"IsTruncated"`
			Next        string `xml:"NextContinuationToken"`
		}
		err = xml.NewDecoder(resp.Body).Decode(&res)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("s3 list: %w", err)
		}
		for _, c := range res.Contents {
			name := strings.TrimPrefix(c.Key, s.prefix)
			if !strings.Contains(name, "/") {
				out = append(out, Object{Name: name, Size: c.Size})
			}
		}
		if !res.IsTruncated || res.Next == "" {
			return out, nil
		}
		token = res.Next
	}
}
