// S3-compatible storage for cloudserver (checklist 7.7 follow-up). it implements
// the same store contract as localStore, so the server code does not change:
//
//   - put is conditional (If-None-Match: *). A key that already exists is
//     refused, so a stored original stays immutable as long as the provider
//     honours conditional writes. providers that ignore the header lose that
//     guarantee; put cannot detect it.
//   - get returns ErrNoSuchObject for a missing key.
//   - delete treats a missing key as success.
//   - every key passes safeKey before it becomes part of a URL.
//   - transport errors and 429/5xx answers are retried with backoff (see do).
//     about 1 in 20 writes to the railway bucket failed this way under steady
//     load (7.59 cost load, november 19, 2026), and without retries each one
//     failed a user's upload.
//
// requests use path-style addressing (endpoint/bucket/key) and AWS signature
// version 4 with the standard library only, so the module needs no new
// dependency. credentials are never logged and never put in a URL.
package cloudserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// maxObjectBytes bounds one get, so a corrupt or hostile object cannot exhaust
// memory. bundles and documents are both bounded well below this (contract §5.3).
const maxObjectBytes = 64 << 20

// S3Config describes one bucket. endpoint is the provider's S3 API base URL,
// for example https://s3.example.com. it must be https, except for loopback
// addresses used in tests.
type S3Config struct {
	Endpoint  string
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
	// HTTPClient is optional; a client with a 60-second timeout is used when nil.
	HTTPClient *http.Client
}

var (
	s3RegionRE = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	s3BucketRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
)

type s3Store struct {
	base   string
	cfg    S3Config
	client *http.Client
	now    func() time.Time
	// backoff is the wait before each retry; its length is the retry count.
	// up to half again is added at random so concurrent retries spread out.
	backoff []time.Duration
}

// defaultS3Backoff retries three times over about two seconds: long enough to
// ride out a provider's brief 503, short enough to stay well inside the
// 60-second client timeout and the upload's own deadline.
var defaultS3Backoff = []time.Duration{100 * time.Millisecond, 400 * time.Millisecond, 1600 * time.Millisecond}

// retryableStatus reports answers worth retrying: throttling and server errors.
// every 4xx other than 429 (bad signature, missing key, conditional failure)
// is final.
func retryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}

// do sends the request that build returns, retrying transport errors and
// retryable statuses. build is called once per attempt so each attempt has a
// fresh body and a fresh signature. it returns the final response, whose body
// the caller must close, and the number of attempts made. when every attempt
// fails with a retryable status, the last response is returned so the caller
// reports its status.
func (s *s3Store) do(ctx context.Context, build func() (*http.Request, error)) (*http.Response, int, error) {
	for attempt := 0; ; attempt++ {
		req, err := build()
		if err != nil {
			return nil, attempt + 1, err
		}
		resp, err := s.client.Do(req)
		last := attempt == len(s.backoff)
		if err == nil && (!retryableStatus(resp.StatusCode) || last) {
			return resp, attempt + 1, nil
		}
		if err != nil && (last || ctx.Err() != nil) {
			return nil, attempt + 1, transportError(err)
		}
		if resp != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
		}
		wait := s.backoff[attempt]
		if wait > 0 {
			wait += rand.N(wait/2 + 1)
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, attempt + 1, ctx.Err()
		case <-timer.C:
		}
	}
}

// NewS3Store validates the configuration and returns a Store. it makes no
// network call; a bad credential surfaces on the first request.
func NewS3Store(cfg S3Config) (Store, error) {
	if cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, fmt.Errorf("cloudserver: s3 credentials are required")
	}
	if !s3RegionRE.MatchString(cfg.Region) {
		return nil, fmt.Errorf("cloudserver: s3 region %q is not valid", cfg.Region)
	}
	if !s3BucketRE.MatchString(cfg.Bucket) {
		return nil, fmt.Errorf("cloudserver: s3 bucket name is not valid")
	}
	endpoint, err := url.Parse(strings.TrimRight(cfg.Endpoint, "/"))
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" {
		// userinfo is refused outright: an endpoint that carries a password must
		// not be echoed back in an error, so it is never accepted.
		return nil, fmt.Errorf("cloudserver: s3 endpoint is not a plain URL")
	}
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && isLoopbackHost(endpoint.Hostname())) {
		return nil, fmt.Errorf("cloudserver: s3 endpoint must use https")
	}
	client := cfg.HTTPClient
	if client == nil {
		// redirects are not followed: a redirected PUT would be replayed to
		// another host or region with a signature made for this one. the
		// redirect surfaces as an error instead.
		client = &http.Client{
			Timeout: 60 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &s3Store{
		base:    endpoint.String(),
		cfg:     cfg,
		client:  client,
		now:     time.Now,
		backoff: defaultS3Backoff,
	}, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *s3Store) objectURL(key string) string {
	return s.base + "/" + s.cfg.Bucket + "/" + key
}

// put stores data under key. A second put to the same key is refused.
func (s *s3Store) Put(ctx context.Context, key string, data []byte) (int64, error) {
	if !safeKey(key) {
		return 0, fmt.Errorf("cloudserver: unsupported storage key %q", key)
	}
	payload := sha256Hex(data)
	resp, attempts, err := s.do(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, s.objectURL(key), bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("cloudserver: s3 put request: %w", err)
		}
		req.ContentLength = int64(len(data))
		req.Header.Set("If-None-Match", "*")
		s.sign(req, payload)
		return req, nil
	})
	if err != nil {
		return 0, fmt.Errorf("cloudserver: s3 put: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent:
		return int64(len(data)), nil
	case http.StatusPreconditionFailed, http.StatusConflict:
		// 412: the key exists. 409 ConditionalRequestConflict: two conditional
		// writes to the key raced. either way the key is taken. after a retry,
		// the earlier attempt may itself have stored the object before its
		// answer was lost; the key is immutable, so this write succeeded exactly
		// when the stored bytes are ours.
		if attempts > 1 {
			if got, gerr := s.Get(ctx, key); gerr == nil && bytes.Equal(got, data) {
				return int64(len(data)), nil
			}
		}
		return 0, fmt.Errorf("cloudserver: object %q is immutable and already exists", key)
	default:
		return 0, fmt.Errorf("cloudserver: s3 put: status %d", resp.StatusCode)
	}
}

// get returns the whole object. objects larger than maxObjectBytes are refused.
func (s *s3Store) Get(ctx context.Context, key string) ([]byte, error) {
	if !safeKey(key) {
		return nil, fmt.Errorf("cloudserver: unsupported storage key %q", key)
	}
	resp, _, err := s.do(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.objectURL(key), nil)
		if err != nil {
			return nil, fmt.Errorf("cloudserver: s3 get request: %w", err)
		}
		s.sign(req, sha256Hex(nil))
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver: s3 get: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, ErrNoSuchObject
	default:
		return nil, fmt.Errorf("cloudserver: s3 get: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxObjectBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cloudserver: s3 get read: %w", err)
	}
	if len(data) > maxObjectBytes {
		return nil, fmt.Errorf("cloudserver: s3 object %q exceeds the storage budget", key)
	}
	return data, nil
}

// delete removes the object. A missing object is not an error.
func (s *s3Store) Delete(ctx context.Context, key string) error {
	if !safeKey(key) {
		return fmt.Errorf("cloudserver: unsupported storage key %q", key)
	}
	resp, _, err := s.do(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.objectURL(key), nil)
		if err != nil {
			return nil, fmt.Errorf("cloudserver: s3 delete request: %w", err)
		}
		s.sign(req, sha256Hex(nil))
		return req, nil
	})
	if err != nil {
		return fmt.Errorf("cloudserver: s3 delete: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	default:
		return fmt.Errorf("cloudserver: s3 delete: status %d", resp.StatusCode)
	}
}

// sign adds the SigV4 headers to req. the signed headers are host, the
// conditional-write header when present, the payload hash and the timestamp.
func (s *s3Store) sign(req *http.Request, payloadHash string) {
	when := s.now().UTC()
	req.Header.Set("X-Amz-Date", when.Format("20060102T150405Z"))
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	headers := map[string]string{
		"host":                 req.URL.Host,
		"x-amz-content-sha256": payloadHash,
		"x-amz-date":           req.Header.Get("X-Amz-Date"),
	}
	signed := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	if v := req.Header.Get("If-None-Match"); v != "" {
		headers["if-none-match"] = v
		signed = append(signed, "if-none-match")
	}
	sort.Strings(signed)
	auth := sigV4Authorization(req.Method, req.URL.EscapedPath(), headers, signed,
		payloadHash, when, s.cfg.Region, "s3", s.cfg.AccessKey, s.cfg.SecretKey)
	req.Header.Set("Authorization", auth)
}

// sigV4Authorization returns the authorization header value for one request.
// headers maps lowercase names to values; signed lists the names to sign, sorted.
// it is the AWS signature version 4 algorithm with an empty query string.
func sigV4Authorization(method, canonicalURI string, headers map[string]string, signed []string,
	payloadHash string, when time.Time, region, service, accessKey, secretKey string) string {
	when = when.UTC()
	var canonical strings.Builder
	canonical.WriteString(method + "\n" + canonicalURI + "\n" + "\n")
	for _, name := range signed {
		canonical.WriteString(name + ":" + strings.TrimSpace(headers[name]) + "\n")
	}
	canonical.WriteString("\n" + strings.Join(signed, ";") + "\n" + payloadHash)

	date := when.Format("20060102")
	scope := date + "/" + region + "/" + service + "/aws4_request"
	tosign := "AWS4-HMAC-SHA256\n" + when.Format("20060102T150405Z") + "\n" + scope + "\n" + sha256Hex([]byte(canonical.String()))

	kdate := hmacSHA256([]byte("AWS4"+secretKey), date)
	kregion := hmacSHA256(kdate, region)
	kservice := hmacSHA256(kregion, service)
	ksigning := hmacSHA256(kservice, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(ksigning, tosign))

	return "AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + scope +
		", SignedHeaders=" + strings.Join(signed, ";") + ", Signature=" + signature
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

// transportError drops the request URL from a client error. the URL carries
// the bucket and key, which are not secret, but keeping the error short keeps
// the endpoint out of logs.
func transportError(err error) error {
	if u, ok := err.(*url.Error); ok {
		return u.Err
	}
	return err
}
