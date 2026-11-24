// package cloudclient is the CLI half of the phase 7 upload API
// (docs/cloud/upload-api.md): create an upload, POST the bundle to the
// presigned storage policy, then complete it. it never interprets a bundle (
// validation and diagnosis stay in internal/incident and internal/analysis)
// and it never sends the token anywhere but the API calls.
package cloudclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
)

// maxReplyBytes bounds how much of any response body is read, so a hostile or
// broken endpoint cannot stream unbounded data into the CLI.
const maxReplyBytes = 1 << 20

// client talks to one deprehendo cloud endpoint with one personal token.
type Client struct {
	Endpoint string
	Token    string
	HTTP     *http.Client
}

// error is a non-2xx API response, carrying the server's code and message
// verbatim (the CLI prints the message, never the request).
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	message := sanitizeServerText(e.Message)
	if e.Code == "" {
		return fmt.Sprintf("cloud: HTTP %d: %s", e.Status, message)
	}
	return fmt.Sprintf("cloud: HTTP %d (%s): %s", e.Status, e.Code, message)
}

// SanitizeServerText makes server-supplied text safe for a terminal (the
// same rule sanitizeServerText applies to error printing, exported for the
// upload command's composed hints).
func SanitizeServerText(s string) string { return sanitizeServerText(s) }

// sanitizeServerText makes a server-supplied message safe for a terminal
// (secrets-audit F3): control characters other than TAB are stripped, so ANSI
// escapes, carriage returns and friends cannot fake CLI output, and the
// length is capped so one hostile line cannot flood a log. cap first, then
// strip, so a control character cannot cut the visible length.
func sanitizeServerText(s string) string {
	if len(s) > maxServerMessage {
		s = s[:maxServerMessage] + "…"
	}
	if !strings.ContainsFunc(s, needsByteRedaction) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\t' || (r >= 0x20 && r != 0x7f && r != unicode.ReplacementChar) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func needsByteRedaction(r rune) bool { return r != '\t' && r < 0x20 || r == 0x7f }

const maxServerMessage = 512

// new validates the endpoint and returns a client. plain HTTP is accepted only
// for loopback hosts, so a token is never sent in clear text across a network.
func New(endpoint, token string) (*Client, error) {
	normalized, err := NormalizeEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, errors.New("cloud: empty token")
	}
	return &Client{
		Endpoint: normalized,
		Token:    token,
		HTTP: &http.Client{
			Timeout:       5 * time.Minute,
			CheckRedirect: sameHostRedirects,
		},
	}, nil
}

// NormalizeEndpoint trims trailing slashes and enforces the transport rule.
//
// an endpoint is never echoed into an error and never carries credentials:
// a userinfo part is rejected (secrets-audit F1), a parse failure reports
// nothing the caller wrote, and the returned URL contains the scheme, host
// and path only.
func NormalizeEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", errors.New("cloud: empty endpoint")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", errors.New("cloud: endpoint is not a parseable URL")
	}
	if u.User != nil {
		return "", fmt.Errorf("cloud: endpoint %s carries credentials in its userinfo; use a token instead", redactEndpointURL(u, endpoint))
	}
	if u.Host == "" {
		return "", fmt.Errorf("cloud: endpoint %s has no host", redactEndpointURL(u, endpoint))
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !loopbackHost(u.Hostname()) {
			return "", fmt.Errorf("cloud: endpoint %s must use https (plain http is allowed only for localhost)", redactEndpointURL(u, endpoint))
		}
	default:
		return "", fmt.Errorf("cloud: endpoint %s must be an https URL", redactEndpointURL(u, endpoint))
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

// sameHostRedirects refuses to follow a redirect to another host, so the
// bearer token cannot be carried off the configured endpoint by a proxy or a
// hostile server. Same-host redirects are followed (go copies the header).
func sameHostRedirects(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	if !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
		return fmt.Errorf("cloud: refusing redirect to %s", req.URL.Host)
	}
	if len(via) >= 5 {
		return errors.New("cloud: too many redirects")
	}
	return nil
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// redactEndpointURL renders an endpoint for an error message with any
// userinfo removed (secrets-audit F1): a caller may write credentials into
// the endpoint itself, and those must never reach stderr or a log. when the
// URL has no host, nothing parseable about the input survives. the raw input
// is never echoed back.
func redactEndpointURL(u *url.URL, endpoint string) string {
	if u == nil || u.Host == "" {
		return "<unparseable endpoint>"
	}
	redacted := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}
	return redacted.String()
}

// CreateRequest is the declared identity of the bytes being uploaded. the
// server records these claims but recomputes the digest from stored bytes.
type CreateRequest struct {
	SHA256        string `json:"sha256"`
	SizeBytes     int64  `json:"size_bytes"`
	IncidentID    string `json:"incident_id"`
	SchemaVersion int    `json:"schema_version"`
	FormatVersion int    `json:"format_version"`
}

// target is the presigned POST policy the bytes are uploaded to.
type Target struct {
	URL    string            `json:"url"`
	Fields map[string]string `json:"fields"`
}

// upload is the server's view of one upload: either a target to POST to or,
// when the bytes already exist in the organization, the existing incident.
type Upload struct {
	UploadID   string  `json:"upload_id"`
	ObjectKey  string  `json:"object_key"`
	IncidentID string  `json:"incident_id"`
	URL        string  `json:"url"`
	Duplicate  bool    `json:"duplicate"`
	Upload     *Target `json:"upload"`
}

// create opens an upload and returns the storage target, or the existing
// incident when the organization already holds these bytes (contract §6).
func (c *Client) Create(ctx context.Context, req CreateRequest) (*Upload, error) {
	if req.SHA256 == "" || req.SizeBytes <= 0 {
		return nil, errors.New("cloud: create upload needs a sha256 and a positive size")
	}
	var out Upload
	if err := c.do(ctx, http.MethodPost, "/api/uploads", req, &out); err != nil {
		return nil, err
	}
	if !out.Duplicate && (out.Upload == nil || out.Upload.URL == "") {
		return nil, errors.New("cloud: create upload returned no storage target")
	}
	return &out, nil
}

// PutObject streams the file to the presigned policy: the policy fields first,
// in the order the server sent them, then the file as the last part. no
// authorization header is attached (the URL is already signed).
func (c *Client) PutObject(ctx context.Context, target *Target, path string) error {
	if target == nil || target.URL == "" {
		return errors.New("cloud: missing storage target")
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cloud: open bundle: %w", err)
	}
	defer f.Close()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	// recording the fields in a deterministic order keeps retries and tests
	// comparable; multipart fields are unordered on the wire.
	for _, name := range FieldOrder(target.Fields) {
		if err := writer.WriteField(name, target.Fields[name]); err != nil {
			return fmt.Errorf("cloud: storage field %q: %w", name, err)
		}
	}
	part, err := writer.CreateFormFile("file", filepath.Base(path))
	if err != nil {
		return fmt.Errorf("cloud: storage form: %w", err)
	}
	if _, err := io.Copy(part, f); err != nil {
		return fmt.Errorf("cloud: upload bundle: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("cloud: storage form: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.URL, &body)
	if err != nil {
		return fmt.Errorf("cloud: storage request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.ContentLength = int64(body.Len())
	resp, err := c.http().Do(req)
	if err != nil {
		// the transport error is a *url.Error carrying the full request URL,
		// including the presigned policy's signature query parameter(s). the
		// signature is a credential-like value (secrets-audit F2): only the
		// underlying cause is wrapped, never the URL.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return fmt.Errorf("cloud: storage upload: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, maxReplyBytes))
		// the storage host is named by the server and its reply reaches the
		// terminal: filter it like every other server message (secrets-audit F3).
		return fmt.Errorf("cloud: storage upload failed: HTTP %d: %s", resp.StatusCode, sanitizeServerText(strings.TrimSpace(string(msg))))
	}
	return nil
}

// complete asks the server to verify the stored bytes and analyze them.
func (c *Client) Complete(ctx context.Context, uploadID string) (*Upload, error) {
	if uploadID == "" {
		return nil, errors.New("cloud: complete needs an upload id")
	}
	var out Upload
	path := "/api/uploads/" + url.PathEscape(uploadID) + "/complete"
	if err := c.do(ctx, http.MethodPost, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// FieldOrder returns the policy field names alphabetically, so a test can
// assert exactly which fields accompany the file.
func FieldOrder(fields map[string]string) []string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("cloud: encode request: %w", err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Endpoint+path, body)
	if err != nil {
		return fmt.Errorf("cloud: request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "deprehendo-agent")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return fmt.Errorf("cloud: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxReplyBytes))
	if err != nil {
		return fmt.Errorf("cloud: read reply: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		apierr := &Error{Status: resp.StatusCode, Message: strings.TrimSpace(string(data))}
		var envelope struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(data, &envelope) == nil && envelope.Error.Message != "" {
			apierr.Code = envelope.Error.Code
			apierr.Message = envelope.Error.Message
		}
		if apierr.Message == "" {
			apierr.Message = http.StatusText(resp.StatusCode)
		}
		return apierr
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("cloud: decode reply: %w", err)
		}
	}
	return nil
}
