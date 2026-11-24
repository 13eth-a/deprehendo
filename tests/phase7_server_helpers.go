// helpers for the phase 7 server integration suite (phase7_server_test.go):
// HTTP plumbing the tests share.
package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"deprehendo/internal/cloudclient"
	"deprehendo/internal/incident"
)

// listenLoopback opens a TCP listener on a free loopback port.
func listenLoopback() (*net.TCPListener, error) {
	return net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
}

// bearerGet performs a GET with (or without) a bearer token and asserts the
// status, returning the body.
func bearerGet(t *testing.T, endpoint, token, path string, wantStatus int) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, endpoint+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s as %q: status %d, want %d; body %s", path, token, resp.StatusCode, wantStatus, body)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<24))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// fetchJSON decodes an API GET into T.
func fetchJSON[T any](t *testing.T, endpoint, token, path string) T {
	var out T
	data := bearerGet(t, endpoint, token, path, http.StatusOK)
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return out
}

// deleteStatus performs a DELETE and returns the status.
func deleteStatus(t *testing.T, endpoint, token, path string) (int, string) {
	req, err := http.NewRequest(http.MethodDelete, endpoint+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, string(body)
}

// getStatus is bearerGet without asserting, for after-deletion checks.
func getStatus(t *testing.T, endpoint, token, path string) int {
	req, err := http.NewRequest(http.MethodGet, endpoint+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// storagePut encodes the policy fields plus the file and POSTs them to the
// storage endpoint, mirroring cloudclient.PutObject with caller-supplied
// fields (the tampering cases).
func storagePut(t *testing.T, url string, fields map[string]string, data []byte) error {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for _, name := range cloudclient.FieldOrder(fields) {
		if err := writer.WriteField(name, fields[name]); err != nil {
			return err
		}
	}
	part, err := writer.CreateFormFile("file", "bundle.deprehendo")
	if err != nil {
		return err
	}
	if _, err := part.Write(data); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.ContentLength = int64(body.Len())
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, "storage refused")
	}
	return nil
}

// readBundleFile opens a validated bundle with the real incident reader.
func readBundleFile(t *testing.T, path string) (*incident.Bundle, error) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return incident.Read(bytes.NewReader(raw), int64(len(raw)))
}
