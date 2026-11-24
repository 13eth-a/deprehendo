package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	"deprehendo/internal/incident"
)

// DefaultSocket is private to the current user. A stale socket is never
// silently removed: the operator must choose a new path or remove it.
func DefaultSocket() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("deprehendo-agent-%d.sock", os.Getuid()))
}

// TriggerResponse acknowledges an accepted manual trigger. state is sampled
// immediately afterwards; with a zero post-window it may already be
// FINALIZING or COMPLETE.
type TriggerResponse struct {
	ID     string                 `json:"id"`
	State  incident.CaptureState  `json:"state"`
	Window incident.CaptureWindow `json:"window"`
	Note   string                 `json:"note,omitempty"`
}

// IncidentStatus is the capture status view polled by the trigger command and
// by tests. path is set only after a successful save.
type IncidentStatus struct {
	State  incident.CaptureState  `json:"state"`
	ID     string                 `json:"id,omitempty"`
	Path   string                 `json:"path,omitempty"`
	Error  string                 `json:"error,omitempty"`
	Window incident.CaptureWindow `json:"window"`
}

// ServeControl exposes read-only recorder views plus manual incident trigger
// over a mode-0600 unix socket. closing the server removes the socket created
// by this invocation.
func (r *Runtime) ServeControl(path string) (*http.Server, error) {
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen control socket: %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(r.Status())
	})
	mux.HandleFunc("GET /snapshot", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := r.Dump(w); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		}
	})
	mux.HandleFunc("GET /history", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(r.History())
	})
	mux.HandleFunc("POST /trigger", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.capture == nil {
			http.Error(w, "incident capture not configured", http.StatusServiceUnavailable)
			return
		}
		var payload struct {
			Note string `json:"note"`
		}
		if req.ContentLength > 4096 {
			http.Error(w, "trigger request too large", http.StatusRequestEntityTooLarge)
			return
		}
		if req.Body != nil && req.ContentLength != 0 {
			body, err := io.ReadAll(io.LimitReader(req.Body, 4097))
			if err != nil || len(body) > 4096 {
				http.Error(w, "trigger request too large or unreadable", http.StatusRequestEntityTooLarge)
				return
			}
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&payload); err != nil {
				http.Error(w, "invalid trigger request", http.StatusBadRequest)
				return
			}
			var extra any
			if err := decoder.Decode(&extra); err != io.EOF {
				http.Error(w, "invalid trigger request", http.StatusBadRequest)
				return
			}
		}
		if len(payload.Note) > 1024 || !utf8.ValidString(payload.Note) {
			http.Error(w, "note must be valid UTF-8 and at most 1024 bytes", http.StatusBadRequest)
			return
		}
		id, err := r.capture.Trigger(incident.Trigger{Type: "manual", Note: payload.Note})
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		status := r.capture.Status()
		_ = json.NewEncoder(w).Encode(TriggerResponse{ID: id, State: status.State, Window: r.capture.Window(), Note: payload.Note})
	})
	mux.HandleFunc("GET /incident", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.capture == nil {
			http.Error(w, "incident capture not configured", http.StatusServiceUnavailable)
			return
		}
		status := r.capture.Status()
		if id := req.URL.Query().Get("id"); id != "" {
			var ok bool
			status, ok = r.capture.StatusFor(id)
			if !ok {
				http.Error(w, "incident result is unavailable or expired", http.StatusNotFound)
				return
			}
		}
		_ = json.NewEncoder(w).Encode(IncidentStatus{State: status.State, ID: status.ID, Path: status.Path, Error: status.Error, Window: r.capture.Window()})
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second}
	go func() { _ = server.Serve(listener) }()
	return server, nil
}

func controlRequest(ctx context.Context, socket, method, view string) ([]byte, error) {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost/"+view, nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agent unavailable at %s: %w", socket, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return nil, fmt.Errorf("agent: %s: %s", res.Status, body)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, (64<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 64<<20 {
		return nil, fmt.Errorf("agent: response exceeds 64 MiB limit")
	}
	return data, nil
}

// ReadControl retrieves a view from a running foreground agent.
func ReadControl(ctx context.Context, socket, view string, dst io.Writer) error {
	data, err := controlRequest(ctx, socket, http.MethodGet, view)
	if err != nil {
		return err
	}
	_, err = dst.Write(data)
	return err
}

// TriggerControl requests a manual incident while the recorder is running.
func TriggerControl(ctx context.Context, socket string) (TriggerResponse, error) {
	return TriggerControlWithNote(ctx, socket, "")
}

// TriggerControlWithNote requests a manual capture and attaches a bounded note.
func TriggerControlWithNote(ctx context.Context, socket, note string) (TriggerResponse, error) {
	var response TriggerResponse
	if len(note) > 1024 || !utf8.ValidString(note) {
		return response, fmt.Errorf("agent: note must be valid UTF-8 and at most 1024 bytes")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	bodybytes, err := json.Marshal(struct {
		Note string `json:"note"`
	}{Note: note})
	if err != nil {
		return response, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/trigger", bytes.NewReader(bodybytes))
	if err != nil {
		return response, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return response, fmt.Errorf("agent unavailable at %s: %w", socket, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return response, fmt.Errorf("agent: %s: %s", res.Status, data)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return response, err
	}
	return response, json.Unmarshal(data, &response)
}

// IncidentStatusControl polls the current incident capture state.
func IncidentStatusControl(ctx context.Context, socket string) (IncidentStatus, error) {
	var status IncidentStatus
	data, err := controlRequest(ctx, socket, http.MethodGet, "incident")
	if err != nil {
		return status, err
	}
	return status, json.Unmarshal(data, &status)
}

// IncidentStatusControlFor keeps a manual request attached to its own result,
// even if another trigger has already started.
func IncidentStatusControlFor(ctx context.Context, socket, id string) (IncidentStatus, error) {
	var status IncidentStatus
	data, err := controlRequest(ctx, socket, http.MethodGet, "incident?id="+url.QueryEscape(id))
	if err != nil {
		return status, err
	}
	return status, json.Unmarshal(data, &status)
}
