package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"runopsy/internal/cloudclient"
	"runopsy/internal/incident"
	"runopsy/internal/uploadqueue"
)

// stdin is the reader login uses for a pasted token. it is a variable so tests
// can drive the prompt without owning the process stdin.
var stdin io.Reader = os.Stdin

// cloudConfig is the local credential file (7.12). the token is stored beside
// the endpoint, never inside a bundle, and the file is kept at 0600.
//
// AutoUpload is the 7.46 opt-in: when true, a completed incident is queued for
// upload after it is saved locally. absent (the zero value) means manual
// `upload` only, which is what the roadmap asks for until manual upload is
// routine.
type cloudConfig struct {
	Endpoint   string `json:"endpoint"`
	Token      string `json:"token"`
	AutoUpload bool   `json:"auto_upload,omitempty"`
}

// defaultQueuePath is the upload queue beside the credential file: same
// private directory, one file per agent configuration.
func defaultQueuePath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "queue.json")
}

// defaultCloudConfigPath is ~/.config/runopsy/config.json on linux and the
// platform equivalent elsewhere (os.UserConfigDir).
func defaultCloudConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "runopsy", "config.json")
}

func readCloudConfig(path string) (cloudConfig, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cloudConfig{}, fmt.Errorf("no cloud credentials at %s; run `runopsy-agent login -endpoint URL` first", path)
		}
		return cloudConfig{}, fmt.Errorf("read cloud config: %w", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return cloudConfig{}, fmt.Errorf("cloud config %s has permissions %04o; it holds a token, so make it 0600", path, perm)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cloudConfig{}, fmt.Errorf("read cloud config: %w", err)
	}
	var cfg cloudConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cloudConfig{}, fmt.Errorf("cloud config %s is not valid JSON: %w", path, err)
	}
	if cfg.Endpoint == "" || cfg.Token == "" {
		return cloudConfig{}, fmt.Errorf("cloud config %s needs both endpoint and token; run `runopsy-agent login` again", path)
	}
	if _, err := cloudclient.NormalizeEndpoint(cfg.Endpoint); err != nil {
		return cloudConfig{}, fmt.Errorf("cloud config %s: %w", path, err)
	}
	return cfg, nil
}

// writeCloudConfig writes the credential file atomically at 0600 inside a
// directory at 0700, so a crash cannot leave a half-written or world-readable
// token behind.
func writeCloudConfig(path string, cfg cloudConfig) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode cloud config: %w", err)
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(dir, ".config-*.json")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	tmpname := tmp.Name()
	defer os.Remove(tmpname)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("restrict config permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write cloud config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close cloud config: %w", err)
	}
	if err := os.Rename(tmpname, path); err != nil {
		return fmt.Errorf("install cloud config: %w", err)
	}
	return nil
}

func runLogin(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("runopsy-agent login", flag.ContinueOnError)
	fs.SetOutput(stderr)
	endpoint := fs.String("endpoint", "", "Runopsy Cloud endpoint (e.g. https://runopsy.example.com)")
	tokenfile := fs.String("token-file", "", "read the personal API token from this file instead of stdin")
	configpath := fs.String("config", defaultCloudConfigPath(), "credential file (default ~/.config/runopsy/config.json)")
	autoUpload := fs.Bool("auto-upload", false, "queue every completed incident for upload (7.46)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "runopsy-agent login: unexpected arguments")
		return 2
	}
	if *endpoint == "" {
		fmt.Fprintln(stderr, "runopsy-agent login: --endpoint is required (7.11/7.12)")
		return 2
	}
	normalized, err := cloudclient.NormalizeEndpoint(*endpoint)
	if err != nil {
		fmt.Fprintf(stderr, "runopsy-agent login: %v\n", err)
		return 2
	}

	var raw []byte
	if *tokenfile != "" {
		raw, err = os.ReadFile(*tokenfile)
		if err != nil {
			fmt.Fprintf(stderr, "runopsy-agent login: %v\n", err)
			return 1
		}
	} else {
		// terminal echo is the terminal's business (no term dependency here);
		// the token is stored only in the 0600 config file.
		fmt.Fprint(stderr, "Paste your Runopsy API token, then press Ctrl-D: ")
		raw, err = io.ReadAll(io.LimitReader(stdin, 4096))
		if err != nil {
			fmt.Fprintf(stderr, "runopsy-agent login: read token: %v\n", err)
			return 1
		}
	}
	token := strings.TrimSpace(string(raw))
	token = strings.TrimPrefix(token, "Bearer ")
	if token == "" {
		fmt.Fprintln(stderr, "runopsy-agent login: no token provided")
		return 1
	}
	if strings.ContainsAny(token, " \t\r\n") {
		fmt.Fprintln(stderr, "runopsy-agent login: token must be a single line without spaces")
		return 1
	}

	if _, err := cloudclient.New(normalized, token); err != nil {
		fmt.Fprintf(stderr, "runopsy-agent login: %v\n", err)
		return 1
	}
	if err := writeCloudConfig(*configpath, cloudConfig{Endpoint: normalized, Token: token, AutoUpload: *autoUpload}); err != nil {
		fmt.Fprintf(stderr, "runopsy-agent login: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Logged in to %s\nCredentials saved to %s (0600)\n", normalized, *configpath)
	if *autoUpload {
		fmt.Fprintf(stdout, "Auto-upload: on; queue %s\n", defaultQueuePath(*configpath))
	}
	return 0
}

// uploadResult is the outcome of sending one bundle.
type uploadResult struct {
	IncidentID string
	URL        string
	Duplicate  bool
}

// sendBundle validates a bundle locally, hashes the exact bytes it sends and
// drives the §1..§3 flow. it is the one implementation behind both `upload`
// and the auto-upload queue, so the two cannot diverge.
func sendBundle(ctx context.Context, client *cloudclient.Client, bundlePath string, progress func(format string, args ...any)) (uploadResult, error) {
	if progress == nil {
		progress = func(string, ...any) {}
	}
	info, err := os.Stat(bundlePath)
	if err != nil {
		return uploadResult{}, err
	}
	if info.Size() > incident.MaxArchiveSize {
		return uploadResult{}, fmt.Errorf("%s is %d bytes, above the %d-byte bundle limit", bundlePath, info.Size(), int64(incident.MaxArchiveSize))
	}
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		return uploadResult{}, err
	}
	bundle, err := incident.Read(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return uploadResult{}, fmt.Errorf("%s is not a valid bundle: %w", bundlePath, err)
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])

	progress("Uploading incident %s...\n", bundle.Manifest.IncidentID)
	progress("Validated\n")

	createctx, cancelcreate := context.WithTimeout(ctx, time.Minute)
	created, err := client.Create(createctx, cloudclient.CreateRequest{
		SHA256:        digest,
		SizeBytes:     int64(len(raw)),
		IncidentID:    bundle.Manifest.IncidentID,
		SchemaVersion: bundle.Manifest.SchemaVersion,
		FormatVersion: bundle.Manifest.FormatVersion,
	})
	cancelcreate()
	if err != nil {
		return uploadResult{}, err
	}
	if created.Duplicate {
		progress("Already uploaded\n%s\n", created.URL)
		return uploadResult{IncidentID: created.IncidentID, URL: created.URL, Duplicate: true}, nil
	}

	// large bundles legitimately take minutes; the storage POST gets its own
	// deadline instead of the API's one-minute one.
	uploadctx, cancelupload := context.WithTimeout(ctx, 10*time.Minute)
	err = client.PutObject(uploadctx, created.Upload, bundlePath)
	cancelupload()
	if err != nil {
		return uploadResult{}, err
	}

	completectx, cancelcomplete := context.WithTimeout(ctx, time.Minute)
	done, err := client.Complete(completectx, created.UploadID)
	cancelcomplete()
	if err != nil {
		return uploadResult{}, err
	}
	if done.Duplicate {
		progress("Already uploaded\n%s\n", done.URL)
		return uploadResult{IncidentID: done.IncidentID, URL: done.URL, Duplicate: true}, nil
	}
	progress("Uploaded\n%s\n", done.URL)
	return uploadResult{IncidentID: done.IncidentID, URL: done.URL}, nil
}

func runUpload(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("runopsy-agent upload", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configpath := fs.String("config", defaultCloudConfigPath(), "credential file (default ~/.config/runopsy/config.json)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "runopsy-agent upload: usage: upload [-config FILE] PATH")
		return 2
	}
	bundlepath := fs.Arg(0)

	cfg, err := readCloudConfig(*configpath)
	if err != nil {
		fmt.Fprintf(stderr, "runopsy-agent upload: %v\n", err)
		return 1
	}
	client, err := cloudclient.New(cfg.Endpoint, cfg.Token)
	if err != nil {
		fmt.Fprintf(stderr, "runopsy-agent upload: %v\n", err)
		return 1
	}

	// validation and hashing happen before any network call: a corrupt bundle
	// is refused locally, and the digest the server records is of the exact
	// bytes sent.
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	_, err = sendBundle(ctx, client, bundlepath, func(format string, args ...any) {
		fmt.Fprintf(stdout, format, args...)
	})
	if err != nil {
		fmt.Fprintf(stderr, "runopsy-agent upload: %v\n", uploadHint(err))
		return 1
	}
	return 0
}

// queueUploader sends one queued bundle through the same sendBundle path the
// manual command uses.
type queueUploader struct {
	client *cloudclient.Client
}

func (u queueUploader) Upload(ctx context.Context, bundlePath string) (string, error) {
	res, err := sendBundle(ctx, u.client, bundlePath, nil)
	if err != nil {
		return "", err
	}
	return res.URL, nil
}

// autoUploadInterval is how often the agent retries queued uploads. the
// per-entry backoff decides whether anything is actually due; this only sets
// how promptly a due entry is noticed.
const autoUploadInterval = 30 * time.Second

// autoUpload is the 7.46 hook: a completed incident is queued locally and sent
// in the background. the queue is fed after the bundle is written, so nothing
// here can lose an incident.
type autoUpload struct {
	uploader queueUploader
	queue    *uploadqueue.Queue
	logger   *slog.Logger
}

// newAutoUpload builds the hook from the credential file. it returns
// (nil, nil) when there is no credential file or it does not opt in: auto
// upload is off unless the user asked. an unreadable or malformed file is an
// error the caller reports while recording continues.
func newAutoUpload(configPath string, logger *slog.Logger) (*autoUpload, error) {
	if _, err := os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	cfg, err := readCloudConfig(configPath)
	if err != nil {
		return nil, err
	}
	if !cfg.AutoUpload {
		return nil, nil
	}
	client, err := cloudclient.New(cfg.Endpoint, cfg.Token)
	if err != nil {
		return nil, err
	}
	queue, err := uploadqueue.Open(defaultQueuePath(configPath), uploadqueue.DefaultPolicy())
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &autoUpload{uploader: queueUploader{client: client}, queue: queue, logger: logger}, nil
}

// OnSaved queues one completed incident. A queue problem is logged and the
// incident stays local: the bundle is already on disk.
func (a *autoUpload) OnSaved(id, path string) {
	entry, added, err := a.queue.Enqueue(path)
	if err != nil {
		a.logger.Warn("auto-upload: incident stays local", "id", id, "error", err)
		return
	}
	if !added {
		return
	}
	a.logger.Info("auto-upload: incident queued", "id", id, "queue", a.queue.Path(), "next_attempt", entry.NextAttempt)
}

// DrainLoop attempts due uploads immediately and then on a fixed interval
// until ctx is cancelled. bounded backoff lives in the queue, not here.
func (a *autoUpload) DrainLoop(ctx context.Context) {
	ticker := time.NewTicker(autoUploadInterval)
	defer ticker.Stop()
	for {
		a.Drain(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// drain runs one pass and logs the counters when something was attempted.
func (a *autoUpload) Drain(ctx context.Context) uploadqueue.Result {
	res, err := a.queue.Drain(ctx, a.uploader)
	if err != nil {
		a.logger.Warn("auto-upload: queue state could not be saved", "error", err)
		return res
	}
	if res.Attempted > 0 {
		a.logger.Info("auto-upload: queue drained",
			"attempted", res.Attempted, "uploaded", res.Uploaded,
			"retrying", res.Retrying, "failed", res.Failed)
	}
	return res
}

// runQueue inspects and drains the local upload queue (7.47/7.48). it exits 0
// when uploads are merely deferred: being offline is not an error, and the
// incidents stay local.
func runQueue(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("runopsy-agent queue", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configpath := fs.String("config", defaultCloudConfigPath(), "credential file (default ~/.config/runopsy/config.json)")
	queuepath := fs.String("queue", "", "queue file (default: beside the credential file)")
	retryfailed := fs.Bool("retry", false, "reset failed entries for another attempt")
	nodrain := fs.Bool("no-drain", false, "only report the queue; do not upload")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "runopsy-agent queue: unexpected arguments")
		return 2
	}
	path := *queuepath
	if path == "" {
		path = defaultQueuePath(*configpath)
	}
	queue, err := uploadqueue.Open(path, uploadqueue.DefaultPolicy())
	if err != nil {
		fmt.Fprintf(stderr, "runopsy-agent queue: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Queue %s\n", queue.Path())
	printQueueSummary(stdout, queue.Summary())

	if *retryfailed {
		n, err := queue.Retry()
		if err != nil {
			fmt.Fprintf(stderr, "runopsy-agent queue: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Reset %d failed entries\n", n)
	}
	if *nodrain {
		return 0
	}

	cfg, err := readCloudConfig(*configpath)
	if err != nil {
		fmt.Fprintf(stderr, "runopsy-agent queue: %v\n", err)
		return 1
	}
	client, err := cloudclient.New(cfg.Endpoint, cfg.Token)
	if err != nil {
		fmt.Fprintf(stderr, "runopsy-agent queue: %v\n", err)
		return 1
	}
	res, err := queue.Drain(context.Background(), queueUploader{client: client})
	if err != nil {
		fmt.Fprintf(stderr, "runopsy-agent queue: %v\n", err)
		return 1
	}
	if res.Attempted == 0 {
		fmt.Fprintln(stdout, "Nothing due")
	} else {
		fmt.Fprintf(stdout, "Attempted %d: uploaded %d, deferred %d, failed %d\n",
			res.Attempted, res.Uploaded, res.Retrying, res.Failed)
	}
	if res.Retrying > 0 {
		fmt.Fprintln(stdout, "Upload deferred; the incident stays local and is retried later")
	}
	printQueueSummary(stdout, queue.Summary())
	return 0
}

// printQueueSummary renders the three states (7.47) on one line.
func printQueueSummary(stdout io.Writer, s uploadqueue.Summary) {
	fmt.Fprintf(stdout, "pending %d, uploaded %d, failed %d\n", s.Pending, s.Uploaded, s.Failed)
}

// uploadHint turns the API's unambiguous statuses into the action the user
// needs (7.11's "uploading … validated … uploaded" flow should only fail with
// something the user can do).
func uploadHint(err error) string {
	var apiErr *cloudclient.Error
	if !errors.As(err, &apiErr) {
		return cloudclient.SanitizeServerText(err.Error())
	}
	switch apiErr.Status {
	case 401:
		return "not authenticated: run `runopsy-agent login -endpoint URL` again"
	case 413:
		return "bundle too large for this server: " + cloudclient.SanitizeServerText(apiErr.Message)
	case 429:
		return "rate limited, try again later: " + cloudclient.SanitizeServerText(apiErr.Message)
	default:
		return cloudclient.SanitizeServerText(err.Error())
	}
}
