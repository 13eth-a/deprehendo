// deprehendo-cloud is the phase 7 backend binary: migrate the schema, serve the
// upload API and dashboard reads, and manage personal tokens (7.12 server
// half).
//
// subcommands:
//
//	deprehendo-cloud migrate -database DSN [-dir db/migrations] [-down]
//	deprehendo-cloud serve   -database DSN [-addr 127.0.0.1:6080] [...]
//	deprehendo-cloud token   -database DSN -user USER -org ORG [-org-name NAME]
//	deprehendo-cloud member  -database DSN -user USER -org ORG [-role member|owner] [-remove]
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"deprehendo/internal/analyzer"
	"deprehendo/internal/clouddb"
	"deprehendo/internal/cloudserver"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "deprehendo-cloud: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError("a subcommand is required: migrate, serve, token, member, prune")
	}
	switch args[0] {
	case "migrate":
		return migrate(args[1:])
	case "serve":
		return serve(args[1:])
	case "token":
		return token(args[1:])
	case "member":
		return member(args[1:])
	case "prune":
		return prune(args[1:])
	case "-h", "--help", "help":
		fmt.Print(helpText)
		return nil
	default:
		return usageError("unknown subcommand %q", args[0])
	}
}

func usageError(format string, args ...any) error {
	fmt.Fprintf(os.Stderr, "deprehendo-cloud: "+format+"\n", args...)
	fmt.Fprint(os.Stderr, helpText)
	return errors.New("usage")
}

const helpText = `Deprehendo Cloud control plane.

  deprehendo-cloud migrate -database DSN [-dir db/migrations] [-down]
      Apply (or, with -down, roll back) the schema migrations in order. Each
      migration runs in one transaction; a failed file is never recorded.

  deprehendo-cloud serve -database DSN [options]
      Serve the upload API (docs/cloud/upload-api.md v1) and the incident
      read endpoints. The analyzer child must be an analyzer binary path
      (one child process per bundle, resource-limited).

  deprehendo-cloud token -database DSN -user USER -org ORG [-org-name NAME]
      Create a personal API token and print the raw value exactly once; it
      is stored hashed and never retrievable again.

  deprehendo-cloud member -database DSN -user USER -org ORG [-role member|owner] [-remove]
      Grant (or, with -remove, revoke) a user's membership in an
      organization. USER is the sign-in user id: the Better Auth user id for
      dashboard users (the sub claim; neon_auth."user".id on Neon). Removing a
      member takes effect on the next request.

  deprehendo-cloud prune -database DSN -older-than 90d [-limit N] [-dry-run]
      Delete uploads (rows, then objects) older than the age. Manual delete
      stays the minimum; this is the optional 7.58 time-based sweep. Run it
      with -dry-run first: it lists what would go and deletes nothing.

Flags:
  -addr HOST:PORT    serve address (default 127.0.0.1:6080)
  -database DSN      PostgreSQL URL or connection string
  -dir DIR           migrations directory (default db/migrations)
  -storage-root DIR  object storage directory (default ./storage; MVP store)
                     Set DEPREHENDO_S3_BUCKET to store objects in an S3-compatible
                     bucket instead. Credentials come only from the environment:
                     AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION and
                     AWS_ENDPOINT_URL_S3.
  -analyzer PATH     analyzer child binary (default "deprehendo-analyzer" next
                     to this binary)
  -external-url URL  base URL clients should use for dashboard and storage
                     links (default: derive from the request)
  -stats-interval D  print one telemetry summary line per interval (default
                     1m; 0 disables). Counts and latencies only.

Browser sign-in (contract §8.2, Better Auth): set DEPREHENDO_AUTH_URL to the
Better Auth base URL (for Neon Auth, the project's auth URL) and serve also
accepts dashboard session JWTs (EdDSA, verified against
DEPREHENDO_AUTH_URL/.well-known/jwks.json). Issuer and audience default to the
URL's origin; override with DEPREHENDO_AUTH_ISSUER, DEPREHENDO_AUTH_AUDIENCE and
DEPREHENDO_AUTH_JWKS_URL. Unset, the API accepts personal tokens only.

Token values, database DSNs and request bodies are never logged by this
binary; stdout errors carry no request data.
`

func migrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	dsn := fs.String("database", "", "PostgreSQL DSN")
	dir := fs.String("dir", "db/migrations", "migrations directory")
	down := fs.Bool("down", false, "roll back every applied migration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dsn == "" {
		return errors.New("migrate: -database is required")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if *down {
		undone, err := clouddb.Down(ctx, *dsn, *dir)
		if err != nil {
			return err
		}
		for _, name := range undone {
			fmt.Println("rolled back", name)
		}
		return nil
	}
	applied, err := clouddb.Apply(ctx, *dsn, *dir)
	if err != nil {
		return err
	}
	for _, name := range applied {
		fmt.Println("applied", name)
	}
	if len(applied) == 0 {
		fmt.Println("schema is current")
	}
	return nil
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dsn := fs.String("database", "", "PostgreSQL DSN")
	addr := fs.String("addr", "127.0.0.1:6080", "listen address")
	dir := fs.String("dir", "db/migrations", "migrations directory")
	storageroot := fs.String("storage-root", "./storage", "local object storage root")
	analyzerpath := fs.String("analyzer", "", "analyzer child binary (default: next to this binary)")
	externalURL := fs.String("external-url", "", "base URL for client links")
	statsinterval := fs.Duration("stats-interval", time.Minute,
		"telemetry summary interval (0 disables; counts only, never request data)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dsn == "" {
		return errors.New("serve: -database is required")
	}
	if *analyzerpath == "" {
		*analyzerpath = filepath.Join(exeDir(), "deprehendo-analyzer")
	}
	// the child runs in a private temporary directory (contract §5.4), so a
	// relative flag value passes this startup check and then fails every job
	// with "fork/exec …: no such file or directory". resolve it against the
	// operator's working directory now, once.
	if absolute, err := filepath.Abs(*analyzerpath); err == nil {
		*analyzerpath = absolute
	}
	if info, err := os.Stat(*analyzerpath); err != nil || info.IsDir() {
		return fmt.Errorf("serve: analyzer child %q is not an executable file", *analyzerpath)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// migrations before serving (7.57): a schema the code does not match
	// must stop the process, not half-serve it.
	if _, err := clouddb.Apply(ctx, *dsn, *dir); err != nil {
		return err
	}
	db, err := clouddb.Open(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	if drift, err := clouddb.AppliedButMissing(ctx, db, *dir); err != nil {
		return err
	} else if len(drift) > 0 {
		return fmt.Errorf("serve: migrations recorded but missing: %v", drift)
	}

	store, err := openStore(*storageroot)
	if err != nil {
		return err
	}
	// one logger for operational errors and the 7.55 counters. every message
	// it receives is server-produced error text or a fixed count line: no
	// token, bundle, document or runner-log content reaches it.
	logger := log.New(os.Stderr, "deprehendo-cloud: ", log.LstdFlags|log.LUTC)
	browserAuth, err := openBrowserAuth()
	if err != nil {
		return err
	}
	if browserAuth != nil {
		logger.Printf("browser sign-in enabled")
	}
	srv, err := cloudserver.New(cloudserver.Config{
		Database:    db,
		Storage:     store,
		Analyzer:    analyzer.NewRunner(*analyzerpath),
		ExternalURL: *externalURL,
		BrowserAuth: browserAuth,
		Logf:        logger.Printf,
		// SigningSecret nil: a fresh per-process secret; pending policies die
		// with restarts, which is the safe default (docs/cloud/contract.md).
	})
	if err != nil {
		return err
	}
	if *statsinterval > 0 {
		go func() {
			ticker := time.NewTicker(*statsinterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					srv.LogStats()
				}
			}
		}()
	}
	mux := http.NewServeMux()
	srv.Handler(mux)
	// timeouts (7.60): without ReadTimeout a client can trickle a body forever
	// and hold a connection (the storage POST is unauthenticated until its
	// policy verifies). ReadTimeout allows a 65 MiB bundle over a slow link;
	// WriteTimeout runs from the end of the headers, so it must cover a full
	// complete: storage read + the 60 s analyzer wall clock + document write.
	httpserver := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		shutdownctx, closectx := context.WithTimeout(context.Background(), 5*time.Second)
		defer closectx()
		_ = httpserver.Shutdown(shutdownctx)
		close(done)
	}()
	fmt.Println("serving on", *addr)
	err = httpserver.ListenAndServe()
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		<-done
		return nil
	}
	return err
}

// token creates one personal token and prints its raw value once. -org may
// name a new organization when -org-name is given.
func token(args []string) error {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	dsn := fs.String("database", "", "PostgreSQL DSN")
	user := fs.String("user", "", "library-auth user id")
	org := fs.String("org", "", "organization id, created when -org-name is given")
	orgname := fs.String("org-name", "", "name to create -org with")
	role := fs.String("role", "member", "membership role (member|owner)")
	description := fs.String("description", "", "token description")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dsn == "" {
		return errors.New("token: -database is required")
	}
	if *user == "" || *org == "" {
		return errors.New("token: -user and -org are required")
	}
	switch *role {
	case "member", "owner":
	default:
		return fmt.Errorf("token: -role must be member or owner, not %q", *role)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := clouddb.Open(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	if !orgExists(ctx, db, *org) {
		if strings.TrimSpace(*orgname) == "" {
			return fmt.Errorf("token: organization %s does not exist; pass -org-name to create it", *org)
		}
		created, err := clouddb.CreateOrganization(ctx, db, *orgname)
		if err != nil {
			return err
		}
		if created != *org {
			return fmt.Errorf("token: passed -org %s is not an organization id; created %s instead", *org, created)
		}
	}
	if err := clouddb.EnsureMembership(ctx, db, *user, *org, *role); err != nil {
		return err
	}
	raw, err := clouddb.CreateToken(ctx, db, *user, *org, *description)
	if err != nil {
		return err
	}
	// stdout only, never a log: printed exactly once, stored hashed.
	fmt.Println(raw)
	return nil
}

// member grants or revokes one membership (contract §8.2): how a dashboard
// user, identified by their better auth user id, joins an organization.
func member(args []string) error {
	fs := flag.NewFlagSet("member", flag.ExitOnError)
	dsn := fs.String("database", "", "PostgreSQL DSN")
	user := fs.String("user", "", "sign-in user id (Better Auth user id)")
	org := fs.String("org", "", "organization id")
	role := fs.String("role", "member", "membership role (member|owner)")
	remove := fs.Bool("remove", false, "revoke the membership instead")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dsn == "" || *user == "" || *org == "" {
		return errors.New("member: -database, -user and -org are required")
	}
	switch *role {
	case "member", "owner":
	default:
		return fmt.Errorf("member: -role must be member or owner, not %q", *role)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := clouddb.Open(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	if !orgExists(ctx, db, *org) {
		return fmt.Errorf("member: organization %s does not exist", *org)
	}
	if *remove {
		res, err := db.ExecContext(ctx,
			`DELETE FROM memberships WHERE user_id = $1 AND organization_id = $2`, *user, *org)
		if err != nil {
			return fmt.Errorf("member: remove: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("member: %s is not a member of %s", *user, *org)
		}
		fmt.Printf("removed %s from %s\n", *user, *org)
		return nil
	}
	// upsert, so re-running with another -role changes the role.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO memberships (user_id, organization_id, role) VALUES ($1, $2, $3)
		ON CONFLICT (user_id, organization_id) DO UPDATE SET role = EXCLUDED.role`,
		*user, *org, *role); err != nil {
		return fmt.Errorf("member: %w", err)
	}
	fmt.Printf("%s is now %s of %s\n", *user, *role, *org)
	return nil
}

// openBrowserAuth reads the browser sign-in settings from the environment.
// nothing set means the API stays token-only.
func openBrowserAuth() (*cloudserver.BrowserAuth, error) {
	authURL := strings.TrimSpace(os.Getenv("DEPREHENDO_AUTH_URL"))
	if authURL == "" {
		return nil, nil
	}
	return cloudserver.NewBrowserAuth(cloudserver.BrowserAuthConfig{
		AuthURL:  authURL,
		JWKSURL:  os.Getenv("DEPREHENDO_AUTH_JWKS_URL"),
		Issuer:   os.Getenv("DEPREHENDO_AUTH_ISSUER"),
		Audience: os.Getenv("DEPREHENDO_AUTH_AUDIENCE"),
	})
}

// prune deletes uploads older than an age (7.58 time-based retention).
func prune(args []string) error {
	fs := flag.NewFlagSet("prune", flag.ExitOnError)
	dsn := fs.String("database", "", "PostgreSQL DSN")
	dir := fs.String("dir", "db/migrations", "migrations directory")
	storageroot := fs.String("storage-root", "./storage", "local object storage root")
	olderthan := fs.String("older-than", "", "delete uploads older than this age (e.g. 90d, 2160h)")
	limit := fs.Int("limit", 1000, "maximum uploads to delete in one run")
	dryrun := fs.Bool("dry-run", false, "list what would be deleted and delete nothing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dsn == "" || *olderthan == "" {
		return errors.New("prune: -database and -older-than are required")
	}
	age, err := parseAge(*olderthan)
	if err != nil {
		return fmt.Errorf("prune: %v", err)
	}
	if *limit <= 0 {
		return errors.New("prune: -limit must be positive")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if _, err := clouddb.Apply(ctx, *dsn, *dir); err != nil {
		return err
	}
	db, err := clouddb.Open(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	store, err := openStore(*storageroot)
	if err != nil {
		return err
	}
	srv, err := cloudserver.New(cloudserver.Config{
		Database: db,
		Storage:  store,
		Analyzer: analyzer.NewRunner(filepath.Join(exeDir(), "deprehendo-analyzer")),
		Logf:     log.New(os.Stderr, "deprehendo-cloud: ", log.LstdFlags|log.LUTC).Printf,
	})
	if err != nil {
		return err
	}
	cutoff := time.Now().Add(-age)
	if *dryrun {
		plan, err := srv.PlanPrune(ctx, cutoff, *limit)
		if err != nil {
			return err
		}
		for _, e := range plan.Entries {
			fmt.Printf("would delete %s org=%s uploaded_at=%s bytes=%d\n",
				e.UploadID, e.OrganizationID, e.UploadedAt.UTC().Format(time.RFC3339), e.SizeBytes)
		}
		fmt.Printf("dry-run: uploads=%d objects=%d bundle_bytes=%d cutoff=%s\n",
			plan.Stats.Uploads, plan.Stats.Objects, plan.Stats.Bytes, cutoff.UTC().Format(time.RFC3339))
		if plan.Stats.Uploads == 0 {
			return nil
		}
		fmt.Println("nothing was deleted; rerun without -dry-run to apply")
		return nil
	}
	stats, err := srv.PruneUploadsOlderThan(ctx, cutoff, *limit)
	// print progress even when the sweep stopped, so the operator sees what
	// finished before the failure.
	fmt.Printf("pruned uploads=%d objects=%d bundle_bytes=%d older_than=%s\n",
		stats.Uploads, stats.Objects, stats.Bytes, *olderthan)
	if err != nil {
		return fmt.Errorf("prune stopped: %w", err)
	}
	return nil
}

// parseAge accepts go durations plus a day suffix (90d) the standard parser
// lacks, so an operator can write the retention policy as days.
func parseAge(s string) (time.Duration, error) {
	if d, err := time.ParseDuration(s); err == nil {
		if d <= 0 {
			return 0, fmt.Errorf("age must be positive")
		}
		return d, nil
	}
	if len(s) > 1 && s[len(s)-1] == 'd' {
		var days int64
		if _, err := fmt.Sscanf(s[:len(s)-1], "%d", &days); err == nil && days > 0 {
			return time.Duration(days) * 24 * time.Hour, nil
		}
	}
	return 0, fmt.Errorf("age %q is not a duration (try 90d or 2160h)", s)
}

// orgExists reads the organizations table; a read failure surfaces as an
// error so the caller never assumes absence of a real row.
func orgExists(ctx context.Context, db *sql.DB, id string) bool {
	var one int
	err := db.QueryRowContext(ctx, "SELECT 1 FROM organizations WHERE id = $1", id).Scan(&one)
	if err == nil {
		return true
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	// broken database: the organization cannot be assumed missing.
	fmt.Fprintln(os.Stderr, "deprehendo-cloud: token: organization lookup:", err)
	return false
}

// exeDir is the directory of this binary, for the default analyzer path.
func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

// openStore picks the object store. DEPREHENDO_S3_BUCKET selects the S3-compatible
// store. its credentials come only from the environment, never from flags, so
// they stay out of process listings and shell history.
func openStore(storageRoot string) (cloudserver.Store, error) {
	bucket := os.Getenv("DEPREHENDO_S3_BUCKET")
	if bucket == "" {
		local, err := cloudserver.NewLocalStore(storageRoot)
		if err != nil {
			return nil, err
		}
		return local, nil
	}
	return cloudserver.NewS3Store(cloudserver.S3Config{
		Endpoint:  os.Getenv("AWS_ENDPOINT_URL_S3"),
		Region:    os.Getenv("AWS_REGION"),
		Bucket:    bucket,
		AccessKey: os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
	})
}
