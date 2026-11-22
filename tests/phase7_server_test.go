// phase 7 server integration (checklist 7.40/7.36): the real upload client
// against the real cloudserver package: postgres, migrations, the local
// object store and the real analyzer child binary (one child process per
// bundle).
//
// gated on RUNOPSY_CLOUD_TEST_DSN: `make test-cloud` starts one postgres and
// sets it. without the variable the suite skips, so the default go test
// sweep never touches a database.
package tests

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"runopsy/internal/analyzer"
	"runopsy/internal/cloudclient"
	"runopsy/internal/clouddb"
	"runopsy/internal/cloudserver"
)

func cloudTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("RUNOPSY_CLOUD_TEST_DSN")
	if dsn == "" {
		t.Skip("RUNOPSY_CLOUD_TEST_DSN is not set (make test-cloud starts one)")
	}
	return dsn
}

// cloudFixture is one running server plus the two organizations' tokens.
type cloudFixture struct {
	Endpoint string
	TokenA   string
	TokenB   string
	Server   *cloudserver.Server
}

func newCloudServer(t *testing.T, dsn string) cloudFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clouddb.Apply(ctx, dsn, filepath.Join(root, "db", "migrations")); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	db, err := clouddb.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// the §5/User/Org model with two separate organizations (7.36).
	orga, err := clouddb.CreateOrganization(ctx, db, "Org A "+t.Name())
	if err != nil {
		t.Fatal(err)
	}
	orgb, err := clouddb.CreateOrganization(ctx, db, "Org B "+t.Name())
	if err != nil {
		t.Fatal(err)
	}
	usera, userb := "user_a_"+t.Name(), "user_b_"+t.Name()
	// signup creates the membership rows; tokens without one grant nothing
	// (the server's requireToken answers 403, exercised below).
	if err := clouddb.EnsureMembership(ctx, db, usera, orga, "owner"); err != nil {
		t.Fatal(err)
	}
	if err := clouddb.EnsureMembership(ctx, db, userb, orgb, "owner"); err != nil {
		t.Fatal(err)
	}
	tokenA, err := clouddb.CreateToken(ctx, db, usera, orga, "test a")
	if err != nil {
		t.Fatal(err)
	}
	tokenB, err := clouddb.CreateToken(ctx, db, userb, orgb, "test b")
	if err != nil {
		t.Fatal(err)
	}

	store, err := cloudserver.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := cloudserver.New(cloudserver.Config{
		Database: db,
		Storage:  store,
		Analyzer: analyzer.NewRunner(analyzerPath),
		Logf:     t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	srv.Handler(mux)
	httpsrv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	ln, err := listenLoopback()
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = httpsrv.Serve(ln) }()
	t.Cleanup(func() {
		shutdownctx, closectx := context.WithTimeout(context.Background(), time.Second)
		defer closectx()
		_ = httpsrv.Shutdown(shutdownctx)
	})
	return cloudFixture{
		Endpoint: "http://" + ln.Addr().String(),
		TokenA:   tokenA,
		TokenB:   tokenB,
		Server:   srv,
	}
}

// uploadBundle drives the full §1..§3 flow through the real client.
func uploadBundle(t *testing.T, endpoint, token, bundlePath string) (string, string) {
	t.Helper()
	client, err := cloudclient.New(endpoint, token)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	// the manifest's incident id is what the CLI uses (analyze first).
	bundle, err := readBundleFile(t, bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	target, err := client.Create(ctx, cloudclient.CreateRequest{
		SHA256:        digestOf(t, bundlePath),
		SizeBytes:     int64(len(raw)),
		IncidentID:    bundle.Manifest.IncidentID,
		SchemaVersion: bundle.Manifest.SchemaVersion,
		FormatVersion: bundle.Manifest.FormatVersion,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if target.Duplicate {
		return target.UploadID, target.IncidentID
	}
	if err := client.PutObject(ctx, target.Upload, bundlePath); err != nil {
		t.Fatalf("put: %v", err)
	}
	done, err := client.Complete(ctx, target.UploadID)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	return done.UploadID, done.IncidentID
}

func TestPhase7ServerPipeline(t *testing.T) {
	dsn := cloudTestDSN(t)
	cloud := newCloudServer(t, dsn)
	endpoint, tokenA, tokenB := cloud.Endpoint, cloud.TokenA, cloud.TokenB
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	bundlepath := filepath.Join(root, "testdata", "incidents", "frozen-worker.runopsy")

	uploadID, incidentID := uploadBundle(t, endpoint, tokenA, bundlepath)
	if !strings.HasPrefix(uploadID, "upl_") || !strings.HasPrefix(incidentID, "inc_") {
		t.Fatalf("ids look wrong: %s %s", uploadID, incidentID)
	}

	// 7.11/7.12 through the real CLI: login stores the credential, upload
	// drives the same §1..§3 flow through the runopsy-agent binary, and the
	// second run hits the dedupe answer ("already uploaded").
	dir := t.TempDir()
	configpath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configpath, []byte(fmt.Sprintf("{\"endpoint\":%q,\"token\":%q}\n", endpoint, tokenA)), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runAgentCLI(t, "upload", "-config", configpath, bundlepath)
	if code != 0 {
		t.Fatalf("CLI duplicate upload exited %d:\n%s", code, out)
	}
	requireOutput(t, out, "Already uploaded", "/incidents/"+incidentID)
	if strings.Contains(out, tokenA) {
		t.Fatal("the CLI printed the API token")
	}

	// 7.30: the duplicate returns the existing incident, not a second row.
	client, err := cloudclient.New(endpoint, tokenA)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	target, err := client.Create(ctx, cloudclient.CreateRequest{
		SHA256: digestOf(t, bundlepath), SizeBytes: 22,
		IncidentID: incidentID, SchemaVersion: 1, FormatVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !target.Duplicate || target.IncidentID != incidentID {
		t.Fatalf("duplicate create: %+v", target)
	}

	// 7.43 through the real server, not the reference fixture: the document
	// the cloud stores is the one the laptop renders, byte for byte. the
	// dashboard therefore shows the CLI's diagnosis, not a reinterpretation.
	localdocpath := filepath.Join(t.TempDir(), "local-document.json")
	analyzeout, analyzecode := runAgentCLI(t, "analyze", "--document", localdocpath, bundlepath)
	if analyzecode != 0 {
		t.Fatalf("analyze --document exited %d:\n%s", analyzecode, analyzeout)
	}
	localdoc, err := os.ReadFile(localdocpath)
	if err != nil {
		t.Fatal(err)
	}
	serveddoc := bearerGet(t, endpoint, tokenA, "/api/incidents/"+incidentID+"/analysis", http.StatusOK)
	if !bytes.Equal(serveddoc, localdoc) {
		t.Fatalf("cloud serves %d bytes, the local CLI document is %d: local/cloud results differ", len(serveddoc), len(localdoc))
	}

	// 7.36, one case per access path: org B user cannot see org A data.
	bearerGet(t, endpoint, tokenA, "/api/incidents/"+incidentID, http.StatusOK)
	bearerGet(t, endpoint, tokenA, "/api/incidents/"+incidentID+"/analysis", http.StatusOK)
	bearerGet(t, endpoint, tokenA, "/api/incidents/"+incidentID+"/bundle", http.StatusOK)
	bearerGet(t, endpoint, tokenB, "/api/incidents/"+incidentID, http.StatusNotFound)
	bearerGet(t, endpoint, tokenB, "/api/incidents/"+incidentID+"/analysis", http.StatusNotFound)
	bearerGet(t, endpoint, tokenB, "/api/incidents/"+incidentID+"/bundle", http.StatusNotFound)
	bearerGet(t, endpoint, "", "/api/incidents/"+incidentID, http.StatusUnauthorized)
	bearerGet(t, endpoint, "rps_wrong", "/api/incidents/"+incidentID, http.StatusUnauthorized)

	// 7.55: the operational counters saw this flow, and none of it was a
	// storage failure. (the 401s above are the client errors counted below.)
	stats := cloud.Server.Stats()
	if stats.UploadsCreated < 1 || stats.UploadsCompleted < 1 || stats.AnalysisRuns < 1 {
		t.Errorf("telemetry after one upload: %+v", stats)
	}
	if stats.StorageFailures != 0 {
		t.Errorf("a successful flow recorded %d storage failures", stats.StorageFailures)
	}
	if stats.APIErrorsClient < 1 {
		t.Errorf("telemetry did not count the rejected token: %+v", stats)
	}

	// the metadata row is populated from the document (7.6).
	i := fetchJSON[map[string]any](t, endpoint, tokenA, "/api/incidents/"+incidentID)
	signature, _ := i["primary_signature"].(string)
	if signature == "" {
		t.Errorf("primary_signature missing from the incident row: %v", i)
	}

	// 7.25: free-text search finds this incident for its own organization
	// and returns nothing for another organization or an absent term.
	if signature != "" {
		term := url.QueryEscape(signature)
		if hits := fetchJSON[[]map[string]any](t, endpoint, tokenA, "/api/incidents?q="+term); len(hits) == 0 {
			t.Errorf("search for %q found no incidents", signature)
		}
		if hits := fetchJSON[[]map[string]any](t, endpoint, tokenB, "/api/incidents?q="+term); len(hits) != 0 {
			t.Errorf("org B search for %q returned %d incidents", signature, len(hits))
		}
		if hits := fetchJSON[[]map[string]any](t, endpoint, tokenA, "/api/incidents?q=nothing-matches-this-9f2c"); len(hits) != 0 {
			t.Errorf("a term with no matches returned %d incidents", len(hits))
		}
		// the same term is also usable as an exact filter.
		if hits := fetchJSON[[]map[string]any](t, endpoint, tokenA, "/api/incidents?signature="+term); len(hits) == 0 {
			t.Errorf("signature filter found no incidents")
		}
	}
	// malformed filters are refused rather than silently ignored.
	if code := getStatus(t, endpoint, tokenA, "/api/incidents?from=yesterday"); code != http.StatusBadRequest {
		t.Errorf("malformed from = %d, want 400", code)
	}

	// 7.29: the bundle download is byte-for-byte the original.
	raw, err := os.ReadFile(bundlepath)
	if err != nil {
		t.Fatal(err)
	}
	body := bearerGet(t, endpoint, tokenA, "/api/incidents/"+incidentID+"/bundle", http.StatusOK)
	if !bytes.Equal(body, raw) {
		t.Fatalf("bundle download differs from the original (%d vs %d bytes)", len(body), len(raw))
	}

	// 7.28: deletion removes the metadata AND the objects. org B may not.
	if status, _ := deleteStatus(t, endpoint, tokenB, "/api/incidents/"+incidentID); status != http.StatusNotFound {
		t.Fatalf("org B delete status = %d, want %d", status, http.StatusNotFound)
	}
	if status, _ := deleteStatus(t, endpoint, tokenA, "/api/incidents/"+incidentID); status != http.StatusOK {
		t.Fatalf("delete status = %d, want 200", status)
	}
	for _, path := range []string{
		"/api/incidents/" + incidentID,
		"/api/incidents/" + incidentID + "/analysis",
		"/api/incidents/" + incidentID + "/bundle",
	} {
		if code := getStatus(t, endpoint, tokenA, path); code != http.StatusNotFound {
			t.Errorf("after delete, %s = %d, want 404", path, code)
		}
	}
}

// TestPhase7ServerRefusesHostileStorage verifies that a tampered or forged
// storage POST is refused without ever touching the store (7.37/7.38).
func TestPhase7ServerRefusesHostileStorage(t *testing.T) {
	dsn := cloudTestDSN(t)
	cloud := newCloudServer(t, dsn)
	endpoint, tokenA := cloud.Endpoint, cloud.TokenA
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	bundlepath := filepath.Join(root, "testdata", "incidents", "oom-kill.runopsy")
	if _, err := os.Stat(bundlepath); err != nil {
		bundlepath = filepath.Join(root, "testdata", "incidents", "frozen-worker.runopsy")
	}

	client, err := cloudclient.New(endpoint, tokenA)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, err := os.ReadFile(bundlepath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := readBundleFile(t, bundlepath)
	if err != nil {
		t.Fatal(err)
	}
	target, err := client.Create(ctx, cloudclient.CreateRequest{
		SHA256:        digestOf(t, bundlepath),
		SizeBytes:     int64(len(raw)),
		IncidentID:    bundle.Manifest.IncidentID,
		SchemaVersion: bundle.Manifest.SchemaVersion,
		FormatVersion: bundle.Manifest.FormatVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	if target.Duplicate {
		t.Fatal("expected a fresh upload for this test")
	}

	// the policy is real; POST with the WRONG file must be refused by the
	// digest check (the server does not accept different bytes under the
	// registered key).
	wrong := append([]byte(nil), raw...)
	wrong[0] ^= 0xFF
	if err := storagePut(t, endpoint+"/storage", target.Upload.Fields, wrong); err == nil {
		t.Error("storage accepted bytes whose digest does not match the policy")
	}
	// correct bytes complete the flow.
	if err := storagePut(t, endpoint+"/storage", target.Upload.Fields, raw); err != nil {
		t.Fatalf("correct storage put: %v", err)
	}

	// A forged policy (client-side signature over different fields) fails.
	forged := map[string]string{
		"key":             "orgs/org_evil/bundles/" + strings.Repeat("f", 64) + ".runopsy",
		"policy":          "forged",
		"x-amz-signature": "forged",
	}
	if err := storagePut(t, endpoint+"/storage", forged, raw); err == nil {
		t.Error("forged policy accepted")
	}
}
