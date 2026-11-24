// command deprehendo-cost measures what one incident costs to store and analyze
// (checklist 7.59). it reads the real bundles, runs the real analyzer child,
// and (given a database) inserts one incident's rows and reads their actual
// tuple sizes with pg_column_size, so the model is built from measurements
// rather than from remembered numbers.
//
//	deprehendo-cost [-bundles DIR] [-analyzer PATH] [-runs N] [-database DSN]
//
// provider bills still need a deployed system; this answers the part that can
// be answered here: bytes and seconds per incident. see
// docs/cloud/cost-measurement.md for the recorded run.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"deprehendo/internal/analysis"
	"deprehendo/internal/analyzer"
	"deprehendo/internal/clouddb"
)

// prices are list rates as of november 2026; every one is a flag so a provider
// change does not need a code change. the defaults are the ones recorded in
// docs/cloud/cost-measurement.md.
type prices struct {
	storagePerGBMonth   float64
	putPer1k            float64
	vcpuSecond          float64
	gibSecond           float64
	requestPerMillion   float64
	requestsPerIncident float64
}

func main() {
	bundles := flag.String("bundles", filepath.Join("testdata", "incidents"), "directory of .deprehendo bundles")
	analyzerpath := flag.String("analyzer", filepath.Join("bin", "deprehendo-analyzer"), "analyzer child binary (make build)")
	runs := flag.Int("runs", 5, "analysis runs per bundle; the median is reported")
	dsn := flag.String("database", "", "optional PostgreSQL DSN for real row sizes (inserted in a rolled-back transaction)")
	dir := flag.String("dir", filepath.Join("db", "migrations"), "migrations directory for -database")
	p := prices{}
	flag.Float64Var(&p.storagePerGBMonth, "storage-per-gb-month", 0.023, "object storage, USD per GB-month")
	flag.Float64Var(&p.putPer1k, "put-per-1k", 0, "object storage write requests, USD per 1,000 (Neon Object Storage has no per-operation charge)")
	flag.Float64Var(&p.vcpuSecond, "vcpu-second", 0.000024, "compute, USD per vCPU-second")
	flag.Float64Var(&p.gibSecond, "gib-second", 0.0000025, "compute memory, USD per GiB-second")
	flag.Float64Var(&p.requestPerMillion, "request-per-million", 0.40, "compute requests, USD per million")
	flag.Float64Var(&p.requestsPerIncident, "requests-per-incident", 3, "Cloud Run HTTP requests per successful upload (create, storage, complete)")
	flag.Parse()

	if *runs < 1 {
		fmt.Fprintln(os.Stderr, "deprehendo-cost: -runs must be at least 1")
		os.Exit(2)
	}
	ctx := context.Background()
	m, err := measureBundles(ctx, *bundles, *analyzerpath, *runs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "deprehendo-cost:", err)
		os.Exit(1)
	}
	m.print(os.Stdout)

	if *dsn != "" {
		rows, err := measureRows(ctx, *dsn, *dir, m)
		if err != nil {
			fmt.Fprintln(os.Stderr, "deprehendo-cost: database:", err)
			os.Exit(1)
		}
		rows.print(os.Stdout)
	}

	printCosts(os.Stdout, m, p)
}

// stats is the measured distribution of one quantity.
type stats struct {
	n      int
	sum    int64
	min    int64
	max    int64
	sorted []int64
}

func (s *stats) add(v int64) {
	if s.n == 0 {
		s.min, s.max = v, v
	}
	s.n++
	s.sum += v
	s.sorted = append(s.sorted, v)
	if v < s.min {
		s.min = v
	}
	if v > s.max {
		s.max = v
	}
}

// median sorts on first use; call sortOnce after filling.
func (s *stats) median() int64 {
	if s.n == 0 {
		return 0
	}
	sort.Slice(s.sorted, func(i, j int) bool { return s.sorted[i] < s.sorted[j] })
	return s.sorted[s.n/2]
}

func (s *stats) mean() float64 {
	if s.n == 0 {
		return 0
	}
	return float64(s.sum) / float64(s.n)
}

// measured is one run's findings.
type measured struct {
	bundles    int
	bundleSize stats // bytes
	docSize    stats // bytes
	analysisMs stats // milliseconds, median per bundle reported below
	medians    stats // per-bundle median analysis time, so the table is not skewed by a slow fixture
}

func measureBundles(ctx context.Context, dir, childPath string, runs int) (measured, error) {
	var m measured
	paths, err := filepath.Glob(filepath.Join(dir, "*.deprehendo"))
	if err != nil {
		return m, err
	}
	if len(paths) == 0 {
		return m, fmt.Errorf("no .deprehendo bundles under %s", dir)
	}
	sort.Strings(paths)
	runner := analyzer.NewRunner(childPath)
	for _, path := range paths {
		bundle, err := os.ReadFile(path)
		if err != nil {
			return m, err
		}
		m.bundles++
		m.bundleSize.add(int64(len(bundle)))
		perbundle := stats{}
		for i := 0; i < runs; i++ {
			result, err := runner.Run(ctx, bundle)
			if err != nil {
				return m, fmt.Errorf("%s: %w", filepath.Base(path), err)
			}
			if result.Status != analyzer.StatusReady {
				return m, fmt.Errorf("%s: analyzer status %s (%s)", filepath.Base(path), result.Status, result.Reason)
			}
			perbundle.add(result.Duration.Milliseconds())
			m.analysisMs.add(result.Duration.Milliseconds())
			if i == 0 {
				m.docSize.add(int64(len(result.Document)))
			}
		}
		m.medians.add(perbundle.median())
	}
	return m, nil
}

// rowSizes is what one incident adds to the database, in bytes, measured with
// pg_column_size on rows this command inserts.
type rowSizes struct {
	organizations int64
	uploads       int64
	analyses      int64
	incidents     int64
}

func (r rowSizes) total() int64 { return r.organizations + r.uploads + r.analyses + r.incidents }

func (r rowSizes) print(w *os.File) {
	fmt.Fprintf(w, "\nDatabase rows per incident (pg_column_size, one analysis row):\n")
	fmt.Fprintf(w, "  organizations %5d B (once per organization, not per incident)\n", r.organizations)
	fmt.Fprintf(w, "  uploads       %5d B\n", r.uploads)
	fmt.Fprintf(w, "  analyses      %5d B (the engine JSONB dominates)\n", r.analyses)
	fmt.Fprintf(w, "  incidents     %5d B\n", r.incidents)
	fmt.Fprintf(w, "  per incident  %5d B (+%d B once per organization)\n", r.uploads+r.analyses+r.incidents, r.organizations)
}

func measureRows(ctx context.Context, dsn, dir string, m measured) (rowSizes, error) {
	var sizes rowSizes
	if _, err := clouddb.Apply(ctx, dsn, dir); err != nil {
		return sizes, err
	}
	db, err := clouddb.Open(ctx, dsn)
	if err != nil {
		return sizes, err
	}
	defer db.Close()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return sizes, err
	}
	defer tx.Rollback() // measurement only: nothing this command inserts survives

	org, upload := "org_cost", "upl_cost"
	if _, err := tx.ExecContext(ctx, `INSERT INTO organizations (id, name) VALUES ($1, $2)`, org, "cost probe"); err != nil {
		return sizes, err
	}
	engine := analysis.EngineIdentity()
	enginejson, err := json.Marshal(engine)
	if err != nil {
		return sizes, err
	}
	enginekey, err := json.Marshal(engine)
	if err != nil {
		return sizes, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO uploads
		(id, organization_id, sha256, object_key, size_bytes, incident_id, schema_version, format_version, uploaded_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		upload, org, make([]byte, 32),
		"orgs/"+org+"/bundles/"+fmt.Sprintf("%064d", 0)+".deprehendo",
		m.bundleSize.median(), "inc_cost", 1, 1, "user_cost"); err != nil {
		return sizes, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO analyses
		(id, upload_id, engine, engine_key, status, document_key, duration_ms)
		VALUES ($1, $2, $3, $4, 'READY', $5, $6)`,
		"ana_cost", upload, enginejson, string(enginekey),
		"orgs/"+org+"/documents/"+upload+".json", int(m.medians.median())); err != nil {
		return sizes, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO incidents
		(upload_id, organization_id, external_incident_id, active_analysis_id, original_analysis_id,
		 triggered_at, primary_signature, confidence, severity, runner_name, runner_version,
		 repository, workflow, job, run_id, hostname_hash, platform, architecture)
		VALUES ($1, $2, $3, $4, $4, now(), $5, 0.9, 'high', $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		upload, org, "inc_cost", "ana_cost", "SIGNATURE_PLACEHOLDER", "runner-name", "0.9.0",
		"owner/repo", "ci", "test", "123456", "hosthash", "linux", "amd64"); err != nil {
		return sizes, err
	}

	const q = `SELECT pg_column_size(t.*) FROM %s t WHERE %s = $1`
	for _, row := range []struct {
		table, where string
		into         *int64
	}{
		{"organizations", "t.id", &sizes.organizations},
		{"uploads", "t.id", &sizes.uploads},
		{"analyses", "t.id", &sizes.analyses},
		{"incidents", "t.upload_id", &sizes.incidents},
	} {
		if err := tx.QueryRowContext(ctx, fmt.Sprintf(q, row.table, row.where), map[string]string{
			"organizations": org, "uploads": upload, "analyses": "ana_cost", "incidents": upload,
		}[row.table]).Scan(row.into); err != nil {
			return sizes, fmt.Errorf("%s row size: %w", row.table, err)
		}
	}
	return sizes, nil
}

func (m measured) print(w *os.File) {
	fmt.Fprintf(w, "Measured over %d bundles, median of per-bundle medians:\n", m.bundles)
	fmt.Fprintf(w, "  bundle bytes    mean %.0f  min %d  max %d\n", m.bundleSize.mean(), m.bundleSize.min, m.bundleSize.max)
	fmt.Fprintf(w, "  document bytes  mean %.0f  min %d  max %d\n", m.docSize.mean(), m.docSize.min, m.docSize.max)
	fmt.Fprintf(w, "  analysis        median %d ms  mean %.1f ms  min %d  max %d\n",
		m.medians.median(), float64(m.analysisMs.sum)/float64(m.analysisMs.n), m.analysisMs.min, m.analysisMs.max)
}

// printCosts applies the prices to the measured per-incident profile at the
// three volumes the checklist names.
func printCosts(w *os.File, m measured, p prices) {
	bundle := m.bundleSize.mean()
	doc := m.docSize.mean()
	seconds := float64(m.medians.median()) / 1000
	fmt.Fprintf(w, "\nPer incident: %.0f B bundle + %.0f B document, %.3f s compute at %.0f ms median\n",
		bundle, doc, seconds, float64(m.medians.median()))
	fmt.Fprintf(w, "Prices: %.4f/GB-month, %.4f/1k storage ops, %.6f/vCPU-s, %.6f/GiB-s, %.2f/M requests; %.0f requests/incident\n",
		p.storagePerGBMonth, p.putPer1k, p.vcpuSecond, p.gibSecond, p.requestPerMillion, p.requestsPerIncident)
	fmt.Fprintf(w, "\n%9s %12s %12s %18s %18s\n", "incidents", "stored GB", "storage/mo", "ops+compute", "total first month")
	for _, n := range []int{1, 100, 1000} {
		count := float64(n)
		gb := (bundle + doc) * count / 1e9
		storage := gb * p.storagePerGBMonth
		writes := 2 * count / 1000 * p.putPer1k
		compute := count * (seconds*(p.vcpuSecond+p.gibSecond) + p.requestsPerIncident*p.requestPerMillion/1e6)
		fmt.Fprintf(w, "%9d %12.6f %12.9f %18.9f %18.9f\n", n, gb, storage, writes+compute, storage+writes+compute)
	}
	fmt.Fprintf(w, "\nNot measured here: database instance/storage price, egress, backups,\n")
	fmt.Fprintf(w, "and container idle time. Those need a deployed system's bill.\n")
}
