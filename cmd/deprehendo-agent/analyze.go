package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"

	"deprehendo/internal/analysis"
	"deprehendo/internal/causal"
	"deprehendo/internal/diagnosis"
	"deprehendo/internal/incident"
	"deprehendo/internal/provider"
	"deprehendo/internal/provider/evidence"
	"deprehendo/internal/provider/github"
)

// runAnalyze implements the offline phase 3 entry point: decode a verified
// bundle, run the deterministic signature engine, and render a report.
// rendering is deterministic and contains no generated prose.
func runAnalyze(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "deprehendo-agent: analyze requires exactly one bundle")
		return 2
	}
	// flag stops at the first positional argument; pre-split with knowledge of
	// which flags take a value so `analyze FILE --explain` and
	// `analyze --min-confidence 0.7 FILE` both parse.
	valueflags := map[string]bool{"--min-confidence": true, "--disable": true, "--document": true}
	var flagArgs, positional []string
	for index := 0; index < len(args); index++ {
		a := args[index]
		switch {
		case strings.HasPrefix(a, "-") && valueflags[a]:
			if index+1 >= len(args) {
				fmt.Fprintf(stderr, "deprehendo-agent: analyze: %s requires a value\n", a)
				return 2
			}
			flagArgs = append(flagArgs, a, args[index+1])
			index++
		case strings.HasPrefix(a, "-"):
			flagArgs = append(flagArgs, a)
		default:
			positional = append(positional, a)
		}
	}
	fs := flag.NewFlagSet("deprehendo-analyzer analyze", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonoutput := fs.Bool("json", false, "machine-readable JSON output")
	explainflag := fs.Bool("explain", false, "include evidence, rejections, and missing-data details")
	reportflag := fs.Bool("report", false, "render the full human-readable incident report")
	minConfidence := fs.Float64("min-confidence", diagnosis.DefaultMinConfidence, "minimum confidence to report a diagnosis")
	disable := fs.String("disable", "", "comma-separated signature IDs to exclude from evaluation")
	document := fs.String("document", "", "write the deprehendo.analysis document as JSON to this path (- for stdout; Phase 7)")
	if err := fs.Parse(flagArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	disabled, err := parseDisable(*disable)
	if err != nil {
		fmt.Fprintf(stderr, "deprehendo-agent: analyze: %v\n", err)
		return 2
	}
	if len(positional) != 1 || math.IsNaN(*minConfidence) || *minConfidence < 0 || *minConfidence > 1 {
		fmt.Fprintln(stderr, "deprehendo-agent: analyze requires exactly one bundle path and 0 <= --min-confidence <= 1")
		return 2
	}
	bundle, err := incident.ReadFile(positional[0])
	if err != nil {
		fmt.Fprintf(stderr, "deprehendo-agent: analyze: %v\n", err)
		return 1
	}
	report, err := diagnosis.Analyze(bundle.Incident, diagnosisOptions(bundle.Incident, *minConfidence, disabled))
	if err != nil {
		fmt.Fprintf(stderr, "deprehendo-agent: analyze: %v\n", err)
		return 1
	}
	providerreport := provider.Default.InterpretAll(bundle.Incident.Providers, bundle.Incident)
	_, graph, err := buildCausalGraph(bundle.Incident)
	if err != nil {
		fmt.Fprintf(stderr, "deprehendo-agent: analyze: %v\n", err)
		return 1
	}
	failures := graph.FailureAnalyses()
	if *jsonoutput {
		return writeJSONWithProviderReport(report, providerreport, failures, stdout, stderr)
	}
	if *reportflag {
		if err := renderGitHubSummary(stdout, bundle.Incident.Providers, bundle.Incident.CaptureStart, bundle.Incident.CaptureEnd); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if err := writeTextReport(report, *explainflag || *reportflag, stdout); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	// analyze reads the same bundle the timeline does, so the causal chain
	// carries the same per-link evidence class (6.62).
	if err := renderCausal(stdout, graph, newQualityResolver(bundle.Incident)); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := renderProviderReport(stdout, bundle.Incident.Providers, providerreport); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	// the document is the phase 7 stored analysis (contract §3.3): it comes
	// from analysis.Run, the same package the worker uses, so the bytes a
	// dashboard stores are the bytes this CLI writes for the same bundle.
	if *document != "" {
		if code := writeDocument(bundle, positional[0], *document, *minConfidence, disabled, stdout, stderr); code != 0 {
			return code
		}
	}
	return 0
}

// writeDocument renders the deprehendo.analysis document for one bundle.
func writeDocument(bundle *incident.Bundle, path, destination string, minConfidence float64, disabled []diagnosis.SignatureID, stdout, stderr io.Writer) int {
	raw, err := readBundleBytes(path)
	if err != nil {
		fmt.Fprintf(stderr, "deprehendo-agent: analyze: %v\n", err)
		return 1
	}
	doc, err := analysis.Run(bundle, analysis.SHA256OfBytes(raw), analysis.Options{MinConfidence: minConfidence, Disabled: disabled})
	if err != nil {
		fmt.Fprintf(stderr, "deprehendo-agent: analyze: %v\n", err)
		return 1
	}
	var out io.Writer = stdout
	if destination != "-" {
		f, err := os.Create(destination)
		if err != nil {
			fmt.Fprintf(stderr, "deprehendo-agent: analyze: %v\n", err)
			return 1
		}
		defer f.Close()
		if err := f.Chmod(0600); err != nil {
			fmt.Fprintf(stderr, "deprehendo-agent: analyze: %v\n", err)
			return 1
		}
		out = f
	}
	if err := analysis.WriteJSON(out, doc); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

// readBundleBytes reads one bundle file with the reader's size budget.
func readBundleBytes(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("incident: bundle must be a regular file")
	}
	if st.Size() > incident.MaxArchiveSize {
		return nil, fmt.Errorf("incident: archive size exceeds budget")
	}
	return os.ReadFile(path)
}

// writeJSONWithProviderReport keeps the generic diagnosis schema and adds the
// independently interpreted provider evidence and causal failures beside it.
func writeJSONWithProviderReport(report *diagnosis.Report, interpreted []provider.Interpretation, failures []causal.FailureAnalysis, stdout, stderr io.Writer) int {
	if failures == nil {
		failures = []causal.FailureAnalysis{}
	}
	data, err := json.MarshalIndent(struct {
		*diagnosis.Report
		Providers []provider.Interpretation `json:"providers,omitempty"`
		Failures  []causal.FailureAnalysis  `json:"failures"`
	}{Report: report, Providers: interpreted, Failures: failures}, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "deprehendo-agent: analyze: %v\n", err)
		return 1
	}
	if _, err := stdout.Write(append(data, '\n')); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func renderProviderReport(w io.Writer, sections []evidence.Section, interpreted []provider.Interpretation) error {
	if len(sections) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(w, "\nPROVIDER EVIDENCE"); err != nil {
		return err
	}
	for _, section := range sections {
		var interpretation *provider.Interpretation
		for index := range interpreted {
			if interpreted[index].Provider == section.Provider {
				interpretation = &interpreted[index]
				break
			}
		}
		if _, err := fmt.Fprintf(w, "%s  health=%s\n", section.Provider, section.Health.State); err != nil {
			return err
		}
		for _, runner := range section.Runners {
			if _, err := fmt.Fprintf(w, "  Runner %s version=%s lifecycle=%s\n", providerText(runner.Name), providerText(runner.Version), runner.Lifecycle); err != nil {
				return err
			}
		}
		for _, job := range section.Jobs {
			if _, err := fmt.Fprintf(w, "  job %s repository=%s workflow=%s name=%s run=%s attempt=%s outcome=%s\n", job.Ref, providerText(job.Repository), providerText(job.Workflow), providerText(job.Name), providerInt(job.RunID), providerInt(job.Attempt), job.Outcome); err != nil {
				return err
			}
			if !job.StartedAt.IsZero() {
				if _, err := fmt.Fprintf(w, "    job started=%s source=%s\n", job.StartedAt.UTC().Format(time.RFC3339), job.StartedAtSource); err != nil {
					return err
				}
			}
			if !job.CompletedAt.IsZero() {
				if _, err := fmt.Fprintf(w, "    job completed=%s source=%s\n", job.CompletedAt.UTC().Format(time.RFC3339), job.CompletedAtSource); err != nil {
					return err
				}
			}
		}
		for _, conflict := range section.Conflicts {
			if _, err := fmt.Fprintf(w, "  PROVIDER_STATE_CONFLICT topic=%s claims=%d\n", conflict.Question, len(conflict.Claims)); err != nil {
				return err
			}
		}
		if interpretation != nil {
			for _, event := range interpretation.Generic {
				if _, err := fmt.Fprintf(w, "  %s %s source=%s\n", event.Timestamp.UTC().Format(time.RFC3339), event.Kind, event.Source); err != nil {
					return err
				}
			}
			for _, sig := range interpretation.Signatures {
				if _, err := fmt.Fprintf(w, "  SIGNATURE %s onset=%s confidence=%s runner=%s job=%s\n", sig.Label, sig.Onset.UTC().Format(time.RFC3339), sig.Confidence, sig.Runner, sig.Job); err != nil {
					return err
				}
			}
		}
		if section.Provider == github.Name {
			if err := renderGitHubTimeline(w, []evidence.Section{section}); err != nil {
				return err
			}
		}
	}
	return nil
}

func providerText(value evidence.Text) string {
	switch value.State {
	case evidence.Known:
		return value.Value
	case evidence.Withheld:
		return "WITHHELD"
	default:
		return "UNKNOWN"
	}
}

func providerInt(value evidence.Int64) string {
	switch value.State {
	case evidence.Known:
		return fmt.Sprintf("%d", value.Value)
	case evidence.Withheld:
		return "WITHHELD"
	default:
		return "UNKNOWN"
	}
}

// parseDisable splits a comma-separated --disable value into signature IDs.
// empty tokens are rejected: silently ignoring them would make a typo look
// like a valid disable.
func parseDisable(value string) ([]diagnosis.SignatureID, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var out []diagnosis.SignatureID
	for _, part := range strings.Split(value, ",") {
		id := strings.TrimSpace(part)
		if id == "" {
			return nil, errors.New("--disable contains an empty signature ID")
		}
		out = append(out, diagnosis.SignatureID(id))
	}
	return out, nil
}

func writeJSONReport(report *diagnosis.Report, stdout, stderr io.Writer) int {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "deprehendo-agent: analyze: %v\n", err)
		return 1
	}
	data = append(data, '\n')
	if _, err := stdout.Write(data); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

// writeTextReport renders the human-readable report. everything comes from
// structured evidence, so the same bundle always renders identically.
func writeTextReport(report *diagnosis.Report, explain bool, stdout io.Writer) error {
	var b strings.Builder
	line := "----------------------------------------------------------------"
	fmt.Fprintf(&b, "%s\nDEPREHENDO INCIDENT ANALYSIS\n", line)
	fmt.Fprintf(&b, "Incident: %s    Analyzer: %s    Signature set: %d\n", report.IncidentID, report.Analyzer, report.SignatureSet)
	fmt.Fprintf(&b, "Trigger: %s", report.Trigger)
	if !report.TriggeredAt.IsZero() {
		fmt.Fprintf(&b, " at %s", formatEvidenceTime(report.TriggeredAt))
	}
	b.WriteString("\n")

	if report.Unknown {
		fmt.Fprintf(&b, "\nROOT CAUSE\nUnknown\n\nNo known signature met its evidence requirements and the %.2f confidence threshold.\n", report.MinConfidence)
		if len(report.StrongObservations) > 0 {
			fmt.Fprintf(&b, "\nStrong observations:\n")
			for _, ev := range report.StrongObservations {
				fmt.Fprintf(&b, "- %s (%s at %s)\n", ev.Code, ev.Source, formatEvidenceTime(ev.At))
			}
		}
	}

	for _, match := range report.Matches {
		if len(report.Matches) == 1 {
			fmt.Fprintf(&b, "\nPrimary diagnosis\n%s\n", match.SignatureID)
		} else if len(report.Matches) > 1 {
			fmt.Fprintf(&b, "\nDiagnosis\n%s\n", match.SignatureID)
		} else {
			fmt.Fprintf(&b, "\nAlternative candidate\n%s\n", match.SignatureID)
		}
		fmt.Fprintf(&b, "Confidence\n%s — %.2f   Severity: %s\n", match.Band, match.Confidence, match.Severity)
		if match.Summary != "" {
			fmt.Fprintf(&b, "%s\n", match.Summary)
		}
		if len(match.Supporting) > 0 {
			fmt.Fprintf(&b, "\nSupporting evidence:\n")
			for _, ev := range match.Supporting {
				fmt.Fprintf(&b, "+ %s\n", describeEvidence(ev))
			}
		}
		if len(match.Contradicting) > 0 {
			fmt.Fprintf(&b, "\nContradicting evidence:\n")
			for _, ev := range match.Contradicting {
				fmt.Fprintf(&b, "- %s\n", describeEvidence(ev))
			}
		}
		if len(match.MissingEvidence) > 0 {
			fmt.Fprintf(&b, "\nUnknown evidence: %s\n", strings.Join(match.MissingEvidence, ", "))
		}
		if attrs := sortedAttributes(match); len(attrs) > 0 {
			fmt.Fprintf(&b, "Attributes:\n")
			for _, kv := range attrs {
				fmt.Fprintf(&b, "  %s=%s\n", kv[0], kv[1])
			}
		}
	}

	if len(report.Ambiguous) > 0 {
		fmt.Fprintln(&b, "\nAmbiguous rival explanations:")
		for _, pair := range report.Ambiguous {
			fmt.Fprintln(&b, "- "+pair)
		}
	}

	if explain {
		for _, rejection := range report.Rejections {
			fmt.Fprintf(&b, "\n%s rejected: %s", rejection.SignatureID, rejection.Rejected)
			if rejection.Confidence > 0 {
				fmt.Fprintf(&b, " (scored %.2f)", rejection.Confidence)
			}
			b.WriteString("\n")
			if len(rejection.Supporting) > 0 {
				fmt.Fprintln(&b, "Supporting observations (insufficient for diagnosis):")
				for _, ev := range rejection.Supporting {
					fmt.Fprintf(&b, "+ %s\n", describeEvidence(ev))
				}
			}
			if len(rejection.Contradicting) > 0 {
				fmt.Fprintf(&b, "Against:\n")
				for _, ev := range rejection.Contradicting {
					fmt.Fprintf(&b, "- %s\n", describeEvidence(ev))
				}
			}
			if len(rejection.MissingEvidence) > 0 {
				fmt.Fprintf(&b, "Unknown: %s\n", strings.Join(rejection.MissingEvidence, ", "))
			}
		}

	} else if len(report.Rejections) > 0 {
		// without --explain the report still names rejected candidates at
		// the threshold: no evidence detail, just the ranking.
		fmt.Fprintf(&b, "\nRejected alternatives:\n")
		for i, rejection := range report.Rejections {
			if i >= 4 {
				break
			}
			fmt.Fprintf(&b, "%-28s %.2f\n", rejection.SignatureID, rejection.Confidence)
		}
	}

	if len(report.Matches) == 0 && !report.Unknown {
		fmt.Fprintf(&b, "\nNo signature matched.\n")
	}
	b.WriteString(line + "\n")
	_, err := io.WriteString(stdout, b.String())
	return err
}

// describeEvidence renders one evidence item deterministically: code, the
// observed/threshold pair when present, provenance, and time.
func describeEvidence(ev diagnosis.Evidence) string {
	parts := []string{string(ev.Code)}
	if ev.Observed != nil {
		parts = append(parts, evidenceValue(ev.Observed))
	}
	if ev.Threshold != nil {
		parts = append(parts, fmt.Sprintf("threshold %s", evidenceValue(ev.Threshold)))
	}
	if !ev.At.IsZero() {
		parts = append(parts, "at "+formatEvidenceTime(ev.At))
	}
	return strings.Join(parts, " ") + fmt.Sprintf(" (%s)", ev.Source)
}

// evidenceValue renders observed values compactly and deterministically
// without reflection magic: maps render as key=value pairs sorted by key.
func evidenceValue(value any) string {
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		for i := 1; i < len(keys); i++ {
			for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
				keys[j-1], keys[j] = keys[j], keys[j-1]
			}
		}
		pairs := make([]string, 0, len(keys))
		for _, key := range keys {
			pairs = append(pairs, fmt.Sprintf("%s=%s", key, evidenceValue(v[key])))
		}
		return strings.Join(pairs, ",")
	case float64:
		return fmt.Sprintf("%.2f", v)
	case bool:
		return fmt.Sprintf("%t", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func sortedAttributes(match diagnosis.SignatureMatch) [][2]string {
	if len(match.Attributes) == 0 {
		return nil
	}
	keys := make([]string, 0, len(match.Attributes))
	for key := range match.Attributes {
		keys = append(keys, key)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	out := make([][2]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, [2]string{key, match.Attributes[key]})
	}
	return out
}

func formatEvidenceTime(t interface {
	Format(string) string
	UTC() time.Time
}) string {
	return t.UTC().Format("15:04:05.000Z")
}
