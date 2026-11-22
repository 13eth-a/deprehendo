package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"runopsy/internal/analysis"
	"runopsy/internal/causal"
	"runopsy/internal/diagnosis"
	"runopsy/internal/incident"
	"runopsy/internal/provider"
	"runopsy/internal/provider/evidence"
)

// TimelineOutput is the stable JSON shape for 4.33/4.44/4.45. failure
// explanation is the per-anchor "failures" array (§5.2): every failure anchor
// gets one analysis, so an unknown cause is never suppressed because another
// anchor has a candidate.
type TimelineOutput struct {
	IncidentID       string                    `json:"incident_id"`
	Origin           time.Time                 `json:"origin"`
	Events           []causal.Event            `json:"events"`
	Edges            []causal.CausalEdge       `json:"edges"`
	RejectedEdges    []causal.RejectedEdge     `json:"rejected_edges,omitempty"`
	Failures         []causal.FailureAnalysis  `json:"failures"`
	Healthy          bool                      `json:"healthy"`
	Diagnosis        *diagnosis.Report         `json:"diagnosis,omitempty"`
	Providers        []provider.Interpretation `json:"providers,omitempty"`
	ProviderEvidence []evidence.Section        `json:"provider_evidence,omitempty"`
}

func runTimeline(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "runopsy-agent: timeline requires exactly one bundle")
		return 2
	}
	valueflags := map[string]bool{"--explain-edge": true, "--min-confidence": true, "--disable": true}
	flagargs, positional := splitValueFlags(args, valueflags)
	fs := flag.NewFlagSet("runopsy-agent timeline", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonoutput := fs.Bool("json", false, "machine-readable timeline and causal graph")
	causalflag := fs.Bool("causal", false, "include rule-backed causal graph and root candidates")
	explainedge := fs.String("explain-edge", "", "explain an edge by stable edge ID or zero-based index")
	combined := fs.Bool("report", false, "include Phase 3 signature diagnosis in the causal report")
	minconfidence := fs.Float64("min-confidence", diagnosis.DefaultMinConfidence, "minimum Phase 3 diagnosis confidence")
	disable := fs.String("disable", "", "comma-separated Phase 3 signature IDs to exclude")
	if err := fs.Parse(flagargs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	disabled, err := parseDisable(*disable)
	if err != nil {
		fmt.Fprintf(stderr, "runopsy-agent: timeline: %v\n", err)
		return 2
	}
	if len(positional) != 1 || *minconfidence < 0 || *minconfidence > 1 {
		fmt.Fprintln(stderr, "runopsy-agent: timeline requires exactly one bundle and 0 <= --min-confidence <= 1")
		return 2
	}
	bundle, err := incident.ReadFile(positional[0])
	if err != nil {
		fmt.Fprintf(stderr, "runopsy-agent: timeline: %v\n", err)
		return 1
	}
	timeline, graph, err := buildCausalGraph(bundle.Incident)
	if err != nil {
		fmt.Fprintf(stderr, "runopsy-agent: timeline: %v\n", err)
		return 1
	}

	var report *diagnosis.Report
	if *combined {
		report, err = diagnosis.Analyze(bundle.Incident, diagnosisOptions(bundle.Incident, *minconfidence, disabled))
		if err != nil {
			fmt.Fprintf(stderr, "runopsy-agent: timeline: diagnosis: %v\n", err)
			return 1
		}
		linkDiagnoses(report, timeline)
	}
	failures := graph.FailureAnalyses()
	consistency := crossCheckDiagnoses(report, graph)
	if len(consistency) > 0 {
		fmt.Fprintf(stderr, "runopsy-agent: timeline: Phase 3/Phase 4 consistency warning: %s\n", strings.Join(consistency, "; "))
	}
	providerreport := provider.Default.InterpretAll(bundle.Incident.Providers, bundle.Incident)
	output := TimelineOutput{
		Providers:        providerreport,
		ProviderEvidence: bundle.Incident.Providers,
		IncidentID:       bundle.Incident.ID,
		Origin:           timeline.Origin,
		Events:           timeline.Events,
		Edges:            graph.Edges,
		RejectedEdges:    graph.Rejected,
		Failures:         failures,
		Healthy:          graph.Healthy(),
		Diagnosis:        report,
	}
	if output.Edges == nil {
		output.Edges = []causal.CausalEdge{}
	}
	if output.Failures == nil {
		output.Failures = []causal.FailureAnalysis{}
	}
	if *explainedge != "" {
		index, err := resolveEdge(*explainedge, graph.Edges)
		if err != nil {
			fmt.Fprintf(stderr, "runopsy-agent: timeline: %v\n", err)
			return 2
		}
		text, err := graph.Explain(index)
		if err != nil {
			fmt.Fprintf(stderr, "runopsy-agent: timeline: %v\n", err)
			return 1
		}
		_, err = io.WriteString(stdout, text)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	if *jsonoutput {
		data, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "runopsy-agent: timeline: %v\n", err)
			return 1
		}
		data = append(data, '\n')
		if _, err := stdout.Write(data); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	if *combined {
		if err := renderCombinedTimeline(stdout, timeline, bundle.Incident.Providers); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := renderCombinedReport(stdout, bundle.Incident, graph, report); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := renderProviderReport(stdout, bundle.Incident.Providers, providerreport); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	if err := renderTimeline(stdout, timeline, graph, *causalflag, bundle.Incident.Providers, providerreport); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := renderProviderReport(stdout, bundle.Incident.Providers, providerreport); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

// splitValueFlags allows a flag with a value before or after the bundle path.
func splitValueFlags(args []string, values map[string]bool) (flags, positional []string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if values[arg] {
			if i+1 == len(args) {
				flags = append(flags, arg)
				continue
			}
			flags = append(flags, arg, args[i+1])
			i++
			continue
		}
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
		} else {
			positional = append(positional, arg)
		}
	}
	return flags, positional
}

func resolveEdge(value string, edges []causal.CausalEdge) (int, error) {
	for i, edge := range edges {
		if edge.ID == value || string(edge.From)+"->"+string(edge.To) == value {
			return i, nil
		}
	}
	// A19: a rule ID names a rule, not an edge. resolve it only when exactly
	// one edge carries it; otherwise list the candidates instead of silently
	// explaining the first.
	var byRule []string
	match := -1
	for i, edge := range edges {
		if edge.RuleID == value {
			byRule = append(byRule, edge.ID)
			match = i
		}
	}
	switch len(byRule) {
	case 1:
		return match, nil
	case 0:
	default:
		return 0, fmt.Errorf("rule %q matches %d edges (%s); pass an edge ID", value, len(byRule), strings.Join(byRule, ", "))
	}
	var index int
	if _, err := fmt.Sscanf(value, "%d", &index); err != nil || index < 0 || index >= len(edges) {
		return 0, fmt.Errorf("edge %q not found (use an edge index, RULE@VERSION, or FROM->TO)", value)
	}
	return index, nil
}

// wrappers over internal/analysis (phase 7 contract §3.3): the orchestration
// exists once; the CLI renders, the package computes.
func intentCovers(interps []provider.Interpretation) []causal.IntentCover {
	return analysis.IntentCovers(interps)
}

func diagnosisCovers(covers []causal.IntentCover) []diagnosis.IntentCover {
	return analysis.DiagnosisCovers(covers)
}

func buildCausalGraph(inc *incident.Incident) (*causal.Timeline, *causal.Graph, error) {
	return analysis.BuildCausalGraph(inc)
}

func diagnosisOptions(inc *incident.Incident, minConfidence float64, disabled []diagnosis.SignatureID) diagnosis.Options {
	return analysis.DiagnosisOptions(inc, minConfidence, disabled)
}

func linkDiagnoses(report *diagnosis.Report, tl *causal.Timeline) {
	analysis.LinkDiagnoses(report, tl)
}

func renderTimeline(w io.Writer, tl *causal.Timeline, graph *causal.Graph, showCausal bool, sections []evidence.Section, interpreted []provider.Interpretation) error {
	if err := renderCombinedTimeline(w, tl, sections); err != nil {
		return err
	}
	if !showCausal {
		return nil
	}
	return renderCausal(w, graph, nil)
}

// qualityResolver is the CLI's handle on the quality index (6.32/6.61/6.62):
// it maps each causal chain link back to the class of evidence the bundle holds
// for it. A multi-source link takes the class of its weakest source, because a
// premise is only as good as its weakest part.
type qualityResolver struct{ index *incident.QualityIndex }

func newQualityResolver(inc *incident.Incident) *qualityResolver {
	if inc == nil {
		return nil
	}
	return &qualityResolver{index: incident.NewQualityIndex(inc)}
}

func (r *qualityResolver) eventQuality(event *causal.Event) incident.Quality {
	if r == nil || event == nil {
		return incident.QualityUnknown
	}
	var weakest incident.Quality
	for _, source := range event.Provenance.Sources {
		quality, ok := r.index.Lookup(source.Kind, source.Ref)
		if !ok || quality == incident.QualityUnknown {
			return incident.QualityUnknown
		}
		weakest = weakerQuality(weakest, quality)
	}
	if weakest == "" {
		// no citable source at all (a rule-derived event with no recorded
		// evidence behind it) is unknown, not inferred.
		return incident.QualityUnknown
	}
	return weakest
}

func (r *qualityResolver) claimQuality(graph *causal.Graph, failure *causal.FailureAnalysis) string {
	if r == nil || graph == nil || failure == nil {
		return incident.ClaimUnknown
	}
	ids := append([]causal.EventID{failure.Anchor}, failure.KnownChain...)
	seen := make(map[causal.EventID]bool, len(ids))
	qualities := make([]incident.Quality, 0, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		qualities = append(qualities, r.eventQuality(graph.Get(id)))
	}
	return incident.Aggregate(qualities)
}

// weakerQuality orders the classes by directness, which is the only ordering
// contract §9.2 licenses: a premise is as good as its weakest part.
func weakerQuality(a, b incident.Quality) incident.Quality {
	if a == "" {
		return b
	}
	if a.Direct() && !b.Direct() {
		return b
	}
	return a
}

// qualityLabel is the human-facing rendering of one class.
func qualityLabel(q incident.Quality) string {
	switch q {
	case incident.QualityDirectKernel:
		return "kernel trace"
	case incident.QualityDirectProcess:
		return "process reading"
	case incident.QualityDerivedSnapshot:
		return "snapshot inference"
	case incident.QualityProviderLog:
		return "provider log"
	case incident.QualityProviderAPI:
		return "provider API"
	case incident.QualityAgent:
		return "agent action"
	default:
		return "source unknown"
	}
}

// renderCausal renders the per-anchor failure analyses (§5.4): the headline
// is the primary failure's analysis; every other anchor's analysis follows.
// anchors whose cause is UNKNOWN render the known chain and the missing
// evidence instead of a fabricated root (4.45). wording follows §8.3: the
// headline is never stronger than the weakest of analysis status, candidate
// band, and the anchors it discriminates.
func renderCausal(w io.Writer, graph *causal.Graph, quality *qualityResolver) error {
	if err := renderCausalAnalyses(w, graph, quality); err != nil {
		return err
	}
	if n := graph.OtherExits(); n > 0 {
		// R13: exits with no failure context are stated, not listed as
		// failures (v1 records no exit status).
		if _, err := fmt.Fprintf(w, "\nOther process exits recorded: %d (exit status not captured; no trigger, consequence or limit context, so not treated as failures)\n", n); err != nil {
			return err
		}
	}
	return nil
}

func renderCausalAnalyses(w io.Writer, graph *causal.Graph, quality *qualityResolver) error {
	analyses := graph.FailureAnalyses()
	if len(analyses) == 0 {
		if _, err := fmt.Fprintln(w, "\nCAUSAL ANALYSIS (healthy)\nNo failure anchor in the capture: no causal conclusion to report."); err != nil {
			return err
		}
		for _, id := range graph.UnconfirmedSevere() {
			event := graph.Get(id)
			if _, err := fmt.Fprintf(w, "Noteworthy: %s on %s:%s at T+%s seen in one sample only; persistence not observed, so not treated as a failure.\n",
				event.Type, event.Subject.Kind, event.Subject.ID, event.Timestamp.Sub(graph.Origin).Round(time.Millisecond)); err != nil {
				return err
			}
		}
		return nil
	}
	primary := primaryFailure(graph, analyses)
	if _, err := fmt.Fprintf(w, "\nCAUSAL ANALYSIS — primary failure (%s)\n", primary.AnchorType); err != nil {
		return err
	}
	// the §5.4 headline is the primary failure's analysis; the other
	// anchors' analyses are listed after it.
	if err := renderAnalysis(w, graph, primary, quality); err != nil {
		return err
	}
	for i := range analyses {
		if &analyses[i] == primary {
			continue
		}
		if _, err := fmt.Fprintf(w, "\nSecondary failure\n"); err != nil {
			return err
		}
		if err := renderAnalysis(w, graph, &analyses[i], quality); err != nil {
			return err
		}
	}
	return nil
}

// primaryFailure picks the §5.4 headline: the earliest anchor that is not
// reached by a causal path from another anchor. equal earliest anchors share
// the headline time; canonical (analysis) order breaks that display tie only,
// never a role (P7).
func primaryFailure(graph *causal.Graph, analyses []causal.FailureAnalysis) *causal.FailureAnalysis {
	for i := range analyses {
		// another anchor's chain that contains this anchor makes it a
		// downstream failure, not the headline.
		downstream := false
		for j := range analyses {
			if i == j {
				continue
			}
			for _, id := range analyses[j].KnownChain {
				if id == analyses[i].Anchor {
					downstream = true
					break
				}
			}
			if downstream {
				break
			}
		}
		if !downstream {
			return &analyses[i]
		}
	}
	return &analyses[0]
}

// rootCauseLabel is the §8.3 wording for an explained anchor's leading
// candidate: the headline is never stronger than the candidate's chain band.
func rootCauseLabel(band causal.CausalConfidence) string {
	switch band {
	case causal.ConfidenceHigh:
		return "Root cause"
	case causal.ConfidenceMedium:
		return "Most likely root cause"
	default:
		return "Possible root cause"
	}
}

func describeCandidate(graph *causal.Graph, candidate causal.RootCandidate) string {
	event := graph.Get(candidate.Event)
	onset := ""
	if candidate.OnsetUnknown {
		onset = "; onset not captured"
	}
	return fmt.Sprintf("%s on %s:%s (%s confidence%s)",
		event.Type, event.Subject.Kind, event.Subject.ID, candidate.Confidence, onset)
}

// renderAnalysis renders one anchor's analysis. Re-audit R5 (2026-10-28):
// the cause line is derived from the analysis status and candidate kind
// only. an UNKNOWN anchor always reads "root cause: UNKNOWN"; an unexplained
// chain head is "earliest known link", never "root cause"; a contributing
// factor is never promoted to the cause line (§5.2, §8.3).
func renderAnalysis(w io.Writer, graph *causal.Graph, analysis *causal.FailureAnalysis, quality *qualityResolver) error {
	anchor := graph.Get(analysis.Anchor)
	if _, err := fmt.Fprintf(w, "Failure %s on %s:%s at %s (relative T+%s)\n",
		analysis.AnchorType,
		anchor.Subject.Kind, anchor.Subject.ID,
		anchor.Timestamp.UTC().Format(time.RFC3339),
		anchor.Timestamp.Sub(graph.Origin).Round(time.Millisecond)); err != nil {
		return err
	}
	// 6.61/6.62: the class of evidence behind the failure is stated before
	// any causal wording, so "inferred" can never read like "observed".
	if claim := quality.claimQuality(graph, analysis); claim != "" {
		if _, err := fmt.Fprintf(w, "Evidence quality: %s\n", claim); err != nil {
			return err
		}
	}
	var leads, competing, heads, contributors, others []causal.RootCandidate
	for _, candidate := range analysis.Candidates {
		switch {
		case candidate.Kind == causal.KindContributingFactor:
			contributors = append(contributors, candidate)
		case candidate.Kind == causal.KindUnexplainedHead:
			heads = append(heads, candidate)
		case candidate.Role == causal.RoleCompeting:
			competing = append(competing, candidate)
		case candidate.Role == causal.RolePrimary:
			leads = append(leads, candidate)
		default:
			others = append(others, candidate)
		}
	}
	var lines []string
	switch {
	case analysis.Status == causal.StatusExplained && len(leads) > 0:
		lines = append(lines, fmt.Sprintf("%s: %s", rootCauseLabel(leads[0].Confidence), describeCandidate(graph, leads[0])))
		for _, other := range others {
			lines = append(lines, "Weaker candidate: "+describeCandidate(graph, other))
		}
	case analysis.Status == causal.StatusAmbiguous:
		lines = append(lines, "Root cause: AMBIGUOUS between")
		for _, candidate := range competing {
			lines = append(lines, "  - "+describeCandidate(graph, candidate))
		}
	default:
		lines = append(lines, "Root cause: UNKNOWN")
	}
	for _, head := range heads {
		lines = append(lines, "Earliest known link: "+describeCandidate(graph, head)+"; its own cause was not captured")
	}
	for _, contributor := range contributors {
		lines = append(lines, "Contributing factor: "+describeCandidate(graph, contributor))
	}
	if members, ok := anchor.Data["member_pids"]; ok && analysis.AnchorType == causal.EventProcessGroupTerminated {
		// member exits are this anchor's evidence, not separate failures (R8).
		lines = append(lines, fmt.Sprintf("Member exits (PIDs): %v", members))
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	if len(analysis.KnownChain) > 1 || (len(analysis.KnownChain) > 0 && analysis.Status == causal.StatusUnknown) {
		if _, err := fmt.Fprintln(w, "Known chain:"); err != nil {
			return err
		}
		for _, id := range analysis.KnownChain {
			event := graph.Get(id)
			// each link names its source class (6.62): the same chain can mix a
			// kernel observation with an inferred disappearance.
			suffix := ""
			if quality != nil {
				suffix = "  [" + qualityLabel(quality.eventQuality(event)) + "]"
			}
			if _, err := fmt.Fprintf(w, "  T+%s  %s (on %s:%s)%s\n",
				event.Timestamp.Sub(graph.Origin).Round(time.Millisecond),
				event.Type,
				event.Subject.Kind, event.Subject.ID,
				suffix); err != nil {
				return err
			}
		}
	}
	if len(analysis.MissingEvidence) > 0 {
		if _, err := fmt.Fprintln(w, "Missing evidence:"); err != nil {
			return err
		}
		for _, missing := range analysis.MissingEvidence {
			if _, err := fmt.Fprintf(w, "- %s\n", missing); err != nil {
				return err
			}
		}
	}
	if len(analysis.Alternatives) > 0 {
		if _, err := fmt.Fprintln(w, "Alternatives:"); err != nil {
			return err
		}
		for _, alternative := range analysis.Alternatives {
			if _, err := fmt.Fprintf(w, "- %s\n", alternative); err != nil {
				return err
			}
		}
	}
	return nil
}

func crossCheckDiagnoses(report *diagnosis.Report, graph *causal.Graph) []string {
	if report == nil || graph == nil {
		return nil
	}
	var warnings []string
	failures := graph.FailureAnalyses()
	for _, match := range report.Matches {
		identityset := make(map[causal.ProcessIdentity]bool, len(match.ProcessIdentities))
		for _, identity := range match.ProcessIdentities {
			identityset[causal.ProcessIdentity{PID: identity.PID, StartTicks: identity.StartTicks}] = true
		}
		for _, id := range match.RelatedEvents {
			var related *causal.Event
			for _, event := range graph.Events {
				if string(event.ID) == id {
					related = event
					break
				}
			}
			if related == nil {
				warnings = append(warnings, fmt.Sprintf("%s links missing Phase 4 event %s", match.SignatureID, id))
				continue
			}
			if isProcessDiagnosis(match.SignatureID) && !eventInProcessScope(related, identityset) {
				warnings = append(warnings, fmt.Sprintf("%s links event %s outside its exact process scope", match.SignatureID, id))
			}
		}
		if isProcessDiagnosis(match.SignatureID) && len(identityset) == 0 && len(match.RelatedEvents) > 0 {
			warnings = append(warnings, fmt.Sprintf("%s has linked process events but no process identity scope", match.SignatureID))
		}
	}

	// phase 3's ambiguous pair must not be contradicted by an explained
	// phase 4 anchor that has only one corresponding root candidate. this is
	// deliberately warning-only: the phases have different observability and
	// no report finding changes causal edges or EXPLAINED status.
	for _, alternative := range report.Ambiguous {
		parts := strings.Split(alternative, " vs ")
		if len(parts) != 2 {
			continue
		}
		for _, failure := range failures {
			if failure.Status != causal.StatusExplained {
				continue
			}
			var pairRoots, rootCount int
			for _, candidate := range failure.Candidates {
				if candidate.Kind != causal.KindRootCause || candidate.Role == causal.RoleSecondary {
					continue
				}
				rootCount++
				if causalSignature(candidate, graph) == parts[0] || causalSignature(candidate, graph) == parts[1] {
					pairRoots++
				}
			}
			if pairRoots > 0 && rootCount == 1 {
				warnings = append(warnings, fmt.Sprintf("Phase 3 reports %s as ambiguous, but Phase 4 explains failure %s using only one competing mechanism", alternative, failure.Anchor))
			}
		}
	}
	return warnings
}

func isProcessDiagnosis(signature diagnosis.SignatureID) bool {
	switch signature {
	case diagnosis.SignatureOOMKill, diagnosis.SignatureFrozenProcess, diagnosis.SignatureCPUSpin,
		diagnosis.SignatureOrphanProcess, diagnosis.SignatureGroupKill, diagnosis.SignatureBrokerStall:
		return true
	default:
		return false
	}
}

func eventInProcessScope(event *causal.Event, identities map[causal.ProcessIdentity]bool) bool {
	if event == nil || len(identities) == 0 {
		return false
	}
	if event.Type == causal.EventProcessGroupTerminated {
		for _, identity := range event.ProcessIDs {
			if identity.PID > 0 && identity.StartTicks > 0 && identities[identity] {
				return true
			}
		}
		return false
	}
	if event.Type == causal.EventProcessReparented {
		child := causal.ProcessIdentity{PID: event.PID, StartTicks: event.StartTicks}
		parent := causal.ProcessIdentity{PID: event.PPID, StartTicks: event.PPIDStartTicks}
		return child.PID > 0 && child.StartTicks > 0 && identities[child] ||
			event.PPID > 0 && event.PPIDStartTicks > 0 && identities[parent]
	}
	identity := causal.ProcessIdentity{PID: event.PID, StartTicks: event.StartTicks}
	return identity.PID > 0 && identity.StartTicks > 0 && identities[identity]
}

func causalSignature(candidate causal.RootCandidate, graph *causal.Graph) string {
	event := graph.Get(candidate.Event)
	if event == nil {
		return ""
	}
	switch event.Type {
	case causal.EventProcessGroupTerminated:
		return string(diagnosis.SignatureGroupKill)
	case causal.EventDiskPressureStarted, causal.EventDiskLowActive, causal.EventDiskExhausted:
		return string(diagnosis.SignatureDiskExhaustion)
	case causal.EventMemoryPressureStarted, causal.EventMemoryPressureActive, causal.EventMemoryLimitReached, causal.EventCgroupLimitReached:
		return string(diagnosis.SignatureOOMKill)
	case causal.EventNetworkProgressStopped:
		return string(diagnosis.SignatureBrokerStall)
	default:
		return ""
	}
}

func evidenceCodes(evidence []causal.EvidenceNote) string {
	codes := make([]string, 0, len(evidence))
	for _, e := range evidence {
		codes = append(codes, e.Code)
	}
	sort.Strings(codes)
	return strings.Join(codes, ", ")
}

// matchQuality reduces the events one diagnosis cites to the claim word
// (6.61). an empty result means the diagnosis cited no event, so the report
// must not attach a class it did not observe.
func matchQuality(quality *qualityResolver, graph *causal.Graph, related []string) string {
	if quality == nil || len(related) == 0 {
		return ""
	}
	qualities := make([]incident.Quality, 0, len(related))
	for _, id := range related {
		event := graph.Get(causal.EventID(id))
		if event == nil {
			qualities = append(qualities, incident.QualityUnknown)
			continue
		}
		qualities = append(qualities, quality.eventQuality(event))
	}
	return incident.Aggregate(qualities)
}

// renderTraceEvidence states whether the kernel trace existed and whether it
// was complete (6.27/6.48/6.62). this block is load-bearing for every
// conclusion below it: under incomplete or absent coverage, a signal that is
// not in the bundle is missing evidence, not evidence that nothing was sent.
func renderTraceEvidence(w io.Writer, tracing *incident.TraceReliability) error {
	switch {
	case tracing == nil:
		_, err := fmt.Fprintf(w, "\nKernel trace evidence\nTracing            not configured (polling only)\nCoverage           none: signal and stop/resume evidence is inferred from snapshots\n")
		return err
	case tracing.State != "active":
		if _, err := fmt.Fprintf(w, "\nKernel trace evidence\nTracing            %s\n", tracing.State); err != nil {
			return err
		}
		if tracing.Reason != "" {
			if _, err := fmt.Fprintf(w, "Reason             %s\n", tracing.Reason); err != nil {
				return err
			}
		}
		_, err := fmt.Fprintf(w, "Coverage           none: absence of a signal here is not evidence that none was sent\n")
		return err
	}
	backend := tracing.Backend
	if backend == "" {
		backend = "unspecified"
	}
	if _, err := fmt.Fprintf(w, "\nKernel trace evidence\nTracing            active (%s)\n", backend); err != nil {
		return err
	}
	if tracing.EventsLost > 0 {
		// A gap is at least that many events: the kernel does not say how
		// many (contract §7.1).
		if tracing.CaptureLost > 0 {
			if _, err := fmt.Fprintf(w, "Recorder dropped    %d\n", tracing.CaptureLost); err != nil {
				return err
			}
		}
		_, err := fmt.Fprintf(w, "Events lost        at least %d\nCoverage           incomplete: trace evidence for the affected window cannot be read as absence\n", tracing.EventsLost)
		return err
	}
	if tracing.CaptureLost > 0 {
		// Recorder-side refusals are just as evidence-breaking as wire gaps:
		// what this recorder refused is unknowable-for-the-window too.
		_, err := fmt.Fprintf(w, "Events lost        0 observed on the wire\nRecorder dropped    %d (window or buffer bounds)\nCoverage           incomplete: trace evidence for the affected window cannot be read as absence\n", tracing.CaptureLost)
		return err
	}
	_, err := fmt.Fprintf(w, "Events lost        0 observed on the wire\nCoverage           complete for the traced event classes\n")
	return err
}

// renderCombinedReport renders 4.44 with the §8.3 wording rule: the headline
// is never stronger than the weakest of the phase 3 band, the phase 4 failure
// status, and the chain band.
func renderCombinedReport(w io.Writer, inc *incident.Incident, graph *causal.Graph, report *diagnosis.Report) error {
	if _, err := fmt.Fprintln(w, "RUNOPSY ANALYSIS"); err != nil {
		return err
	}
	// the causal headline wording lives inside renderCausal/renderAnalysis:
	// it never claims more than the anchor analysis grants.

	if err := renderGitHubSummary(w, inc.Providers, inc.CaptureStart, inc.CaptureEnd); err != nil {
		return err
	}
	quality := newQualityResolver(inc)
	if err := renderTraceEvidence(w, inc.Tracing); err != nil {
		return err
	}
	if report == nil || len(report.Matches) == 0 {
		if _, err := fmt.Fprintln(w, "\nUnderlying systems diagnosis\nUNKNOWN — no Phase 3 signature met its evidence requirements."); err != nil {
			return err
		}
	} else {
		for i, match := range report.Matches {
			label := "Alternative diagnosis"
			if i == 0 {
				label = "Primary diagnosis"
			}
			if i == 0 {
				label = "Underlying systems diagnosis"
			}
			if _, err := fmt.Fprintf(w, "\n%s\n%s\nConfidence: %s (%.2f)\n%s\n", label, match.SignatureID, match.Band, match.Confidence, match.Summary); err != nil {
				return err
			}
			// 6.61: the same signature exposed at two levels of evidence.
			// only the events this diagnosis actually cites are consulted; a
			// signature that cites nothing stays unqualified rather than
			// borrowing the incident's overall quality.
			if met := matchQuality(quality, graph, match.RelatedEvents); met != "" {
				if _, err := fmt.Fprintf(w, "Evidence quality: %s\n", met); err != nil {
					return err
				}
			}
			if len(match.RelatedEvents) > 0 {
				if _, err := fmt.Fprintf(w, "Related events: %s\n", strings.Join(match.RelatedEvents, ", ")); err != nil {
					return err
				}
			}
		}
	}
	if _, err := fmt.Fprintln(w, "\nCausal reconstruction"); err != nil {
		return err
	}
	if err := renderCausal(w, graph, quality); err != nil {
		return err
	}
	for _, warning := range crossCheckDiagnoses(report, graph) {
		if _, err := fmt.Fprintf(w, "\nConsistency warning: %s\n", warning); err != nil {
			return err
		}
	}
	if len(report.Ambiguous) > 0 {
		if _, err := fmt.Fprintln(w, "\nAlternative explanations:"); err != nil {
			return err
		}
		for _, alternative := range report.Ambiguous {
			if _, err := fmt.Fprintf(w, "- %s\n", alternative); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintf(w, "\nIncident: %s  Triggered: %s\n", inc.ID, inc.TriggeredAt.UTC().Format(time.RFC3339Nano))
	return err
}
