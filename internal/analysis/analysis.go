package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"deprehendo/internal/causal"
	"deprehendo/internal/collector"
	"deprehendo/internal/diagnosis"
	"deprehendo/internal/incident"
	"deprehendo/internal/provider"
)

// run produces the deprehendo.analysis document for one verified bundle
// (contract docs/cloud/contract.md §3.3). the document is the stored analysis
// of phase 7: the CLI (`analyze --document`), the timeline renderer and the
// analyzer worker all read from it, so there is exactly one interpretation of
// a bundle.
//
// sha256hex is the lowercase hex digest of the original bundle bytes; the
// cloud re-computes it from stored bytes, the CLI from the analyzed file. run
// is a pure function of (bundle, sha256hex, engine, options): the
// determinism test runs it twice and under a different TZ and compares bytes.
func Run(bundle *incident.Bundle, sha256hex string, opts Options) (*Document, error) {
	if bundle == nil || bundle.Incident == nil {
		return nil, fmt.Errorf("analysis: nil bundle")
	}
	if err := checkSHA256(sha256hex); err != nil {
		return nil, err
	}
	inc := bundle.Incident

	// zero means "engine default", so the worker's options{} and the CLI's
	// explicit --min-confidence default produce the same document (7.43).
	if opts.MinConfidence == 0 {
		opts.MinConfidence = diagnosis.DefaultMinConfidence
	}
	interps := provider.Default.InterpretAll(inc.Providers, inc)
	report, err := diagnosis.Analyze(inc, DiagnosisOptions(inc, opts.MinConfidence, opts.Disabled))
	if err != nil {
		return nil, fmt.Errorf("analysis: %w", err)
	}
	timeline, graph, err := BuildCausalGraph(inc)
	if err != nil {
		return nil, fmt.Errorf("analysis: %w", err)
	}
	LinkDiagnoses(report, timeline)

	index := incident.NewQualityIndex(inc)
	doc := &Document{
		DocumentVersion: DocumentVersion,
		Engine:          EngineIdentity(),
		Options:         optionsDocument(opts),
		Bundle:          bundleInfo(sha256hex, bundle.Manifest),
		Privacy:         inc.Privacy,
		Diagnosis:       report,
		Providers:       interpreted(interps),
		Causal:          causalSection(graph, index),
		Timeline:        timelineEvents(timeline, index),
		Series:          series(inc.Snapshots),
	}
	return doc, nil
}

// WriteJSON renders a document as exactly the bytes the cloud stores and the
// CLI writes for --document: indented JSON and one trailing newline. both
// paths call this, so local/cloud equality (7.43) is a byte comparison of one
// writer's output, not of two formatters.
func WriteJSON(w io.Writer, doc *Document) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("analysis: document: %w", err)
	}
	if _, err := w.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("analysis: write document: %w", err)
	}
	return nil
}

// checkSHA256 enforces the digest contract ("sha256 of the original bytes")
// without letting callers smuggle in display strings.
func checkSHA256(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("analysis: bundle sha256 must be 64 hex characters")
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fmt.Errorf("analysis: bundle sha256 is not hex")
	}
	return nil
}

// SHA256OfBytes hashes the original bundle bytes. the CLI and the worker both
// call this so the stored checksum is computed identically in both places.
func SHA256OfBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// interpreted returns provider interpretations, or nil when the bundle has
// none (contract: absent, not empty, so JSON omits the field).
func interpreted(in []provider.Interpretation) []provider.Interpretation {
	if len(in) == 0 {
		return nil
	}
	return in
}

// causalSection serializes the graph: canonical-order nodes with their
// evidence class, all accepted edges, rejected proposals, and every per-anchor
// failure analysis with its claim-level evidence class (§6.62 wording).
func causalSection(graph *causal.Graph, index *incident.QualityIndex) CausalSection {
	out := CausalSection{
		Healthy:    graph.Healthy(),
		OtherExits: graph.OtherExits(),
	}
	for _, id := range graph.UnconfirmedSevere() {
		out.Unconfirmed = append(out.Unconfirmed, string(id))
	}
	for _, id := range graph.EventIDs() {
		e := graph.Get(id)
		if e == nil {
			continue
		}
		out.Nodes = append(out.Nodes, Node{Event: *e, Evidence: nodeQuality(e, index)})
	}
	out.Edges = append(out.Edges, graph.Edges...)
	out.RejectedEdges = append(out.RejectedEdges, graph.Rejected...)
	failures := graph.FailureAnalyses()
	out.Failures = make([]Failure, 0, len(failures))
	for i := range failures {
		f := Failure{FailureAnalysis: failures[i], Claim: claimQuality(graph, &failures[i], index)}
		out.Failures = append(out.Failures, f)
	}
	return out
}

// nodeQuality classifies one event through its provenance sources. A rule
// spend derives from its sources; a premise is as strong as its weakest
// cited source, and an event with no cited source stays UNKNOWN.
func nodeQuality(e *causal.Event, index *incident.QualityIndex) incident.Quality {
	var weakest incident.Quality
	for _, source := range e.Provenance.Sources {
		q, ok := index.Lookup(source.Kind, source.Ref)
		if !ok || q == incident.QualityUnknown {
			return incident.QualityUnknown
		}
		weakest = incident.Weaker(weakest, q)
	}
	if weakest == "" {
		return incident.QualityUnknown
	}
	return weakest
}

// claimQuality aggregates anchor and known chain into the claim word
// (contract §10): direct, mixed, inferred or unknown.
func claimQuality(graph *causal.Graph, failure *causal.FailureAnalysis, index *incident.QualityIndex) string {
	if graph == nil || failure == nil {
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
		qualities = append(qualities, nodeQuality(graph.Get(id), index))
	}
	return incident.Aggregate(qualities)
}

// timelineEvents attaches the per-event evidence class to the normalized
// timeline, keeping extract order so index equals position (7.44 paging).
func timelineEvents(tl *causal.Timeline, index *incident.QualityIndex) []TimelineEvent {
	if tl == nil {
		return nil
	}
	out := make([]TimelineEvent, 0, len(tl.Events))
	for i := range tl.Events {
		e := tl.Events[i]
		out = append(out, TimelineEvent{Event: e, Evidence: nodeQuality(&e, index)})
	}
	return out
}

// series keeps the recorded snapshot order: charts page it and never re-sort
// (7.44). the whole snapshot travels, tagged by the phase 1 JSON schema, so
// the dashboard renders exactly what was collected.
func series(snapshots []collector.Snapshot) []collector.Snapshot {
	if len(snapshots) == 0 {
		return nil
	}
	return append([]collector.Snapshot(nil), snapshots...)
}
