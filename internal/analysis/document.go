package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"runopsy/internal/causal"
	"runopsy/internal/collector"
	"runopsy/internal/diagnosis"
	"runopsy/internal/incident"
	"runopsy/internal/provider"
)

// DocumentVersion identifies the schema of document in this file.
//
// history:
//
//	1: initial runopsy.analysis v1 (phase 7, contract docs/cloud/contract.md
//	   §3.3).
const DocumentVersion = 1

// engine names the exact engine that produced a document (§4). two engines
// that diagnose the same bundle differently must never share an identity, so
// a stored analysis stays attributable and re-analysis (7.34) can compare.
type Engine struct {
	AnalyzerVersion     string `json:"analyzer_version"`
	SignatureVersion    int    `json:"signature_version"`
	SignatureSetVersion int    `json:"signature_set_version"`
	// CausalRules is the sha256 over the sorted causal rule-ID list. rule IDs
	// are versioned, but adding or removing a rule used to change nothing a
	// report records; this hash makes that drift visible (golden test).
	CausalRules   string         `json:"causal_rules"`
	PrivacyPolicy string         `json:"privacy_policy"`
	BundleFormats []BundleFormat `json:"bundle_formats"`
}

// BundleFormat declares a supported on-disk bundle format.
type BundleFormat struct {
	FormatVersion int `json:"format_version"`
	SchemaVersion int `json:"schema_version"`
}

// options controls evaluation only. A cloud run always uses the defaults.
type Options struct {
	MinConfidence float64
	Disabled      []diagnosis.SignatureID
}

// BundleInfo carries the manifest identity of the analyzed bundle plus the
// checksum of the original bytes. incident_id is display data (contract
// §2.3): the uploader wrote it, so it is never a storage or access key.
type BundleInfo struct {
	SHA256           string                         `json:"sha256"`
	IncidentID       string                         `json:"incident_id"`
	SchemaVersion    int                            `json:"schema_version"`
	FormatVersion    int                            `json:"format_version"`
	SnapshotEncoding string                         `json:"snapshot_encoding"`
	CreatedAt        string                         `json:"created_at"`
	AgentVersion     string                         `json:"agent_version"`
	Platform         string                         `json:"platform"`
	Architecture     string                         `json:"architecture"`
	Files            map[string]incident.FileDigest `json:"files,omitempty"`
}

// CausalSection is the graph as data: nodes in canonical order, every
// accepted edge with its evaluated checks, rejected proposals, per-anchor
// failure analyses and the per-event evidence class of each node.
type CausalSection struct {
	Healthy       bool                  `json:"healthy"`
	OtherExits    int                   `json:"other_exits"`
	Unconfirmed   []string              `json:"unconfirmed_severe,omitempty"`
	Nodes         []Node                `json:"nodes"`
	Edges         []causal.CausalEdge   `json:"edges"`
	RejectedEdges []causal.RejectedEdge `json:"rejected_edges,omitempty"`
	Failures      []Failure             `json:"failures"`
}

// node is one graph event with the class of evidence the bundle holds for it
// (6.32/6.61/6.62): DIRECT_KERNEL, DIRECT_PROCESS, DERIVED_SNAPSHOT,
// PROVIDER_LOG, PROVIDER_API, AGENT or UNKNOWN.
type Node struct {
	Event    causal.Event     `json:"event"`
	Evidence incident.Quality `json:"evidence_class"`
}

// failure is one per-anchor analysis (§5.2) with the aggregate evidence class
// of the claim: "direct" only when every cited premise of the anchor and its
// known chain is a direct observation.
type Failure struct {
	causal.FailureAnalysis
	Claim string `json:"claim"`
}

// TimelineEvent is one normalized timeline event with its per-event evidence
// class. the embedded event keeps its own JSON fields inline so the array is
// a flat, stable record per event.
type TimelineEvent struct {
	causal.Event
	Evidence incident.Quality `json:"evidence_class"`
}

// document is the full, renderable analysis of one bundle. large arrays
// (timeline, series) keep their bundle capture order; the index of a record
// equals its position, so a renderer can page without re-sorting (7.44).
type Document struct {
	DocumentVersion int    `json:"document_version"`
	Engine          Engine `json:"engine"`

	// options records the evaluation options actually applied. it is absent
	// for a default run (what the cloud and the worker always do) so a
	// stored analysis states non-default options only when they were used.
	// structured (contract §3.3), not a rendered string, so web can read the
	// values without parsing.
	Options *DocumentOptions `json:"options,omitempty"`

	Bundle    BundleInfo                `json:"bundle"`
	Privacy   incident.PrivacyReport    `json:"privacy"`
	Diagnosis *diagnosis.Report         `json:"diagnosis"`
	Providers []provider.Interpretation `json:"providers,omitempty"`
	Causal    CausalSection             `json:"causal"`
	Timeline  []TimelineEvent           `json:"timeline"`
	Series    []collector.Snapshot      `json:"series"`
}

// DocumentOptions is the JSON shape of one non-default evaluation run:
// contract §3.3 names min_confidence and disabled. disabled carries the
// signature IDs the engine was told to skip.
type DocumentOptions struct {
	MinConfidence float64                 `json:"min_confidence"`
	Disabled      []diagnosis.SignatureID `json:"disabled,omitempty"`
}

// optionsDocument renders options for the document. recorded values are the
// ones actually used: callers pass the post-default options, so a non-default
// min_confidence appears as its applied value and a zero MinConfidence can
// never reach this function. defaults with nothing disabled produce nil, so
// the JSON field is absent for every cloud/worker document.
func optionsDocument(o Options) *DocumentOptions {
	if (o.MinConfidence == 0 || o.MinConfidence == diagnosis.DefaultMinConfidence) && len(o.Disabled) == 0 {
		return nil
	}
	disabled := make([]diagnosis.SignatureID, 0, len(o.Disabled))
	disabled = append(disabled, o.Disabled...)
	return &DocumentOptions{
		MinConfidence: o.MinConfidence,
		Disabled:      disabled,
	}
}

// bundleInfo extracts the manifest identity from a verified bundle.
func bundleInfo(sha256hex string, m incident.Manifest) BundleInfo {
	return BundleInfo{
		SHA256:           strings.ToLower(sha256hex),
		IncidentID:       m.IncidentID,
		SchemaVersion:    m.SchemaVersion,
		FormatVersion:    m.FormatVersion,
		SnapshotEncoding: m.SnapshotEncoding,
		CreatedAt:        m.CreatedAt.UTC().Format(time.RFC3339Nano),
		AgentVersion:     m.AgentVersion,
		Platform:         m.Platform,
		Architecture:     m.Architecture,
		Files:            m.Files,
	}
}

// EngineIdentity computes the engine document (§4). CausalRules hashes the
// sorted rule-ID list of the bundled causal set; the golden fingerprint test
// pins the expected hash so rule drift fails the build.
func EngineIdentity() Engine {
	ids := make([]string, 0, 32)
	for _, rule := range causal.Rules() {
		ids = append(ids, rule.ID)
	}
	sort.Strings(ids)
	sum := sha256.Sum256([]byte(strings.Join(ids, "\n")))
	return Engine{
		AnalyzerVersion:     diagnosis.AnalyzerVersion,
		SignatureVersion:    diagnosis.SignatureVersion,
		SignatureSetVersion: diagnosis.SignatureSetVersion,
		CausalRules:         hex.EncodeToString(sum[:]),
		PrivacyPolicy:       incident.PrivacyPolicy,
		BundleFormats:       []BundleFormat{{FormatVersion: incident.FormatVersion, SchemaVersion: incident.SchemaVersion}},
	}
}
