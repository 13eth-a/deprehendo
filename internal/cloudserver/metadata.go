// cloudserver metadata (checklist 7.6): the searchable incident columns are
// copied from the READY engine document by this file and only this file. the
// extraction is conservative on purpose: a fact the bundle withheld
// (state != KNOWN) stays empty in the database. the dashboard must never be
// able to reconstruct redacted data (7.27), and an UNKNOWN fact is stored as
// what it is: unknown, not fabricated.
package cloudserver

import (
	"encoding/json"
)

// dbIncidentMetadata is the subset of incidents columns the document can
// supply. empty strings / nil pointers are stored as NULL by upsertIncident.
type dbIncidentMetadata struct {
	TriggeredAt      *string
	PrimarySignature string
	Confidence       *float64
	ConfidenceBand   string
	Severity         string
	RunnerName       string
	RunnerVersion    string
	Repository       string
	Workflow         string
	Job              string
	RunID            *int64
	Platform         string
	Architecture     string
}

// document blob shapes: only the fields this package reads. state values are
// the evidence.Text / evidence.Int64 tri-states (KNOWN/UNKNOWN/WITHHELD).
type metaText struct {
	State string
	Value string
}

type metaNumber struct {
	State string
	Value int64
}

type metaRunner struct {
	Name    metaText
	Version metaText
}

type metaJob struct {
	Repository metaText
	Workflow   metaText
	Name       metaText
	RunID      metaNumber
}

type metaSection struct {
	Runners []metaRunner
	Jobs    []metaJob
}

type metaProvider struct {
	Provider string
	Section  metaSection
}

type metaMatch struct {
	Signature      string
	Confidence     float64
	ConfidenceBand string `json:"confidence_band"`
	Severity       string
}

// confidenceBands are the engine's band labels (diagnosis.ConfidenceBand).
// anything else in a document is not stored.
var confidenceBands = map[string]bool{
	"NONE": true, "MODERATE": true, "HIGH": true, "VERY_HIGH": true,
}

type metaDiagnosis struct {
	TriggeredAt string
	Matches     []metaMatch
}

type metaBundle struct {
	IncidentID   string
	Platform     string
	Architecture string
}

type metaDocument struct {
	Bundle    metaBundle
	Diagnosis *metaDiagnosis
	Providers []metaProvider
}

// knownText returns the value only for a KNOWN tri-state, so a withheld or
// unknown fact never reaches the metadata columns (7.27).
func knownText(t metaText) string {
	if t.State == "KNOWN" {
		return t.Value
	}
	return ""
}

// knownNumber does the same for a tri-state number.
func knownNumber(n metaNumber) (int64, bool) {
	if n.State == "KNOWN" && n.Value > 0 {
		return n.Value, true
	}
	return 0, false
}

// pointerIf maps an empty string to a NULL column.
func pointerIf(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// metadataFromDocument extracts the incidents columns from one analysis
// document. A malformed document is not a server failure: the row keeps
// nothing rather than guessing.
func metadataFromDocument(data []byte) dbIncidentMetadata {
	var doc metaDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return dbIncidentMetadata{}
	}
	m := dbIncidentMetadata{
		Platform:     doc.Bundle.Platform,
		Architecture: doc.Bundle.Architecture,
	}
	if doc.Diagnosis != nil {
		m.TriggeredAt = pointerIf(doc.Diagnosis.TriggeredAt)
		for _, match := range doc.Diagnosis.Matches {
			m.PrimarySignature = match.Signature
			m.Confidence = &match.Confidence
			if confidenceBands[match.ConfidenceBand] {
				m.ConfidenceBand = match.ConfidenceBand
			}
			m.Severity = match.Severity
			break // the first reported match is the primary diagnosis
		}
	}
	m.RunnerName, m.RunnerVersion = githubFacts(doc.Providers)
	m.Repository, m.Workflow, m.Job, m.RunID = githubJobFacts(doc.Providers)
	return m
}

func githubFacts(providers []metaProvider) (runnerName, runnerVersion string) {
	for _, p := range providers {
		if p.Provider != "github-actions" {
			continue
		}
		for _, r := range p.Section.Runners {
			if v := knownText(r.Name); v != "" && runnerName == "" {
				runnerName = v
			}
			if v := knownText(r.Version); v != "" && runnerVersion == "" {
				runnerVersion = v
			}
		}
	}
	return runnerName, runnerVersion
}

func githubJobFacts(providers []metaProvider) (repository, workflow, job string, runID *int64) {
	for _, p := range providers {
		if p.Provider != "github-actions" {
			continue
		}
		for _, j := range p.Section.Jobs {
			if v := knownText(j.Repository); v != "" && repository == "" {
				repository = v
			}
			if v := knownText(j.Workflow); v != "" && workflow == "" {
				workflow = v
			}
			if v := knownText(j.Name); v != "" && job == "" {
				job = v
			}
			if v, ok := knownNumber(j.RunID); ok && runID == nil {
				id := v
				runID = &id
			}
		}
	}
	return repository, workflow, job, runID
}
