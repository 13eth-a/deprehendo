package diagnosis

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"time"

	"deprehendo/internal/incident"
	"deprehendo/internal/platform"
)

// signature is one diagnosis rule evaluated over the precomputed context
// (3.2). analyze returns a match whose confidence may be below the report
// threshold; the engine demotes those to rejections, keeping their evidence
// for --explain. rules must be deterministic, read-only, and must never
// mutate the incident or context.
type Signature interface {
	ID() SignatureID
	Description() string
	Analyze(*AnalysisContext) SignatureMatch
}

// signatureMetadata declares how signatures relate (3.21/3.22). exclusion is
// the v1 conflict model: an excluded pair describes the same abnormality
// through rival explanations, and only a confidence margin may pick a
// winner. allowed pairs coexist automatically: metadata opting nothing in
// means nothing is suppressed.
type signatureMetadata struct {
	Excludes []SignatureID
}

var exclusions = []struct {
	A, B SignatureID
}{
	{SignatureBrokerStall, SignatureNetworkFailure},
}

// exclusionMargin is the confidence gap the engine requires to suppress the
// weaker side of an excluded pair. below the gap both are reported and the
// report is marked ambiguous: forcing a winner would invent certainty.
const exclusionMargin = 0.15

// options confine the analyzer (3.20/3.23). zero values mean defaults.
type Options struct {
	// MinConfidence is the report threshold; 0 or negative selects
	// DefaultMinConfidence.
	MinConfidence float64
	// disable removes signatures by stable ID.
	Disable []SignatureID
	// covers are provider intents that explain process exits inside their
	// window (5.25, T2). A process group whose every vanished member is covered
	// is intended termination, not a group kill.
	Covers []IntentCover
}

// IntentCover names the processes a provider-stated intent explains, and the
// window in which their exits count as intended.
type IntentCover struct {
	Processes []ProcessIdentity
	From      time.Time
	Until     time.Time
	// RunnerTree marks a stated stop of the runner's whole tree (service
	// stop, self-update, ephemeral completion). see causal.IntentCover.
	RunnerTree bool
	// JobTree marks a stated job outcome: cancellation, timeout or success.
	// it covers the job's whole tree, not only the role-tagged processes the
	// provider section names, because the runner SIGKILLs leftover job
	// processes when the job ends. those exits are the job's own cleanup, not
	// a group kill (real-runner run 41950041166).
	JobTree bool
}

// analyzer evaluates the bundled signature set. it is immutable and safe for
// concurrent use; a run never mutates its input.
type Analyzer struct {
	signatures []Signature
}

// NewAnalyzerWithSignatures creates an analyzer with a caller-supplied,
// stable ordered signature set. duplicate or empty IDs are rejected by
// analyze to prevent ambiguous reports.
func NewAnalyzerWithSignatures(signatures []Signature) *Analyzer {
	return &Analyzer{signatures: append([]Signature(nil), signatures...)}
}

// DefaultSignatures returns the bundled rules in stable, documented order
// (3.20). the registry is a slice so ordering and enable/disable are
// explicit.
func DefaultSignatures() []Signature {
	return []Signature{
		OOMKillSignature{},
		FrozenProcessSignature{},
		CPUSpinSignature{},
		DiskExhaustionSignature{},
		OrphanProcessTreeSignature{},
		ProcessGroupTerminationSignature{},
		BrokerSocketStallSignature{},
		NetworkPathFailureSignature{},
		ResourceStarvationSignature{},
	}
}

func NewAnalyzer() *Analyzer {
	return NewAnalyzerWithSignatures(DefaultSignatures())
}

// severity assigns the incident-level label. severity is attached by the
// engine to keep rule code focused on evidence.
func severity(id SignatureID) Severity {
	switch id {
	case SignatureOOMKill, SignatureGroupKill, SignatureDiskExhaustion:
		return SeverityCritical
	default:
		return SeverityWarning
	}
}

// strongObservation is a bounded factual anchor for the UNKNOWN report.
type strongObservation struct {
	at time.Time
	ev Evidence
}

// strongObservations collects bounded factual anchors for incidents where no
// signature crossed the threshold (3.24): what deprehendo did observe strongly,
// without claiming a cause.
func (c *AnalysisContext) strongObservations() []Evidence {
	var out []strongObservation
	add := func(ev Evidence, at time.Time) {
		out = append(out, strongObservation{at: at, ev: ev})
	}
	for _, e := range c.Events {
		if e.Type == incident.ProcessExited {
			add(Evidence{
				Code: CodeProcessExited, Source: SourceEvent, At: e.Timestamp,
				Observed: map[string]any{"pid": e.PID, "start_ticks": e.StartTicks},
			}, e.Timestamp)
		}
	}
	for _, life := range c.orderedProcesses() {
		for _, ep := range life.Stopped {
			if ep.StillStopped {
				add(Evidence{
					Code: CodeProcessStopped, Source: SourceProcess, At: ep.From,
					Observed: map[string]any{"pid": life.Identity.PID, "start_ticks": life.Identity.StartTicks, "until": ep.To},
				}, ep.From)
			}
		}
	}
	for _, resource := range []platform.Resource{platform.PressureCPU, platform.PressureMemory, platform.PressureIO} {
		if peak, ok := c.PressurePeak(resource, false); ok && peak >= pressureSomeStressed {
			add(Evidence{
				Code: CodePsiSomeExhausted, Source: SourcePressure,
				Observed: peak, Threshold: pressureSomeStressed, At: c.TimeOfPressure(resource, peak),
			}, c.TimeOfPressure(resource, peak))
		}
	}
	if c.MemoryPeak >= 95 {
		add(Evidence{
			Code: CodeHostMemoryNearLimit, Source: SourceHost,
			Observed: c.MemoryPeak, Threshold: 95, At: c.timeOfMemory(c.MemoryPeak),
		}, c.timeOfMemory(c.MemoryPeak))
	}
	if c.DiskMinFree >= 0 && c.DiskMinFree <= 5 {
		add(Evidence{
			Code: CodeDiskSustainedLowFree, Source: SourceHost,
			Observed: c.DiskMinFree, Threshold: 5, At: c.timeOfDisk(c.DiskMinFree),
		}, c.timeOfDisk(c.DiskMinFree))
	}
	sort.SliceStable(out, func(a, b int) bool {
		if !out[a].at.Equal(out[b].at) {
			return out[a].at.Before(out[b].at)
		}
		return out[a].ev.Code < out[b].ev.Code
	})
	if len(out) > 8 {
		out = out[:8]
	}
	result := make([]Evidence, 0, len(out))
	for _, s := range out {
		result = append(result, s.ev)
	}
	return result
}

// analyze produces the deterministic report for one incident. it validates
// the incident first: analysis refuses fabricated evidence streams rather
// than risking nonsense classifications.
func (a *Analyzer) Analyze(i *incident.Incident, options Options) (*Report, error) {
	if err := incident.Validate(i); err != nil {
		return nil, fmt.Errorf("diagnosis: %w", err)
	}
	minConfidence := options.MinConfidence
	if math.IsNaN(minConfidence) || math.IsInf(minConfidence, 0) {
		return nil, fmt.Errorf("diagnosis: minimum confidence must be finite")
	}
	if minConfidence <= 0 {
		minConfidence = DefaultMinConfidence
	}
	if minConfidence > 1 {
		return nil, fmt.Errorf("diagnosis: minimum confidence must be in [0,1]")
	}
	seenids := make(map[SignatureID]bool, len(a.signatures))
	for _, sig := range a.signatures {
		if sig == nil || (reflect.ValueOf(sig).Kind() == reflect.Pointer && reflect.ValueOf(sig).IsNil()) || sig.ID() == "" {
			return nil, fmt.Errorf("diagnosis: signature has an empty ID")
		}
		if seenids[sig.ID()] {
			return nil, fmt.Errorf("diagnosis: duplicate signature ID %q", sig.ID())
		}
		seenids[sig.ID()] = true
	}
	disabled := map[SignatureID]bool{}
	for _, id := range options.Disable {
		disabled[id] = true
	}
	ctx := buildContext(i)
	ctx.covers = options.Covers

	matches := make([]SignatureMatch, 0, len(a.signatures))
	rejections := make([]SignatureMatch, 0, len(a.signatures))
	for _, id := range options.Disable {
		if !seenids[id] {
			return nil, fmt.Errorf("diagnosis: cannot disable unknown signature %q", id)
		}
	}
	for _, sig := range a.signatures {
		if disabled[sig.ID()] {
			continue
		}
		match := sig.Analyze(ctx)
		if err := validateMatch(sig.ID(), match); err != nil {
			return nil, err
		}
		match.Version = SignatureVersion
		match.Severity = severity(sig.ID())
		if match.Rejected == "" && match.Confidence < minConfidence {
			match.Rejected = fmt.Sprintf("confidence %.2f is below the %.2f threshold", match.Confidence, minConfidence)
		}
		if match.Rejected != "" {
			if match.Band == "" {
				match.Band = BandFor(match.Confidence)
			}
			rejections = append(rejections, match)
			continue
		}
		match.Band = BandFor(match.Confidence)
		matches = append(matches, match)
	}

	matches, rejections, ambiguous := resolveExclusions(matches, rejections)
	report := &Report{
		IncidentID:    i.ID,
		Trigger:       i.Trigger.Type,
		TriggeredAt:   i.TriggeredAt,
		Analyzer:      AnalyzerVersion,
		SignatureSet:  SignatureSetVersion,
		MinConfidence: minConfidence,
		Matches:       matches,
		Rejections:    rejections,
		Ambiguous:     ambiguous,
	}
	sortMatchesByConfidence(report.Rejections)
	if len(matches) == 0 {
		report.Unknown = true
		report.StrongObservations = ctx.strongObservations()
	}
	return report, nil
}

// analyze runs the default bundled signature set.
func Analyze(i *incident.Incident, options Options) (*Report, error) {
	return NewAnalyzer().Analyze(i, options)
}

// resolveExclusions applies the pairwise exclusion semantics. matches are
// keyed stably: ties break on signature ID so the same incident always
// produces the same report.
func resolveExclusions(matches, rejections []SignatureMatch) ([]SignatureMatch, []SignatureMatch, []string) {
	var ambiguous []string
	for _, pair := range exclusions {
		indexa, hasa := indexOfMatch(matches, pair.A)
		indexb, hasb := indexOfMatch(matches, pair.B)
		if !hasa || !hasb {
			continue
		}
		a, b := matches[indexa], matches[indexb]
		switch {
		case a.Confidence-b.Confidence >= exclusionMargin-1e-12:
			b.Rejected = fmt.Sprintf("excluded by higher-confidence %s (margin %.2f)", pair.A, exclusionMargin)
			rejections = append(rejections, b)
			matches = removeMatch(matches, indexb)
		case b.Confidence-a.Confidence >= exclusionMargin-1e-12:
			a.Rejected = fmt.Sprintf("excluded by higher-confidence %s (margin %.2f)", pair.B, exclusionMargin)
			rejections = append(rejections, a)
			matches = removeMatch(matches, indexa)
		default:
			// both explanations are comparable; the engine refuses to pick
			// and says so instead of inventing certainty (3.21).
			ambiguous = append(ambiguous, fmt.Sprintf("%s vs %s", pair.A, pair.B))
		}
	}
	sortMatchesByConfidence(matches)
	return matches, rejections, ambiguous
}

func indexOfMatch(matches []SignatureMatch, id SignatureID) (int, bool) {
	for index := range matches {
		if matches[index].SignatureID == id {
			return index, true
		}
	}
	return -1, false
}

func removeMatch(matches []SignatureMatch, index int) []SignatureMatch {
	return append(matches[:index:index], matches[index+1:]...)
}

func sortMatchesByConfidence(matches []SignatureMatch) {
	sort.SliceStable(matches, func(a, b int) bool {
		if matches[a].Confidence != matches[b].Confidence {
			return matches[a].Confidence > matches[b].Confidence
		}
		return matches[a].SignatureID < matches[b].SignatureID
	})
}

func validateMatch(id SignatureID, match SignatureMatch) error {
	if match.SignatureID != id {
		return fmt.Errorf("diagnosis: signature %s returned mismatched ID %s", id, match.SignatureID)
	}
	if math.IsNaN(match.Confidence) || math.IsInf(match.Confidence, 0) || match.Confidence < 0 || match.Confidence > 1 {
		return fmt.Errorf("diagnosis: signature %s returned invalid confidence", id)
	}
	if match.Rejected == "" && match.Confidence > 0 && len(match.Supporting) == 0 {
		return fmt.Errorf("diagnosis: signature %s returned a match without supporting evidence", id)
	}
	for _, list := range [][]Evidence{match.Supporting, match.Contradicting} {
		for _, ev := range list {
			if ev.Code == "" || ev.Source == "" || math.IsNaN(ev.Weight) || math.IsInf(ev.Weight, 0) || ev.Weight < 0 || ev.Weight > 1 {
				return fmt.Errorf("diagnosis: signature %s returned invalid evidence", id)
			}
		}
	}
	if _, err := json.Marshal(match); err != nil {
		return fmt.Errorf("diagnosis: signature %s returned non-serializable evidence: %w", id, err)
	}
	return nil
}
