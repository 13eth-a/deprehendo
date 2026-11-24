package diagnosis

import (
	"math"
	"testing"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/platform"
)

func TestArchitectureCollectorErrorsOverrideSuccessfulMetrics(t *testing.T) {
	s := withProcess(systemSnapshot(at(0), 99, 1), 42, 10, "T", 100)
	s.Metrics = []collector.CollectorTiming{{Name: "processes"}, {Name: "system"}}
	s.Errors = []collector.CollectionError{{Collector: "processes"}, {Collector: "system"}}
	sm := newSample(s)
	if sm.Available[CoverProcesses] || sm.Available[CoverSystem] {
		t.Fatal("error was overridden by optimistic metric")
	}
	s.Errors = nil
	s.Metrics = append(s.Metrics, collector.CollectorTiming{Name: "processes", Error: true})
	if newSample(s).Available[CoverProcesses] {
		t.Fatal("duplicate failed metric ignored")
	}
}
func TestArchitectureUnavailableSamplesBreakResourceDuration(t *testing.T) {
	i := validIncident(t, at(0), at(20*time.Second))
	for n := range 3 {
		s := systemSnapshot(at(time.Duration(n)*10*time.Second), 99, 1)
		s = withPressure(s, platform.PressureCPU, 80, 40)
		if n == 1 {
			s.System = nil
			s.Pressure = nil
		}
		i.Snapshots = append(i.Snapshots, s)
	}
	c := buildContext(i)
	if c.MemoryOverDuration(95) != 0 || c.DiskUnderDuration(2) != 0 || c.PressureSustained(platform.PressureCPU, false, 50) != 0 {
		t.Fatal("missing sensor bridged sustained duration")
	}
	if c.resourcesKnownHealthy() {
		t.Fatal("missing telemetry became healthy evidence")
	}
}
func TestArchitectureGapUsesFirstAbsentAndNeverCrossesFailure(t *testing.T) {
	for _, failed := range []bool{false, true} {
		i := validIncident(t, at(0), at(20*time.Second))
		i.Snapshots = []collector.Snapshot{withProcess(systemSnapshot(at(0), 30, 80), 42, 10, "S", 0), systemSnapshot(at(10*time.Second), 30, 80), systemSnapshot(at(20*time.Second), 30, 80)}
		if failed {
			i.Snapshots[1].Errors = []collector.CollectionError{{Collector: "processes"}}
		}
		life := buildContext(i).Process[identity{42, 10}]
		if failed {
			if len(life.Gaps) != 0 {
				t.Fatalf("failed sample inferred departure: %+v", life.Gaps)
			}
		} else if len(life.Gaps) != 1 || !life.Gaps[0].From.Equal(at(10*time.Second)) {
			t.Fatalf("wrong departure anchor: %+v", life.Gaps)
		}
	}
}
func TestArchitectureStoppedEpisodeCannotExtendThroughAbsenceOrFailure(t *testing.T) {
	for _, failed := range []bool{false, true} {
		i := validIncident(t, at(0), at(20*time.Second))
		first := withProcess(systemSnapshot(at(0), 30, 80), 42, 10, "T", 0)
		next := systemSnapshot(at(10*time.Second), 30, 80)
		if failed {
			next.Errors = []collector.CollectionError{{Collector: "processes"}}
		}
		i.Snapshots = []collector.Snapshot{first, next, systemSnapshot(at(20*time.Second), 30, 80)}
		life := buildContext(i).Process[identity{42, 10}]
		ep := life.Stopped[0]
		if ep.Span(at(20*time.Second)) != 0 || ep.StillStopped || ep.Resumed {
			t.Fatalf("invented stopped/resumed span: %+v", ep)
		}
	}
}
func TestArchitectureCPUGapsBreakSmoothing(t *testing.T) {
	i := validIncident(t, at(0), at(20*time.Second))
	i.Snapshots = []collector.Snapshot{withProcess(systemSnapshot(at(0), 30, 80), 42, 10, "R", 100), systemSnapshot(at(10*time.Second), 30, 80), withProcess(systemSnapshot(at(20*time.Second), 30, 80), 42, 10, "R", 100)}
	c := buildContext(i)
	if span := c.identitySustainedCPU(c.Process[identity{42, 10}], 90); span != 0 {
		t.Fatalf("CPU span bridges disappearance: %s", span)
	}
}
func TestArchitectureOwnershipUsesContemporaneousIdentity(t *testing.T) {
	i := validIncident(t, at(0), at(20*time.Second))
	for n, start := range []int64{10, 10, 20} {
		s := withProcess(systemSnapshot(at(time.Duration(n)*10*time.Second), 30, 80), 42, start, "S", 0)
		s = withConnection(s, 123, 1000, 443, "ESTABLISHED", 42)
		i.Snapshots = append(i.Snapshots, s)
	}
	c := buildContext(i)
	life := c.orderedConnections()[0]
	if life.Owner != (identity{42, 20}) || !life.OwnerKnown || life.Continuous {
		t.Fatalf("recycled owner treated as continuous: %+v", life)
	}
}
func TestArchitectureSocketGapsAndEstablishedAnchor(t *testing.T) {
	i := validIncident(t, at(0), at(20*time.Second))
	for n := range 3 {
		s := withProcess(systemSnapshot(at(time.Duration(n)*10*time.Second), 30, 80), 42, 10, "S", 0)
		if n != 1 {
			state := "SYN_SENT"
			if n == 2 {
				state = "ESTABLISHED"
			}
			s = withConnection(s, 123, 1000, 443, state, 42)
		}
		s.Metrics = []collector.CollectorTiming{{Name: "connections"}}
		i.Snapshots = append(i.Snapshots, s)
	}
	life := buildContext(i).orderedConnections()[0]
	if life.Continuous || !life.EstablishedSince.Equal(at(20*time.Second)) {
		t.Fatalf("fabricated established continuity: %+v", life)
	}
}
func TestArchitectureUnknownCoverageAndZombieAreNotAliveEvidence(t *testing.T) {
	i := validIncident(t, at(0), at(0))
	c := buildContext(i)
	if c.coverageOK(CoverProcesses) || c.resourcesKnownHealthy() {
		t.Fatal("empty capture treated as covered/healthy")
	}
	i.Snapshots = []collector.Snapshot{withProcess(systemSnapshot(at(0), 30, 80), 42, 10, "Z", 0)}
	c = buildContext(i)
	if c.Process[identity{42, 10}].AliveAtEnd(c.End) {
		t.Fatal("zombie was treated as living owner")
	}
}
func TestArchitectureTemporalSaturationAndZeroDuration(t *testing.T) {
	old := time.Date(1000, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)
	if Within(old, recent, time.Duration(math.MaxInt64)) || Within(recent, old, time.Second) {
		t.Fatal("duration saturation became close timestamps")
	}
	if DurationAbove(0, 0) || DurationAbove(-1, 0) || !DurationAbove(time.Second, 0) {
		t.Fatal("invalid duration semantics")
	}
}

type architectureSignature struct{ match SignatureMatch }

func (*architectureSignature) ID() SignatureID                           { return "CUSTOM" }
func (*architectureSignature) Description() string                       { return "test" }
func (s *architectureSignature) Analyze(*AnalysisContext) SignatureMatch { return s.match }
func TestArchitectureEngineRejectsInvalidScoresAndSignatures(t *testing.T) {
	i := validIncident(t, at(0), at(0))
	for _, value := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := Analyze(i, Options{MinConfidence: value}); err == nil {
			t.Fatal("nonfinite threshold accepted")
		}
	}
	var nilSignature *architectureSignature
	if _, err := NewAnalyzerWithSignatures([]Signature{nilSignature}).Analyze(i, Options{}); err == nil {
		t.Fatal("typed nil signature accepted")
	}
	for _, match := range []SignatureMatch{{SignatureID: "CUSTOM", Confidence: math.NaN()}, {SignatureID: "CUSTOM", Confidence: 1.1}, {SignatureID: "WRONG"}, {SignatureID: "CUSTOM", Confidence: .8}, {SignatureID: "CUSTOM", Rejected: "test", Supporting: []Evidence{{Code: CodeCPUSustained, Source: SourceProcess, Weight: math.Inf(1)}}}} {
		if _, err := NewAnalyzerWithSignatures([]Signature{&architectureSignature{match}}).Analyze(i, Options{}); err == nil {
			t.Fatalf("invalid match accepted: %+v", match)
		}
	}
}
func TestArchitectureExclusionExactMarginIsDeterministic(t *testing.T) {
	out, rejected, ambiguous := resolveExclusions([]SignatureMatch{{SignatureID: SignatureBrokerStall, Confidence: .9}, {SignatureID: SignatureNetworkFailure, Confidence: .75}}, nil)
	if len(out) != 1 || len(rejected) != 1 || len(ambiguous) != 0 {
		t.Fatalf("exact margin lost to float subtraction: %v %v %v", out, rejected, ambiguous)
	}
}
func TestArchitectureStateTransitionHasBothEndpoints(t *testing.T) {
	i := validIncident(t, at(0), at(time.Second))
	i.Snapshots = []collector.Snapshot{withProcess(systemSnapshot(at(0), 30, 80), 42, 10, "S", 0), withProcess(systemSnapshot(at(time.Second), 30, 80), 42, 10, "T", 0)}
	life := buildContext(i).Process[identity{42, 10}]
	if got := life.States[1]; got.From != "S" || got.To != "T" {
		t.Fatalf("lost factual transition: %+v", got)
	}
}

func TestArchitectureSocketGapCannotInventTransition(t *testing.T) {
	for _, failed := range []bool{false, true} {
		i := validIncident(t, at(0), at(20*time.Second))
		for n := range 3 {
			s := withProcess(systemSnapshot(at(time.Duration(n)*10*time.Second), 30, 80), 42, 10, "S", 0)
			s.Metrics = []collector.CollectorTiming{{Name: "connections"}}
			if n != 1 {
				state := "ESTABLISHED"
				if n == 2 {
					state = "CLOSE_WAIT"
				}
				s = withConnection(s, 123, 1000, 443, state, 42)
			}
			if n == 1 && failed {
				s.Errors = []collector.CollectionError{{Collector: "connections"}}
			}
			i.Snapshots = append(i.Snapshots, s)
		}
		life := buildContext(i).orderedConnections()[0]
		if _, left := life.leftEstablishedMidCapture(); left {
			t.Fatalf("missing socket sample inferred transition (failed=%v)", failed)
		}
	}
}
