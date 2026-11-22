package evidence

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const testProvider = "test-ci"

func init() {
	RegisterVocabulary(Vocabulary{
		Provider:       testProvider,
		EventPrefix:    "TESTCI_",
		EventTypes:     []string{"TESTCI_JOB_ASSIGNED", "TESTCI_WORKER_STARTED"},
		SocketRoles:    []string{"CONTROL_CHANNEL"},
		EvidenceCodes:  []string{"EXE_BASENAME_MATCH", "PARENT_IS_SUPERVISOR"},
		ConflictTopics: []string{"JOB_STATE"},
		ClaimValues:    []string{"QUEUED", "ASSIGNED"},
	})
}

func mustRef(t *testing.T, kind string, parts ...string) Ref {
	t.Helper()
	r, err := NewRef(kind, []byte("salt"), parts...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func validSection(t *testing.T) Section {
	t.Helper()
	at := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	runner := mustRef(t, "rnr", "/opt/runner", "runner-1")
	job := mustRef(t, "job", "run-1", "job-1")
	worker := mustRef(t, "wkr", "8421@99")
	return Section{
		Provider: testProvider, SchemaVersion: SchemaVersion, Privacy: PrivacyConservative,
		Health: Health{State: HealthAvailable},
		Runners: []Runner{{
			Ref: runner, Name: Text{State: Withheld, Class: ClassRunnerName},
			Version: KnownText(ClassVersion, "2.320.0", SourceRunnerConfig), Labels: UnknownText(ClassLabels),
			Lifecycle: LifecyclePersistent, Supervisors: []ProcessRef{{PID: 5218, StartTicks: 10}},
		}},
		Jobs: []Job{{
			Ref: job, Runner: runner,
			Repository: Text{State: Withheld, Class: ClassRepository}, Workflow: UnknownText(ClassWorkflow), Name: UnknownText(ClassJobName),
			RunID: Int64{State: Unknown, Class: ClassRunID}, JobID: Int64{State: Unknown, Class: ClassJobID}, Attempt: Int64{State: Unknown, Class: ClassAttempt},
			Outcome: OutcomeRunning,
		}},
		Workers: []Worker{{Ref: worker, Runner: runner, Process: ProcessRef{PID: 8421, StartTicks: 99}, Job: job, Started: at}},
		ProcessRoles: []ProcessRole{{
			Process: ProcessRef{PID: 8421, StartTicks: 99}, Role: RoleWorker, Runner: runner, Worker: worker, Job: job,
			Confidence: ConfidenceHigh, Sources: []Source{SourceLocalProcess}, Evidence: []string{"PARENT_IS_SUPERVISOR"},
		}},
		SocketRoles: []SocketRole{{
			Inode: 88201, Owner: ProcessRef{PID: 5218, StartTicks: 10}, Role: "CONTROL_CHANNEL", Runner: runner,
			Confidence: ConfidenceMedium, Sources: []Source{SourceLocalSocket, SourceRunnerLog}, Evidence: []string{"EXE_BASENAME_MATCH"},
		}},
		Events: []Event{{Timestamp: at, Type: "TESTCI_JOB_ASSIGNED", Runner: runner, Job: job, Source: SourceRunnerLog, Provenance: Provenance{File: 1, Offset: 4096}}},
		Conflicts: []Conflict{{Question: "JOB_STATE", Job: job, Claims: []Claim{
			{Source: SourceProviderAPI, Value: "QUEUED", ObservedAt: at}, {Source: SourceRunnerLog, Value: "ASSIGNED", ObservedAt: at},
		}}},
	}
}

func TestValidSectionValidatesAndRoundTrips(t *testing.T) {
	s := validSection(t)
	if err := s.Validate(); err != nil {
		t.Fatalf("valid section rejected: %v", err)
	}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var back Section
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if err := back.Validate(); err != nil {
		t.Fatalf("round-tripped section rejected: %v", err)
	}
}

func TestUnavailableSectionIsValid(t *testing.T) {
	s := Unavailable(testProvider, ReasonPermissionDenied)
	if err := s.Validate(); err != nil {
		t.Fatalf("an unavailable section must still be writable: %v", err)
	}
}

func TestValidateRejectsOutsideVocabularyAndSchema(t *testing.T) {
	cases := map[string]func(*Section){
		"invalid provider name":  func(s *Section) { s.Provider = "Not A Name" },
		"future schema":          func(s *Section) { s.SchemaVersion = SchemaVersion + 1 },
		"unregistered event":     func(s *Section) { s.Events[0].Type = "TESTCI_INVENTED" },
		"event without prefix":   func(s *Section) { s.Events[0].Type = "JOB_ASSIGNED" },
		"unregistered evidence":  func(s *Section) { s.ProcessRoles[0].Evidence = []string{"LOOKS_RIGHT"} },
		"no evidence codes":      func(s *Section) { s.ProcessRoles[0].Evidence = nil },
		"unknown socket role":    func(s *Section) { s.SocketRoles[0].Role = "BROKER" },
		"dangling runner":        func(s *Section) { s.Jobs[0].Runner = mustRef(t, "rnr", "other") },
		"dangling job":           func(s *Section) { s.Workers[0].Job = mustRef(t, "job", "other") },
		"pid without start time": func(s *Section) { s.Workers[0].Process.PID = 0 },
		"conflict of one claim":  func(s *Section) { s.Conflicts[0].Claims = s.Conflicts[0].Claims[:1] },
		"dropped while healthy":  func(s *Section) { s.Health.Dropped = 3 },
		"repository known under conservative": func(s *Section) {
			s.Jobs[0].Repository = KnownText(ClassRepository, "org/service", SourceRunnerLog)
		},
		"withheld value carries text": func(s *Section) {
			s.Jobs[0].Repository = Text{State: Withheld, Class: ClassRepository, Value: "org/service"}
		},
		"class mismatch": func(s *Section) { s.Runners[0].Name = UnknownText(ClassRepository) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := validSection(t)
			mutate(&s)
			if err := s.Validate(); err == nil {
				t.Errorf("accepted: %s", name)
			}
		})
	}
}

func TestRedactWithholdsByClassAndScrubsUnsafeValues(t *testing.T) {
	s := validSection(t)
	s.Privacy = PrivacyIdentifiers
	s.Runners[0].Name = KnownText(ClassRunnerName, "prod-linux-03", SourceRunnerConfig)
	s.Jobs[0].Repository = KnownText(ClassRepository, "org/service", SourceRunnerLog)
	s.Jobs[0].Workflow = KnownText(ClassWorkflow, "https://x-access-token:ghs_abc@github.com/org/repo", SourceRunnerLog)
	s.Jobs[0].RunID = Int64{State: Known, Class: ClassRunID, Value: 1842, Source: SourceRunnerLog}

	identifiers := s
	identifiers.Runners = append([]Runner(nil), s.Runners...)
	identifiers.Jobs = append([]Job(nil), s.Jobs...)
	identifiers.Redact(PrivacyIdentifiers)
	if got := identifiers.Jobs[0].Workflow; got.State != Withheld || got.Value != "" {
		t.Errorf("credential-bearing value survived identifiers redaction: %+v", got)
	}
	if identifiers.Jobs[0].Repository.State != Known || identifiers.Runners[0].Name.State != Known {
		t.Errorf("opted-in identifiers were withheld")
	}
	if err := identifiers.Validate(); err != nil {
		t.Fatalf("redacted identifiers section invalid: %v", err)
	}

	s.Redact(PrivacyConservative)
	for _, text := range []Text{s.Runners[0].Name, s.Jobs[0].Repository, s.Jobs[0].Workflow} {
		if text.State != Withheld || text.Value != "" || text.Source != "" {
			t.Errorf("conservative redaction left %+v", text)
		}
	}
	if s.Jobs[0].RunID.State != Withheld || s.Jobs[0].RunID.Value != 0 {
		t.Errorf("run id survived conservative redaction: %+v", s.Jobs[0].RunID)
	}
	if s.Runners[0].Version.State != Known {
		t.Errorf("version is public under every level")
	}
	if s.Jobs[0].Name.State != Unknown {
		t.Errorf("UNKNOWN must stay UNKNOWN, not become WITHHELD")
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("conservative section invalid: %v", err)
	}
	data, _ := json.Marshal(s)
	for _, leaked := range []string{"prod-linux-03", "org/service", "ghs_abc", "1842"} {
		if strings.Contains(string(data), leaked) {
			t.Errorf("conservative bundle JSON contains %q", leaked)
		}
	}
}

func TestSafeTextRejectsInvisibleAndControlCharacters(t *testing.T) {
	for _, v := range []string{"ok\x1b[2J", "a\u202eb", "zero\u200bwidth", "line\nbreak", strings.Repeat("a", MaxTextBytes+1)} {
		if safeText(v) == nil {
			t.Errorf("safeText accepted %q", v)
		}
	}
	if err := safeText("2.320.0"); err != nil {
		t.Errorf("plain version rejected: %v", err)
	}
}

// Probe-found gaps (adversarial review of 5.12): encoded URLs, encoded token
// prefixes, presigned signatures, JWT-shaped and opaque token strings must be
// refused as KNOWN text. ordinary names must still pass.
func TestSafeTextRejectsEncodedAndTokenShapedSecrets(t *testing.T) {
	for _, v := range []string{
		"https%3A%2F%2Fapi.github.com%2Fx",
		"X-Amz-Signature%3Dabc123",
		"ghs%5Fabc123",
		"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln",
		"0123456789abcdef0123456789abcdef01234567",
		"Ab3dEf7hIj9kLm1nOp5qRs8t",
	} {
		if safeText(v) == nil {
			t.Errorf("safeText accepted %q", v)
		}
	}
	for _, v := range []string{"build-linux-x64-ubuntu-22-04", "prod-linux-03", "2.320.0", "deploy-production"} {
		if err := safeText(v); err != nil {
			t.Errorf("ordinary value %q rejected: %v", v, err)
		}
	}
}

func TestRefsAreStableSaltedAndOpaque(t *testing.T) {
	a, _ := NewRef("rnr", []byte("host-a"), "/opt/runner", "runner-1")
	b, _ := NewRef("rnr", []byte("host-a"), "/opt/runner", "runner-1")
	c, _ := NewRef("rnr", []byte("host-b"), "/opt/runner", "runner-1")
	d, _ := NewRef("rnr", []byte("host-a"), "/opt/runner/", "runner-1")
	if a != b || !a.Valid() {
		t.Errorf("same identity must give the same valid ref: %s %s", a, b)
	}
	if a == c {
		t.Errorf("refs must differ across host salts")
	}
	if a == d {
		t.Errorf("identity parts are hashed exactly; callers canonicalise paths first")
	}
	if strings.Contains(string(a), "runner") {
		t.Errorf("ref leaks identity text: %s", a)
	}
	if _, err := NewRef("pid", nil, "1"); err == nil {
		t.Errorf("unknown ref kind accepted")
	}
}

func TestRegisterVocabularyRejectsMalformedTokens(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Errorf("malformed vocabulary accepted")
		}
	}()
	RegisterVocabulary(Vocabulary{Provider: "bad-ci", EventPrefix: "BAD_", EventTypes: []string{"BAD_ok", "lower"}})
}

// principal phase 5 audit R17: a reader without a provider compiled in must
// still accept that provider's well-formed section (forward compatibility,
// §1 item 8); only the token shape is checked. A malformed token is still
// rejected, and a registered provider stays strict.
func TestUnregisteredProviderSectionValidatesStructurally(t *testing.T) {
	s := validSection(t)
	s.Provider = "audit-unregistered-ci"
	if err := s.Validate(); err != nil {
		t.Fatalf("well-formed foreign section rejected: %v", err)
	}
	s.Events[0].Type = "lower case token"
	if err := s.Validate(); err == nil {
		t.Fatal("malformed token accepted for an unregistered provider")
	}
	strict := validSection(t)
	strict.Events[0].Type = "TESTCI_INVENTED"
	if err := strict.Validate(); err == nil {
		t.Fatal("registered provider lost its closed vocabulary")
	}
}
