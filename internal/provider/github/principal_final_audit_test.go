package github

// principal phase 5 final-audit findings F2–F5 (docs/reviews/phase5-principal-audit.md
// §5). all four are fixed; these are their regression tests.

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"deprehendo/internal/platform"
	"deprehendo/internal/provider/evidence"
)

// F2 (G2, S2): cgroup identity is visible and a docker container step runs,
// but no witnessed docker client is in the job tree (it already exited, or
// another runtime started the container). the step is not attributed, and the
// bound job must say its process list may be incomplete. today it carries no
// marker, which is the silent untagging G2 was opened for.
func TestPrincipalFinalF2UnattributedContainerStepMarksTheJob(t *testing.T) {
	host, _, base := fakeRunner(t,
		"2026-10-28 12:00:01.500 +00:00 [RUNNER 1] Listening for Jobs",
		"2026-10-28 12:00:02.000 +00:00 [RUNNER 1] Received job message")
	host.table = append(host.table,
		platform.Process{PID: 500, PPID: 1, StartTicks: 50, Name: "containerd", State: "S"},
		platform.Process{PID: 600, PPID: 500, StartTicks: 60, Name: "node", State: "S"},
	)
	host.exe[500] = filepath.Join("/usr", "bin", "containerd")
	s := attachSession(t, host)
	s.Observe(context.Background(), snapWithCgroup(host, base, map[int]string{600: containerCgroupPath}))
	section, err := s.Freeze(context.Background(), base.Add(-time.Second), base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if len(section.Jobs) != 1 {
		t.Fatalf("jobs = %+v", section.Jobs)
	}
	for _, code := range section.Jobs[0].Evidence {
		if code == EvidenceContainerLinkageUnavailable {
			return
		}
	}
	t.Fatalf("job evidence = %v: an unattributed container step left no %s marker",
		section.Jobs[0].Evidence, EvidenceContainerLinkageUnavailable)
}

// F3 (G4, S2): the stall-window override accepts any positive duration. A
// window shorter than a few samples turns every quiet sample into a C11
// progress stall. values below the floor must keep the default.
func TestPrincipalFinalF3StallWindowHasAFloor(t *testing.T) {
	for _, raw := range []string{"1ms", "500ms", "2s"} {
		t.Setenv(stallWindowEnvironment, raw)
		if got := stallWindowFromEnv(); got < 10*time.Second {
			t.Fatalf("%s=%s gave a %v window; a sub-10s window fabricates stalls", stallWindowEnvironment, raw, got)
		}
	}
}

// F4: the C11 window in force is recorded in the section, and the schema
// rejects an out-of-range value.
func TestPrincipalFinalF4StallWindowIsRecorded(t *testing.T) {
	t.Setenv(stallWindowEnvironment, "45s")
	host, _, base := fakeRunner(t, "[2026-10-28 12:00:01Z INFO Terminal] Listening for Jobs")
	s := attachSession(t, host)
	s.Observe(context.Background(), snapshotAt(host, base, 0))
	section := freezeAll(t, s, base)
	if section.StallWindowSeconds != 45 {
		t.Fatalf("stall window recorded = %ds, want 45", section.StallWindowSeconds)
	}
	section.StallWindowSeconds = 1
	if err := section.Validate(); err == nil {
		t.Fatal("a 1 s stall window passed validation")
	}
}

// F5: a runner stopping without a stated reason rests on the locally
// observed supervisor exit, and says so.
func TestPrincipalFinalF5SelfTerminationCitesTheProcessExit(t *testing.T) {
	s := sigSection([]evidence.Event{
		{Timestamp: sigT0, Type: EventRunnerStopped, Runner: sigRunner, Source: evidence.SourceLocalProcess},
	}, nil, nil)
	got := SelfTermination(s)
	if len(got) != 1 || len(got[0].Evidence) != 1 || got[0].Evidence[0] != EvidenceSupervisorExitObserved {
		t.Fatalf("self-termination evidence = %+v, want [%s]", got, EvidenceSupervisorExitObserved)
	}
}
