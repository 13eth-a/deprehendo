package collector

import (
	"testing"

	"runopsy/internal/platform"
)

func filterProcess(pid, ppid int, name string) ProcessSnapshot {
	return ProcessSnapshot{Process: platform.Process{PID: pid, PPID: ppid, Name: name, State: "S"}}
}

func filterFixture() []ProcessSnapshot {
	return []ProcessSnapshot{
		filterProcess(1, 0, "init"),
		filterProcess(100, 1, "Runner.Listener"),
		filterProcess(101, 100, "node"),
		filterProcess(102, 101, "worker"),
		filterProcess(200, 1, "unrelated"),
	}
}

func pidsOf(processes []ProcessSnapshot) []int {
	pids := make([]int, 0, len(processes))
	for _, process := range processes {
		pids = append(pids, process.PID)
	}
	return pids
}

func TestFilterInactiveRecordsEverything(t *testing.T) {
	filter := Filter{}
	if filter.Active() {
		t.Fatal("empty filter reported active")
	}
	all := filterFixture()
	if got := filter.Select(all); len(got) != len(all) {
		t.Fatalf("inactive filter returned %d processes, want %d", len(got), len(all))
	}
}

func TestFilterByPID(t *testing.T) {
	got := Filter{PIDs: []int{100}}.Select(filterFixture())
	if len(got) != 1 || got[0].PID != 100 {
		t.Fatalf("pid selection = %v, want [100]", pidsOf(got))
	}
}

func TestFilterMissingPIDMatchesNothing(t *testing.T) {
	if got := (Filter{PIDs: []int{999999}}).Select(filterFixture()); len(got) != 0 {
		t.Fatalf("missing pid selected %v", pidsOf(got))
	}
}

func TestFilterByNameExact(t *testing.T) {
	got := Filter{Name: "Runner.Listener"}.Select(filterFixture())
	if len(got) != 1 || got[0].PID != 100 {
		t.Fatalf("name selection = %v, want [100]", pidsOf(got))
	}
}

func TestFilterByNamePathBase(t *testing.T) {
	// macOS `ps comm` reports an executable path; matching the base name
	// keeps --watch-name usable there.
	processes := []ProcessSnapshot{
		filterProcess(300, 1, "/var/folders/xyz/runopsy-sim"),
		filterProcess(301, 1, "runopsy-sim"),
	}
	got := Filter{Name: "runopsy-sim"}.Select(processes)
	if len(got) != 2 {
		t.Fatalf("path-base selection = %v, want both runopsy-sim processes", pidsOf(got))
	}
}

func TestFilterDescendants(t *testing.T) {
	got := Filter{PIDs: []int{100}, Descendants: true}.Select(filterFixture())
	want := []int{100, 101, 102}
	if len(got) != len(want) {
		t.Fatalf("tree selection = %v, want %v", pidsOf(got), want)
	}
	for i := range want {
		if got[i].PID != want[i] {
			t.Fatalf("tree selection = %v, want %v", pidsOf(got), want)
		}
	}
}

func TestFilterDescendantsFromName(t *testing.T) {
	got := Filter{Name: "Runner.Listener", Descendants: true}.Select(filterFixture())
	want := []int{100, 101, 102}
	if len(got) != len(want) {
		t.Fatalf("name tree selection = %v, want %v", pidsOf(got), want)
	}
}

func TestFilterUnionOfPIDAndName(t *testing.T) {
	got := Filter{PIDs: []int{200}, Name: "Runner.Listener"}.Select(filterFixture())
	want := []int{100, 200}
	if len(got) != len(want) || got[0].PID != want[0] || got[1].PID != want[1] {
		t.Fatalf("union selection = %v, want %v", pidsOf(got), want)
	}
}

func TestFilterDoesNotMutateInput(t *testing.T) {
	all := filterFixture()
	before := pidsOf(all)
	_ = Filter{PIDs: []int{100}, Descendants: true}.Select(all)
	after := pidsOf(all)
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("filter reordered/mutated input at %d: %v -> %v", i, before, after)
		}
	}
}
