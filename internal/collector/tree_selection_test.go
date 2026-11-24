package collector

import (
	"testing"

	"deprehendo/internal/platform"
)

func proc(pid, ppid int, start int64, name string) ProcessSnapshot {
	return ProcessSnapshot{Process: platform.Process{PID: pid, PPID: ppid, StartTicks: start, Name: name}}
}

func pids(in []ProcessSnapshot) map[int]bool {
	out := map[int]bool{}
	for _, p := range in {
		out[p.PID] = true
	}
	return out
}

// S8 shape: listener(100) -> worker(200) -> step bash(300) -> sleep(400).
// the step ends (bash exits, sleep reparents to init), then the worker exits.
// the sleep must stay in every sample while it lives.
func TestTreeSelectionRetainsReparentedDescendant(t *testing.T) {
	sel := TreeSelection{Filter: Filter{PIDs: []int{100}, Descendants: true}}
	initp := proc(1, 0, 1, "systemd")
	unrelated := proc(900, 1, 90, "cron")

	got := pids(sel.Select([]ProcessSnapshot{initp, proc(100, 1, 10, "Runner.Listener"), proc(200, 100, 20, "Runner.Worker"), proc(300, 200, 30, "bash"), proc(400, 300, 40, "sleep"), unrelated}))
	if !got[400] || got[900] || got[1] {
		t.Fatalf("cycle 1 selection = %v", got)
	}
	got = pids(sel.Select([]ProcessSnapshot{initp, proc(100, 1, 10, "Runner.Listener"), proc(200, 100, 20, "Runner.Worker"), proc(400, 1, 40, "sleep"), unrelated}))
	if !got[400] {
		t.Fatal("reparented descendant dropped as soon as its parent exited")
	}
	got = pids(sel.Select([]ProcessSnapshot{initp, proc(100, 1, 10, "Runner.Listener"), proc(400, 1, 40, "sleep"), unrelated}))
	if !got[400] || got[900] || got[1] {
		t.Fatalf("after worker exit: selection = %v", got)
	}
	// gone: forgotten, so a later reuse of the PID is not retained.
	sel.Select([]ProcessSnapshot{initp, proc(100, 1, 10, "Runner.Listener")})
	got = pids(sel.Select([]ProcessSnapshot{initp, proc(100, 1, 10, "Runner.Listener"), proc(400, 1, 41, "sleep")}))
	if got[400] {
		t.Fatal("a reused PID was retained after the original incarnation exited")
	}
}

func TestTreeSelectionDoesNotRetainAReusedPID(t *testing.T) {
	sel := TreeSelection{Filter: Filter{PIDs: []int{100}, Descendants: true}}
	sel.Select([]ProcessSnapshot{proc(100, 1, 10, "Runner.Listener"), proc(400, 100, 40, "sleep")})
	got := pids(sel.Select([]ProcessSnapshot{proc(100, 1, 10, "Runner.Listener"), proc(400, 1, 77, "sshd")}))
	if got[400] {
		t.Fatal("a different incarnation under the same PID was retained")
	}
}

func TestTreeSelectionFollowsChildrenOfARetainedOrphan(t *testing.T) {
	sel := TreeSelection{Filter: Filter{PIDs: []int{100}, Descendants: true}}
	sel.Select([]ProcessSnapshot{proc(100, 1, 10, "Runner.Listener"), proc(300, 100, 30, "bash"), proc(400, 300, 40, "daemon")})
	got := pids(sel.Select([]ProcessSnapshot{proc(100, 1, 10, "Runner.Listener"), proc(400, 1, 40, "daemon"), proc(401, 400, 41, "child")}))
	if !got[400] || !got[401] {
		t.Fatalf("orphan or its new child dropped: %v", got)
	}
}

// macOS reports no start time; the name guards against PID reuse there.
func TestTreeSelectionWithoutStartTimeUsesName(t *testing.T) {
	sel := TreeSelection{Filter: Filter{PIDs: []int{100}, Descendants: true}}
	sel.Select([]ProcessSnapshot{proc(100, 1, 0, "Runner.Listener"), proc(400, 100, 0, "sleep")})
	if got := pids(sel.Select([]ProcessSnapshot{proc(100, 1, 0, "Runner.Listener"), proc(400, 1, 0, "sleep")})); !got[400] {
		t.Fatal("orphan without a start time was dropped")
	}
	if got := pids(sel.Select([]ProcessSnapshot{proc(100, 1, 0, "Runner.Listener"), proc(400, 1, 0, "sshd")})); got[400] {
		t.Fatal("a reused PID running another program was retained")
	}
}

func TestTreeSelectionWithoutDescendantsIsTheStatelessFilter(t *testing.T) {
	sel := TreeSelection{Filter: Filter{PIDs: []int{400}}}
	if got := pids(sel.Select([]ProcessSnapshot{proc(400, 300, 40, "sleep"), proc(401, 400, 41, "x")})); !got[400] || got[401] {
		t.Fatalf("selection = %v", got)
	}
	if got := sel.Select([]ProcessSnapshot{proc(1, 0, 1, "init")}); len(got) != 0 {
		t.Fatalf("unmatched cycle selected %v", got)
	}
	all := []ProcessSnapshot{proc(1, 0, 1, "init"), proc(2, 1, 2, "x")}
	if got := (&TreeSelection{}).Select(all); len(got) != 2 {
		t.Fatal("an inactive filter must record everything")
	}
}
