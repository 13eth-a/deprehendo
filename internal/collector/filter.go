package collector

import "path"

// filter selects which processes are retained in each snapshot. an empty
// filter means "record every process" (the safe default for a flight
// recorder); otherwise the selected set is the union of explicit PIDs and
// name matches, optionally expanded to the full descendant tree of every
// match. the whole table is still sampled before filtering, because tree
// expansion needs the complete PPID graph for that instant.
type Filter struct {
	// PIDs are watched process ids. missing pids (already exited) simply
	// match nothing for that cycle.
	PIDs []int
	// name matches a process name exactly, or the base name of a process
	// whose reported name is a path (macOS `ps comm` reports the path).
	// linux comm values are kernel-truncated to 15 bytes, so longer names
	// cannot be matched there.
	Name string
	// descendants adds every descendant of each match, including children
	// that appear after recording started. this is the most useful watch
	// mode for process trees. across cycles (TreeSelection, used by the
	// scheduler) a descendant stays selected after it is reparented away
	// from the tree, for as long as the same incarnation is alive: an
	// orphan is exactly the process a tree recorder must not lose.
	Descendants bool
}

// TreeSelection is the stateful form of filter that the scheduler applies
// once per cycle. with descendants set it retains every process incarnation
// it has selected before, while that incarnation is alive, together with the
// incarnation's own descendants. without retention, a job process whose parent
// exits (it is reparented to init or a subreaper) drops out of the very next
// sample, so no orphan can ever be observed outliving its tree (real-runner
// scenario S8). memory is bounded by the current selection: incarnations
// that are no longer present are forgotten.
//
// A TreeSelection is not safe for concurrent use; the scheduler serializes
// cycles.
type TreeSelection struct {
	Filter   Filter
	retained map[incarnation]struct{}
}

// incarnation identifies one process lifetime. where the platform reports no
// start time (StartTicks 0, macOS), the name stands in as a guard so a reused
// PID running a different program is not retained.
type incarnation struct {
	pid   int
	start int64
	name  string
}

func incarnationOf(p ProcessSnapshot) incarnation {
	key := incarnation{pid: p.PID, start: p.StartTicks}
	if p.StartTicks == 0 {
		key.name = p.Name
	}
	return key
}

// select returns the processes selected this cycle, in snapshot order, and
// updates the retained set.
func (t *TreeSelection) Select(processes []ProcessSnapshot) []ProcessSnapshot {
	f := t.Filter
	if !f.Active() {
		return processes
	}
	if !f.Descendants {
		return f.Select(processes)
	}
	tree := BuildProcessTree(processes)
	selected := make(map[int]bool)
	var queue []int
	seed := func(pid int) {
		// A missing watched PID must not select a newly orphaned child that
		// still reports the vanished parent's number.
		if _, exists := tree.ByPID[pid]; exists && !selected[pid] {
			selected[pid] = true
			queue = append(queue, pid)
		}
	}
	for _, pid := range f.PIDs {
		if pid > 0 {
			seed(pid)
		}
	}
	for _, process := range processes {
		if f.Name != "" && (process.Name == f.Name || path.Base(process.Name) == f.Name) {
			seed(process.PID)
		}
		if _, kept := t.retained[incarnationOf(process)]; kept {
			seed(process.PID)
		}
	}
	for i := 0; i < len(queue); i++ {
		for _, child := range tree.Children[queue[i]] {
			if !selected[child] {
				selected[child] = true
				queue = append(queue, child)
			}
		}
	}
	out := make([]ProcessSnapshot, 0, len(selected))
	next := make(map[incarnation]struct{}, len(selected))
	for _, process := range processes {
		if selected[process.PID] {
			out = append(out, process)
			next[incarnationOf(process)] = struct{}{}
		}
	}
	t.retained = next
	return out
}

// active reports whether the filter selects anything; false means unfiltered.
func (f Filter) Active() bool {
	return len(f.PIDs) > 0 || f.Name != ""
}

// select returns the matching processes in their original snapshot order.
// the input slice is not modified.
func (f Filter) Select(processes []ProcessSnapshot) []ProcessSnapshot {
	if !f.Active() {
		return processes
	}
	selected := make(map[int]bool, len(f.PIDs))
	for _, pid := range f.PIDs {
		if pid > 0 {
			selected[pid] = true
		}
	}
	if f.Name != "" {
		for _, process := range processes {
			if process.Name == f.Name || path.Base(process.Name) == f.Name {
				selected[process.PID] = true
			}
		}
	}
	if f.Descendants && len(selected) > 0 {
		tree := BuildProcessTree(processes)
		queue := make([]int, 0, len(selected))
		for pid := range selected {
			// A missing watched PID must not select a newly orphaned child
			// that still reports the vanished parent's number.
			if _, exists := tree.ByPID[pid]; exists {
				queue = append(queue, pid)
			}
		}
		for i := 0; i < len(queue); i++ {
			for _, child := range tree.Children[queue[i]] {
				if !selected[child] {
					selected[child] = true
					queue = append(queue, child)
				}
			}
		}
	}
	out := make([]ProcessSnapshot, 0, len(selected))
	for _, process := range processes {
		if selected[process.PID] {
			out = append(out, process)
		}
	}
	return out
}
