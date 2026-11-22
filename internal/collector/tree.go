package collector

import "sort"

// ProcessTree reconstructs parent/child relationships from one snapshot's
// flat process list. construction never traverses the tree recursively, so a
// synthetic cycle in the data cannot hang the builder.
type ProcessTree struct {
	ByPID    map[int]*ProcessNode
	Children map[int][]int // parent pid -> child pids, sorted
	// roots are nodes whose parent is absent from the same snapshot, was
	// reported as themselves, or is pid 0. the kernel reparents orphans to
	// init or a subreaper, so pid 1 is never assumed to be a root.
	Roots []*ProcessNode
}

// ProcessNode couples a snapshot entry with its observed children.
type ProcessNode struct {
	Snapshot ProcessSnapshot
	Children []*ProcessNode
}

// BuildProcessTree links each node under its reported parent. only parents
// present in the same snapshot get children attached; missing parents make a
// node a root instead of fabricating an ancestor.
func BuildProcessTree(processes []ProcessSnapshot) *ProcessTree {
	tree := &ProcessTree{
		ByPID:    make(map[int]*ProcessNode, len(processes)),
		Children: make(map[int][]int),
	}
	for _, snapshot := range processes {
		tree.ByPID[snapshot.PID] = &ProcessNode{Snapshot: snapshot}
	}
	for pid, node := range tree.ByPID {
		ppid := node.Snapshot.PPID
		parent, ok := tree.ByPID[ppid]
		if !ok || ppid == pid || ppid <= 0 {
			tree.Roots = append(tree.Roots, node)
			continue
		}
		parent.Children = append(parent.Children, node)
		tree.Children[ppid] = append(tree.Children[ppid], pid)
	}
	// deterministic output for equal inputs: sort by pid everywhere. the
	// attachment loop ranges over a map, so both the per-parent pid lists
	// and the child node slices need an explicit sort.
	for _, pids := range tree.Children {
		sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	}
	for _, node := range tree.ByPID {
		children := node.Children
		sort.Slice(children, func(i, j int) bool { return children[i].Snapshot.PID < children[j].Snapshot.PID })
	}
	sort.Slice(tree.Roots, func(i, j int) bool { return tree.Roots[i].Snapshot.PID < tree.Roots[j].Snapshot.PID })
	return tree
}

// find returns the node for pid, or ok=false when the snapshot lacks it.
func (t *ProcessTree) Find(pid int) (*ProcessNode, bool) {
	node, ok := t.ByPID[pid]
	return node, ok
}

// descendants returns all pids below pid in depth-first order, sorted by pid
// within each sibling group.
func (t *ProcessTree) Descendants(pid int) []int {
	var out []int
	seen := map[int]bool{pid: true}
	stack := []int{pid}
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current != pid {
			out = append(out, current)
		}
		children := t.Children[current]
		for i := len(children) - 1; i >= 0; i-- {
			if !seen[children[i]] {
				seen[children[i]] = true
				stack = append(stack, children[i])
			}
		}
	}
	return out
}
