package collector

import (
	"testing"

	"deprehendo/internal/platform"
)

func sample(pid, ppid int) ProcessSnapshot {
	return ProcessSnapshot{Process: platform.Process{PID: pid, PPID: ppid, Name: "p", State: "S"}}
}

func TestBuildProcessTreeLinksChildren(t *testing.T) {
	snapshots := []ProcessSnapshot{
		sample(1, 0),
		sample(100, 1),
		sample(101, 100),
		sample(102, 101),
		sample(103, 100),
	}
	tree := BuildProcessTree(snapshots)
	if len(tree.Roots) != 1 || tree.Roots[0].Snapshot.PID != 1 {
		t.Fatalf("roots = %v, want only pid 1", len(tree.Roots))
	}
	node, ok := tree.Find(100)
	if !ok {
		t.Fatal("pid 100 missing from tree")
	}
	if len(node.Children) != 2 || node.Children[0].Snapshot.PID != 101 || node.Children[1].Snapshot.PID != 103 {
		t.Fatalf("pid 100 children = %+v, want 101 then 103", node.Children)
	}
	grandchild, ok := tree.Find(101)
	if !ok || len(grandchild.Children) != 1 || grandchild.Children[0].Snapshot.PID != 102 {
		t.Fatalf("pid 101 children wrong: %+v ok=%v", grandchild, ok)
	}
	if kids := tree.Children[100]; len(kids) != 2 || kids[0] != 101 || kids[1] != 103 {
		t.Fatalf("Children[100] = %v, want [101 103]", kids)
	}
}

func TestBuildProcessTreeHandlesMissingParents(t *testing.T) {
	// 20's parent 999 is not in the snapshot: reparented/orphaned view.
	tree := BuildProcessTree([]ProcessSnapshot{
		sample(1, 0),
		sample(20, 999),
	})
	if len(tree.Roots) != 2 {
		t.Fatalf("roots = %d, want 2 (pid 1 and pid 20 with missing parent)", len(tree.Roots))
	}
	if _, ok := tree.ByPID[999]; ok {
		t.Fatal("missing parent must not be fabricated into the tree")
	}
	// A self-reported parent is a root, not a cycle.
	selftree := BuildProcessTree([]ProcessSnapshot{sample(7, 7)})
	if len(selftree.Roots) != 1 || selftree.Roots[0].Snapshot.PID != 7 {
		t.Fatalf("self-parent node must be a root: %+v", selftree.Roots)
	}
}

func TestBuildProcessTreeDoesNotAssumePidOne(t *testing.T) {
	// no pid 1 at all: both nodes have parents outside the snapshot and are
	// roots. in container PID namespaces pid 1 often does not appear.
	tree := BuildProcessTree([]ProcessSnapshot{
		sample(50, 2),
		sample(60, 3),
	})
	if len(tree.Roots) != 2 {
		t.Fatalf("roots = %d, want 2", len(tree.Roots))
	}
}

func TestBuildProcessTreeCycleTolerated(t *testing.T) {
	tree := BuildProcessTree([]ProcessSnapshot{
		sample(5, 7),
		sample(7, 5),
	})
	if len(tree.Roots) != 0 {
		t.Fatalf("cycle roots should remain unlinked but not crash: %+v", tree.Roots)
	}
	if got := tree.Descendants(5); len(got) != 1 || got[0] != 7 {
		t.Fatalf("Descendants(5) = %v, want [7]", got)
	}
}

func TestProcessTreeDescendantsOrder(t *testing.T) {
	tree := BuildProcessTree([]ProcessSnapshot{
		sample(1, 0),
		sample(10, 1),
		sample(11, 10),
		sample(12, 10),
	})
	got := tree.Descendants(1)
	want := []int{10, 11, 12}
	if len(got) != len(want) {
		t.Fatalf("Descendants(1) = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Descendants(1) = %v, want %v", got, want)
		}
	}
	if got := tree.Descendants(404); len(got) != 0 {
		t.Fatalf("Descendants(404) = %v, want empty", got)
	}
}
