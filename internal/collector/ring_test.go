package collector

import (
	"sync"
	"testing"
)

func TestRingRetainsCapacityAndWrapsAround(t *testing.T) {
	ring := NewRing[int](3)
	for _, v := range []int{1, 2, 3} {
		ring.Add(v)
	}
	items := ring.Items()
	if len(items) != 3 || items[0] != 1 || items[1] != 2 || items[2] != 3 {
		t.Fatalf("pre-wraparound items = %v, want [1 2 3]", items)
	}
	ring.Add(4) // overwrites slot 0, head moves to 1
	items = ring.Items()
	if len(items) != 3 || items[0] != 2 || items[1] != 3 || items[2] != 4 {
		t.Fatalf("post-wraparound items = %v, want [2 3 4]", items)
	}
	ring.Add(5) // overwrites slot 1, head moves to 2
	items = ring.Items()
	if len(items) != 3 || items[0] != 3 || items[1] != 4 || items[2] != 5 {
		t.Fatalf("second wraparound items = %v, want [3 4 5]", items)
	}
	if ring.Len() != 3 || ring.Capacity() != 3 {
		t.Fatalf("len/capacity = %d/%d, want 3/3", ring.Len(), ring.Capacity())
	}
}

func TestRingItemsReturnsCopy(t *testing.T) {
	ring := NewRing[int](2)
	ring.Add(1)
	ring.Add(2)
	items := ring.Items()
	items[0] = 99
	if got := ring.Items()[0]; got != 1 {
		t.Fatalf("mutating Items() changed ring contents: %d", got)
	}
}

func TestRingConcurrentAccess(t *testing.T) {
	const capacity = 8
	ring := NewRing[int](capacity)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				ring.Add(j)
				_ = ring.Items()
				_ = ring.Len()
			}
			_ = base
		}(i)
	}
	wg.Wait()
	if ring.Len() != capacity {
		t.Fatalf("len = %d, want capacity %d", ring.Len(), capacity)
	}
}

func TestNewRingRejectsNonPositiveCapacity(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewRing(0) did not panic")
		}
	}()
	NewRing[int](0)
}
