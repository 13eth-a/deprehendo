package collector

import "sync"

// ring is a fixed-capacity ring buffer. appends are O(1), memory use is
// bounded by capacity, items returns a copy in chronological order
// (oldest first), and all access is mutex-guarded for concurrent readers
// while the recorder appends.
type Ring[T any] struct {
	mu       sync.RWMutex
	items    []T
	head     int // index of the oldest element
	size     int
	capacity int
}

// NewRing creates an empty ring. panics on non-positive capacity: the caller
// validates its configured window/interval before this point.
func NewRing[T any](capacity int) *Ring[T] {
	if capacity <= 0 {
		panic("collector: ring capacity must be positive")
	}
	return &Ring[T]{items: make([]T, capacity), capacity: capacity}
}

// capacity reports the configured bound.
func (r *Ring[T]) Capacity() int {
	return r.capacity
}

// len reports how many items are currently retained.
func (r *Ring[T]) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.size
}

// add stores one item, overwriting the oldest when full.
func (r *Ring[T]) Add(item T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// before wraparound head stays 0 and appends go to position size.
	// when full the append position wraps to the oldest slot, which head
	// then advances past.
	r.items[(r.head+r.size)%r.capacity] = item
	if r.size < r.capacity {
		r.size++
	} else {
		r.head = (r.head + 1) % r.capacity
	}
}

// items returns the retained items oldest-first. the result is a fresh slice;
// mutating its elements does not replace ring entries; reference-valued fields
// still share their underlying data. scheduler handles snapshot deep copies.
func (r *Ring[T]) Items() []T {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]T, r.size)
	for i := 0; i < r.size; i++ {
		out[i] = r.items[(r.head+i)%r.capacity]
	}
	return out
}

// evictWhile removes oldest entries and clears references to their payloads.
func (r *Ring[T]) evictWhile(remove func(T) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for r.size > 0 && remove(r.items[r.head]) {
		var zero T
		r.items[r.head] = zero
		r.head = (r.head + 1) % r.capacity
		r.size--
	}
}

func (r *Ring[T]) latest() (T, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.size == 0 {
		var zero T
		return zero, false
	}
	return r.items[(r.head+r.size-1)%r.capacity], true
}
