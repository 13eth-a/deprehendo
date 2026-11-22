package diagnosis

import "time"

// temporal reasoning helpers. all comparisons are safe against the zero
// time: an unset timestamp is never "before", "after", or "within" anything.

// within reports whether a and b are at most duration apart. an unset
// timestamp never counts as within.
func Within(a, b time.Time, duration time.Duration) bool {
	if duration < 0 || a.IsZero() || b.IsZero() {
		return false
	}
	if a.Before(b) {
		a, b = b, a
	}
	return !a.After(b.Add(duration))
}

// before reports whether a happened strictly before b, with unset timestamps
// reported false.
func Before(a, b time.Time) bool {
	return !a.IsZero() && !b.IsZero() && a.Before(b)
}

// after reports whether a happened strictly after b, with unset timestamps
// reported false.
func After(a, b time.Time) bool {
	return !a.IsZero() && !b.IsZero() && a.After(b)
}

// DurationAbove reports whether span meets min; zero and negative spans are
// always false.
func DurationAbove(span time.Duration, min time.Duration) bool {
	return span > 0 && span >= min && min >= 0
}
