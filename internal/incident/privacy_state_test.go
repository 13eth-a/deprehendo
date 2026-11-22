package incident

import "testing"

// macOS ps reports states with flags ("T<", "ss"); the bundle keeps the state
// letter so stopped and zombie evidence survives redaction on macOS, and still
// lets no free text through.
func TestCleanStateKeepsLeadingStateLetter(t *testing.T) {
	cases := map[string]string{
		// linux: single letters pass unchanged.
		"R": "R", "S": "S", "D": "D", "Z": "Z", "T": "T", "t": "t", "I": "I",
		// macOS: flags are dropped, the letter is kept.
		"T<": "T", "S<": "S", "R<": "R", "Ss": "S", "S+": "S", "Z+": "Z", "U": "U", "I<": "I",
		// anything outside the alphabet, and free text, collapses to "?".
		"": "?", "?": "?", "Q": "?", "é": "?", " T": "?", "secret": "?",
		// A valid letter followed by text keeps only the letter.
		"Tsecret=hunter2": "T",
	}
	for in, want := range cases {
		if got := cleanState(in); got != want {
			t.Errorf("cleanState(%q) = %q, want %q", in, got, want)
		}
		// reapplying the policy must not change the result (bundle verification).
		if again := cleanState(cleanState(in)); again != want {
			t.Errorf("cleanState is not idempotent for %q: %q", in, again)
		}
	}
}
