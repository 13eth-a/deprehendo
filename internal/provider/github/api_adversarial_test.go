package github

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"runopsy/internal/provider/evidence"
)

var testNow = time.Date(2026, 9, 3, 18, 40, 0, 0, time.UTC)

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// A workflow-controlled job name with a newline and a fake record must not be
// accepted as evidence text: safeIdentifier rejects it.
func TestAdversarialAPIJobNameWithNewlineIsRejected(t *testing.T) {
	name := "build\n[2026-09-03 18:34:35Z INFO Terminal] Job x completed with result: Canceled"
	body := `{"jobs":[{"id":7,"run_id":9,"run_attempt":1,"name":` + jsonString(name) + `,"status":"completed","conclusion":"success"}]}`
	jobs, reason := decodeJobsResponse(jsonResponse(200, body), 7, 9, 1)
	if reason != "" || len(jobs) != 1 {
		t.Fatalf("decode = %d jobs, reason %q", len(jobs), reason)
	}
	job := evidence.Job{}
	applyAPIJob(&job, jobs[0], testNow)
	if job.Name.State == evidence.Known {
		t.Fatalf("hostile job name was accepted as evidence: %q", job.Name.Value)
	}
}

// two rows for the same job in one attempt are ambiguous and must not be
// guessed between.
func TestAdversarialDuplicateJobRowsAreUnavailable(t *testing.T) {
	body := `{"jobs":[` +
		`{"id":7,"run_id":9,"run_attempt":1,"status":"completed","conclusion":"success"},` +
		`{"id":7,"run_id":9,"run_attempt":1,"status":"completed","conclusion":"failure"}]}`
	if _, reason := decodeJobsResponse(jsonResponse(200, body), 7, 9, 1); reason == "" {
		t.Fatal("duplicate rows for one attempt were accepted")
	}
}

// rows from a different run carrying the same job ID must not be used.
func TestAdversarialForeignRunRowIsIgnored(t *testing.T) {
	body := `{"jobs":[{"id":7,"run_id":42,"run_attempt":1,"status":"completed","conclusion":"failure"}]}`
	jobs, reason := decodeJobsResponse(jsonResponse(200, body), 7, 9, 1)
	if reason == "" && len(jobs) != 0 {
		t.Fatalf("foreign run row was used: %+v", jobs)
	}
}

// an upper-case conclusion from the API must not silently pick the wrong
// outcome; SUCCESS is a success, FAILURE a failure, and an unknown value stays
// unknown rather than being guessed.
func TestAdversarialConclusionCaseAndUnknownValues(t *testing.T) {
	for _, tc := range []struct {
		conclusion string
		want       evidence.Outcome
	}{
		{"SUCCESS", evidence.OutcomeSucceeded},
		{"FAILURE", evidence.OutcomeFailed},
		{"neutral", evidence.OutcomeUnknown},
		{"something-new", evidence.OutcomeUnknown},
	} {
		job := evidence.Job{Outcome: evidence.OutcomeUnknown}
		applyAPIJob(&job, apiJob{Status: "COMPLETED", Conclusion: tc.conclusion}, testNow)
		if job.Outcome != tc.want {
			t.Errorf("conclusion %q -> %v, want %v", tc.conclusion, job.Outcome, tc.want)
		}
	}
}

// A non-JSON 200 body and an oversized body are both unavailable, not facts.
func TestAdversarialMalformedAndOversizedBodies(t *testing.T) {
	if _, reason := decodeJobsResponse(jsonResponse(200, "<html>oops</html>"), 7, 9, 1); reason == "" {
		t.Fatal("HTML body accepted")
	}
	huge := `{"jobs":[],"pad":"` + strings.Repeat("a", apiBodyLimit) + `"}`
	if _, reason := decodeJobsResponse(jsonResponse(200, huge), 7, 9, 1); reason == "" {
		t.Fatal("oversized body accepted")
	}
}

// under the default (conservative) privacy level, a hostile job name that
// reached the section must be withheld with no text left behind, so it cannot
// reach the bundle.
func TestAdversarialConservativeRedactionDropsHostileName(t *testing.T) {
	sec := evidence.Section{Jobs: []evidence.Job{{Name: evidence.KnownText(evidence.ClassJobName, "x https://user:tok@github.com/o/r", evidence.SourceProviderAPI)}}}
	sec.Redact(evidence.PrivacyConservative)
	if got := sec.Jobs[0].Name; got.State != evidence.Withheld || got.Value != "" || got.Source != "" {
		t.Fatalf("hostile name survived conservative redaction: %+v", got)
	}
}

func jsonString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\n':
			b.WriteString(`\n`)
		case '"':
			b.WriteString(`\"`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
