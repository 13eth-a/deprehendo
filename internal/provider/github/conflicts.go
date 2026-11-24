// conflicts (5.48, architecture.md §8). sources disagree with each other: a
// log says one thing, the process table another. A conflict is recorded
// with both claims and the section never resolves it silently. the caller
// (review, signatures) decides. P-topics here surface contradiction instead
// of picking a winner.
package github

import (
	"sort"
	"time"

	"deprehendo/internal/provider/evidence"
)

// detectConflicts evaluates stored state for contradictions once, at
// Freeze. deterministic order; bounded count (MaxConflicts).
func (s *session) detectConflicts() {
	s.jobStateConflicts()
	s.terminationConflicts()
	sortConflicts(s.conflicts)
}

// jobStateConflicts (JOB_STATE): runner records for one worker's job state
// two different results (say, a stated cancellation and a "succeeded"
// result), or a result followed by fresh running evidence. A worker exit is
// not a job-state claim: a job that is cancelled and whose worker then exits
// is a sequence, not a disagreement (audit R16: EXITED used to be a claim
// here, which both invented conflicts and, being outside the claim
// vocabulary, invalidated the whole section).
func (s *session) jobStateConflicts() {
	for _, ref := range sortedWorkerStates(s.workers) {
		worker := s.workers[ref]
		var claims []evidence.Claim
		for _, ev := range s.events {
			if ev.Worker != worker.ref {
				continue
			}
			switch ev.Type {
			case EventJobCompleted:
				claims = append(claims, claim(evidence.SourceRunnerLog, "COMPLETED", ev.Timestamp))
			case EventJobCancellation:
				claims = append(claims, claim(evidence.SourceRunnerLog, "CANCELLED", ev.Timestamp))
			case EventJobTimeout:
				claims = append(claims, claim(evidence.SourceRunnerLog, "TIMED_OUT", ev.Timestamp))
			case EventJobAccepted:
				claims = append(claims, claim(evidence.SourceRunnerLog, "RUNNING", ev.Timestamp))
			}
		}
		s.recordStateConflict(ConflictTopicJobState, worker, claims)
	}
}

// terminationConflicts (TERMINATION_INTENT, §7 T4): an intent record that
// arrives after the worker was already gone does not explain that death.
// the death may have caused the cancellation. the intent covers exits from
// one sample tolerance before its record onwards (T2); a worker of the same
// runner that exited earlier than that, within intentLookback, is recorded
// as a conflict between the process fact and the stated intent.
func (s *session) terminationConflicts() {
	for _, ev := range s.events {
		if ev.Type != EventJobCancellation && ev.Type != EventJobTimeout {
			continue
		}
		var died *workerState
		for _, ref := range sortedWorkerStates(s.workers) {
			worker := s.workers[ref]
			if worker.runner != ev.Runner || !worker.exited {
				continue
			}
			if ev.Worker != "" && worker.ref != ev.Worker {
				continue
			}
			gap := ev.Timestamp.Sub(worker.exitedAt)
			if gap <= jobBindingTolerance || gap > intentLookback {
				continue
			}
			if died == nil || worker.exitedAt.After(died.exitedAt) {
				died = worker
			}
		}
		if died == nil || len(s.conflicts) >= maxConflicts {
			continue
		}
		value := "CANCELLED"
		if ev.Type == EventJobTimeout {
			value = "TIMED_OUT"
		}
		s.conflicts = append(s.conflicts, evidence.Conflict{
			Question: ConflictTopicTermination, Runner: died.runner, Job: died.job,
			Claims: []evidence.Claim{
				claim(evidence.SourceLocalProcess, "EXITED", died.exitedAt),
				claim(evidence.SourceRunnerLog, value, ev.Timestamp),
			},
		})
	}
}

// intentLookback bounds how far before an intent record a worker death is
// still compared with it (the T2 shutdown grace).
const intentLookback = 60 * time.Second

// recordStateConflict appends the disagreement when the claims contradict
// each other, never when they merely chain (RUNNING then CANCELLED
// is a sequence, not a conflict).
func (s *session) recordStateConflict(topic string, worker *workerState, claims []evidence.Claim) {
	if len(claims) < 2 || !contradicted(claims) {
		return
	}
	if len(s.conflicts) >= maxConflicts {
		return
	}
	sort.Slice(claims, func(i, j int) bool { return claims[i].ObservedAt.Before(claims[j].ObservedAt) })
	s.conflicts = append(s.conflicts, evidence.Conflict{
		Question: topic, Runner: worker.runner, Job: worker.job, Claims: claims,
	})
}

// maxConflicts mirrors the section bound without reaching into evidence.
const maxConflicts = 1024 // evidence.MaxConflicts, kept in local sync

func claim(src evidence.Source, value string, at time.Time) evidence.Claim {
	return evidence.Claim{Source: src, Value: value, ObservedAt: at}
}

// contradicted: the claims disagree about the same question. two distinct
// stated results, or a result followed by running evidence. the same result
// stated twice (a cancellation message, then a "canceled" result line) is
// agreement, not a conflict.
func contradicted(claims []evidence.Claim) bool {
	terminal := map[string]time.Time{}
	for _, c := range claims {
		switch c.Value {
		case "CANCELLED", "TIMED_OUT", "COMPLETED":
			if first, ok := terminal[c.Value]; !ok || c.ObservedAt.Before(first) {
				terminal[c.Value] = c.ObservedAt
			}
		}
	}
	if len(terminal) > 1 {
		return true
	}
	for _, running := range claims {
		if running.Value != "RUNNING" {
			continue
		}
		for _, at := range terminal {
			if running.ObservedAt.After(at) {
				return true
			}
		}
	}
	return false
}

func sortConflicts(in []evidence.Conflict) {
	sort.Slice(in, func(i, j int) bool {
		if in[i].Question != in[j].Question {
			return in[i].Question < in[j].Question
		}
		if in[i].Runner != in[j].Runner {
			return in[i].Runner < in[j].Runner
		}
		return in[i].Job < in[j].Job
	})
}
