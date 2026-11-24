// the offline github half: translate a stored section into neutral generic
// events for the causal engine (5.8). rules: pure function, no I/O, no
// clock; the same section always yields the same translation. provider
// events without a generic concept stay in the section and are invisible to
// the generic stream. they can still be cited as provider-specific
// evidence, but never strengthen a causal rule that is not written for them.
package github

import (
	"time"

	"deprehendo/internal/incident"
	"deprehendo/internal/provider"
	"deprehendo/internal/provider/evidence"
)

// genericByEvent maps each registered provider event to its neutral kind.
// events absent here (GITHUB_RUNNER_DISCONNECTED/_RECONNECTED,
// GITHUB_RUNNER_UPDATE as an event) have no neutral counterpart yet; a
// signature needing them is written against the provider vocabulary.
var genericByEvent = map[string]struct {
	kind   provider.GenericKind
	intent provider.Intent
}{
	EventRunnerStarted:      {kind: provider.GenericRunnerStarted},
	EventRunnerStopped:      {kind: provider.GenericRunnerStopped},
	EventJobAssigned:        {kind: provider.GenericWorkAssigned},
	EventJobAccepted:        {kind: provider.GenericWorkAssigned},
	EventWorkerStarted:      {kind: provider.GenericWorkerStarted},
	EventWorkerExited:       {kind: provider.GenericWorkerExited},
	EventJobProgressStopped: {kind: provider.GenericWorkerProgressStopped},
	// GITHUB_COMMUNICATION_STALLED deliberately has no generic kind: the
	// runner's control channel stalling is not the job's work stalling, and
	// the two stall labels must never share a translation (§10A S1; audit R8).

	// intended terminations (5.44–5.46). the intent comes from the
	// evidence-checked record, never from the termination itself.
	EventJobCancellation: {kind: provider.GenericTerminationIntended, intent: provider.IntentCancelled},
	EventJobTimeout:      {kind: provider.GenericTerminationIntended, intent: provider.IntentTimedOut},
	EventShutdownStop:    {kind: provider.GenericTerminationIntended, intent: provider.IntentServiceShutdown},
	EventRunnerUpdate:    {kind: provider.GenericTerminationIntended, intent: provider.IntentUpdate},

	EventRunnerEphemeralComplete: {kind: provider.GenericTerminationIntended, intent: provider.IntentEphemeralComplete},
}

// interpret runs on stored bundles. the signatures are judged at the incident's
// capture end, so the same bundle always yields the same findings.
func interpret(section evidence.Section, inc *incident.Incident) (provider.Interpretation, error) {
	out := provider.Interpretation{Provider: Name, Section: section}
	if inc != nil {
		out.Signatures = signatureOutcomes(section, inc.CaptureEnd)
	}
	for _, ev := range section.Events {
		got, ok := genericByEvent[ev.Type]
		if ev.Type == EventJobCompleted {
			// only a stated SUCCEEDED result intends its worker's exit. A failed
			// or unstated completion keeps normal failure semantics.
			got.kind, got.intent = provider.GenericTerminationIntended, provider.IntentJobSucceeded
			ok = ev.Outcome == evidence.OutcomeSucceeded
		}
		if !ok {
			continue
		}
		ge := provider.GenericEvent{
			Timestamp:    ev.Timestamp,
			Kind:         got.kind,
			Intent:       got.intent,
			Runner:       ev.Runner,
			Worker:       ev.Worker,
			Job:          ev.Job,
			Source:       ev.Source,
			ProviderType: ev.Type,
		}
		if ev.Process != nil {
			proc := *ev.Process
			ge.Process = &proc
		}
		ge.Confidence = confidenceFor(ev.Source)
		out.Generic = append(out.Generic, ge)
	}
	return out, nil
}

// signatureOutcomes runs the offline signatures over the stored section and
// returns them in the neutral provider form.
func signatureOutcomes(section evidence.Section, windowEnd time.Time) []provider.Signature {
	var out []provider.Signature
	findings := append(AssignmentStall(section, windowEnd), FinalizationStall(section, windowEnd)...)
	findings = append(findings, CommunicationStall(section, windowEnd)...)
	findings = append(findings, SelfTermination(section)...)
	findings = append(findings, OrphanedJob(section)...)
	for _, f := range findings {
		out = append(out, provider.Signature{
			Label:      f.Label,
			Confidence: f.Confidence,
			Runner:     f.Runner,
			Job:        f.Job,
			Onset:      f.Onset,
			Evidence:   f.Evidence,
		})
	}
	return out
}

// confidenceFor: log-derived facts are order evidence at ≥ 1 s resolution
// (C7) and travel at MEDIUM; direct process observations at HIGH.
func confidenceFor(src evidence.Source) evidence.Confidence {
	switch src {
	case evidence.SourceLocalProcess, evidence.SourceLocalSocket:
		return evidence.ConfidenceHigh
	case evidence.SourceUserOverride:
		return evidence.ConfidenceMedium
	case evidence.SourceRunnerLog:
		return evidence.ConfidenceMedium
	default:
		return evidence.ConfidenceLow
	}
}
