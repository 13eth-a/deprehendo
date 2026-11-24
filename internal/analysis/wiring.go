package analysis

import (
	"fmt"
	"time"

	"deprehendo/internal/causal"
	"deprehendo/internal/diagnosis"
	"deprehendo/internal/incident"
	"deprehendo/internal/provider"
	"deprehendo/internal/provider/evidence"
)

// this file holds the orchestration that once lived in package main
// (contract docs/cloud/contract.md §3.2): how provider intent covers feed the
// causal graph and the diagnosis engine. it must exist exactly once, because
// the CLI, the timeline renderer and the phase 7 analyzer worker all run it.
// the "one deprehendo" rule (7.9).

// jobSucceededLead is how far before a stated SUCCEEDED completion line the
// cover starts. the runner writes that line only after the worker has exited,
// so the worker's departure can precede the line by many seconds; a 1 s lead
// would leave a normal exit uncovered and raise PROCESS_GROUP_TERMINATION.
const jobSucceededLead = 2 * time.Minute

// intentCoversRole decides which roles of the named runner an intent covers.
//
// A runner-scoped intent covers the runner's whole tree, not just the
// supervisor: stopping, updating or completing an ephemeral runner takes its
// worker and job tree down with it, and the runner states that (S6 passes
// with a worker running, S9 exits after a job). covering only the supervisor
// left the worker and job exits uncovered and produced
// PROCESS_GROUP_TERMINATION for a plain runner self-update on the real runner
// (B3, 2026-11-02).
func intentCoversRole(intent provider.Intent, role evidence.Role) bool {
	switch intent {
	case provider.IntentCancelled, provider.IntentTimedOut, provider.IntentJobSucceeded:
		return role == evidence.RoleWorker || role == evidence.RoleJobRoot || role == evidence.RoleJobProcess
	case provider.IntentServiceShutdown, provider.IntentUpdate, provider.IntentEphemeralComplete:
		return role == evidence.RoleSupervisor || role == evidence.RoleWorker || role == evidence.RoleJobRoot || role == evidence.RoleJobProcess
	}
	return false
}

// intentEndsRunnerTree reports whether the intent states that the runner itself
// stopped, so its whole tree ended with it.
func intentEndsRunnerTree(intent provider.Intent) bool {
	switch intent {
	case provider.IntentServiceShutdown, provider.IntentUpdate, provider.IntentEphemeralComplete:
		return true
	}
	return false
}

// intentEndsJobTree reports whether the intent states the end of one job's own
// tree: cancellation, timeout, or a stated success. the diagnosis engine
// widens the cover to the job's observed descendants, because the runner
// SIGKILLs leftover job processes when the job ends (real-runner run
// 41950041166: a SUCCEEDED job's leftovers were reported as a group kill).
func intentEndsJobTree(intent provider.Intent) bool {
	switch intent {
	case provider.IntentCancelled, provider.IntentTimedOut, provider.IntentJobSucceeded:
		return true
	}
	return false
}

// contradictedIntent reports whether the section records a TERMINATION_INTENT
// conflict (T4): the intent then cannot be trusted to cover a death, so its
// exits keep normal failure semantics. conservative: it only removes covers.
func contradictedIntent(section evidence.Section) bool {
	for _, c := range section.Conflicts {
		if c.Question == "TERMINATION_INTENT" {
			return true
		}
	}
	return false
}

// intentCovers turns each provider TERMINATION_INTENDED event into a neutral
// cover (5.25, T2). the window runs from the intent's lead to its grace end.
// the covered set follows §10A.5: the process the provider named, plus, when
// the intent names a runner, that runner's roles resolved through
// ProcessRoles. an intent with neither a process nor a runner covers nothing.
func IntentCovers(interps []provider.Interpretation) []causal.IntentCover {
	var out []causal.IntentCover
	for _, in := range interps {
		if contradictedIntent(in.Section) {
			continue
		}
		for _, ge := range in.Generic {
			if ge.Kind != provider.GenericTerminationIntended {
				continue
			}
			named := ge.Process != nil && ge.Process.PID != 0
			if !named && ge.Runner == "" {
				continue
			}
			grace := 60 * time.Second
			if ge.Intent == provider.IntentCancelled || ge.Intent == provider.IntentTimedOut {
				grace = 30 * time.Second
			}
			lead := time.Second
			if ge.Intent == provider.IntentJobSucceeded {
				lead = jobSucceededLead
			}
			out = append(out, causal.IntentCover{
				Processes:  coveredProcesses(in.Section, ge),
				From:       ge.Timestamp.Add(-lead),
				Until:      ge.Timestamp.Add(grace),
				RunnerTree: intentEndsRunnerTree(ge.Intent),
				JobTree:    intentEndsJobTree(ge.Intent),
			})
		}
	}
	return out
}

// coveredProcesses resolves the §10A.5 covered set for one intent. A
// CANCELLED or TIMED_OUT intent covers the runner's worker and job tree; the
// other intents cover the runner's supervisor. when the intent names a worker,
// worker and job roles are limited to that worker.
func coveredProcesses(section evidence.Section, ge provider.GenericEvent) []causal.ProcessIdentity {
	var out []causal.ProcessIdentity
	if ge.Process != nil && ge.Process.PID != 0 {
		out = append(out, causal.ProcessIdentity{PID: ge.Process.PID, StartTicks: ge.Process.StartTicks})
	}
	if ge.Runner == "" {
		return out
	}
	for _, pr := range section.ProcessRoles {
		if pr.Runner != ge.Runner || !intentCoversRole(ge.Intent, pr.Role) {
			continue
		}
		if pr.Role != evidence.RoleSupervisor && ge.Worker != "" && pr.Worker != ge.Worker {
			continue
		}
		out = append(out, causal.ProcessIdentity{PID: pr.Process.PID, StartTicks: pr.Process.StartTicks})
	}
	return out
}

// DiagnosisCovers converts causal intent covers to the diagnosis engine's
// type, so both engines see the same stated intents.
func DiagnosisCovers(covers []causal.IntentCover) []diagnosis.IntentCover {
	out := make([]diagnosis.IntentCover, 0, len(covers))
	for _, c := range covers {
		procs := make([]diagnosis.ProcessIdentity, 0, len(c.Processes))
		for _, p := range c.Processes {
			procs = append(procs, diagnosis.ProcessIdentity{PID: p.PID, StartTicks: p.StartTicks})
		}
		out = append(out, diagnosis.IntentCover{Processes: procs, From: c.From, Until: c.Until, RunnerTree: c.RunnerTree, JobTree: c.JobTree})
	}
	return out
}

// BuildCausalGraph builds the causal graph with provider intent covers
// applied and runs the rule engine over it.
func BuildCausalGraph(inc *incident.Incident) (*causal.Timeline, *causal.Graph, error) {
	if inc == nil {
		return nil, nil, fmt.Errorf("nil incident")
	}
	timeline := causal.BuildTimeline(inc)
	graph := causal.NewGraph(timeline)
	graph.SetIntentCovers(IntentCovers(provider.Default.InterpretAll(inc.Providers, inc)))
	engine := causal.NewEngine(causal.Rules(), timeline.Origin)
	if _, err := engine.Apply(graph, nil); err != nil {
		return nil, nil, fmt.Errorf("causal analysis: %w", err)
	}
	if err := graph.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid graph: %w", err)
	}
	return timeline, graph, nil
}

// DiagnosisOptions builds diagnosis options with the same provider intent
// covers the causal graph uses, so the group-kill signature sees the same intents.
func DiagnosisOptions(inc *incident.Incident, minConfidence float64, disabled []diagnosis.SignatureID) diagnosis.Options {
	covers := IntentCovers(provider.Default.InterpretAll(inc.Providers, inc))
	return diagnosis.Options{MinConfidence: minConfidence, Disable: disabled, Covers: DiagnosisCovers(covers)}
}

// LinkDiagnoses attaches the causal event IDs a signature's evidence overlaps
// to the report's matches and rejections (4.16).
func LinkDiagnoses(report *diagnosis.Report, tl *causal.Timeline) {
	if report == nil || tl == nil {
		return
	}
	for _, matches := range [][]diagnosis.SignatureMatch{report.Matches, report.Rejections} {
		for i := range matches {
			match := &matches[i]
			var identities []causal.ProcessIdentity
			for _, identity := range match.ProcessIdentities {
				identities = append(identities, causal.ProcessIdentity{PID: identity.PID, StartTicks: identity.StartTicks})
			}
			ids := causal.RelatedEventIDs(tl, string(match.SignatureID), identities)
			for _, id := range ids {
				match.RelatedEvents = append(match.RelatedEvents, string(id))
			}
		}
	}
}
