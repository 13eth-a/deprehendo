package causal

import (
	"fmt"
	"sort"
	"strconv"
	"time"

	"runopsy/internal/collector"
	"runopsy/internal/incident"
	"runopsy/internal/platform"
)

// extraction thresholds. every derived event names its versioned rule and
// operates on the shared percentage scale (PSI avg10 is percent of stalled
// wall time, memory/disk are percent of capacity). hysteresis keeps a value
// oscillating at a boundary from emitting episode noise.
const (
	memoryPressurePercent  = 90.0
	memoryLimitPercent     = 98.0
	memoryHysteresis       = 5.0
	cgroupLimitFraction    = 0.98
	cgroupHysteresis       = 0.05
	cpuSaturatedPercent    = 85.0
	cpuSaturatedBelow      = 75.0
	cpuSustainMinimum      = 10 * time.Second
	diskPressurePercent    = 15.0
	diskExhaustedPercent   = 5.0
	diskRecoverPercent     = 30.0
	diskPressureIOPercent  = 20.0
	diskIOSustain          = 10 * time.Second
	groupCoordinatedWindow = 5 * time.Second
	clockJumpThreshold     = 30 * time.Second
)

// timeline is the normalized event stream for one bundle (4.3/4.19). origin
// is the zero of the relative timeline.
type Timeline struct {
	Events []Event
	Origin time.Time
}

// BuildTimeline converts one decoded bundle into normalized events. it never
// mutates the incident or assumes facts the bundle does not contain:
//
//   - recorded bundle events are authoritative for process lifecycle and
//     sockets (the differ already refuses to fabricate first sightings), and
//     carry their own timestamps, so array order cannot change them (4.38);
//   - snapshots are processed in capture order (recorder bundle order, or an
//     explicit CaptureIndex), never re-sorted by wall time: a clock step is
//     detected from consecutive capture-order pairs BEFORE any ordering
//     (audit A7). A backward step emits CLOCK_DISCONTINUITY, a forward hole
//     emits TIMELINE_GAP; the two are different facts. samples inside a
//     backward step are analyzed co-instant with the last trusted sample
//     until the wall clock passes the trusted reference again. v1 has no
//     monotonic offsets yet, and re-sorting by wall time would fabricate
//     history;
//   - resource episodes emit once per episode with hysteresis, emit explicit
//     recovery events, mark conditions already in effect at their first
//     available observation as ACTIVE with OnsetUnknown (4.28), keep
//     boundary facts when one sample crosses several thresholds at once
//     (same-instant ESCALATES_TO pair), and never claim recovery across a
//     sensor gap, a timeline gap, or a clock step;
//   - process state/reparent changes come only from pairs of samples with an
//     available process section; sensor gaps break episodes instead of
//     bridging them;
//   - OOM_EVENT is derived only when the bundle's cgroup snapshots carry
//     the kernel's memory.events oom_kill counter (§3.2); it is never
//     fabricated. network progress and runner/worker roles remain
//     unobservable in v1 and are never fabricated.
func BuildTimeline(i *incident.Incident) *Timeline {
	events := make([]Event, 0, 64)

	// recorded events carry their own timestamps: array order is not
	// evidence here (4.38). stable sort keeps bundle order at equal times,
	// and the original index travels in provenance.
	eventorder := make([]int, len(i.Events))
	for index := range eventorder {
		eventorder[index] = index
	}
	sort.SliceStable(eventorder, func(a, b int) bool {
		return i.Events[eventorder[a]].Timestamp.Before(i.Events[eventorder[b]].Timestamp)
	})
	snapshotorder := captureOrder(i)

	// Last-known cgroup per pid, in capture order: the exit event's victim
	// identity for the sampled-counter OOM rule (§3.2). A process that is
	// never in a recorded cgroup stays absent, and the check then answers
	// UNKNOWN.
	cgroupbypid := map[int]string{}
	for _, si := range snapshotorder {
		for pi := range i.Snapshots[si].Processes {
			c := i.Snapshots[si].Processes[pi].Cgroup
			if c != nil && c.Path != "" {
				cgroupbypid[i.Snapshots[si].Processes[pi].PID] = c.Path
			}
		}
	}

	for _, index := range eventorder {
		e := &i.Events[index]
		var eventType EventType
		subject := SubjectRef{SubjectHost, "local"}
		switch e.Type {
		case incident.ProcessStarted:
			eventType, subject = EventProcessStarted, processSubject(e.PID, e.StartTicks)
		case incident.ProcessExited:
			eventType, subject = EventProcessExited, processSubject(e.PID, e.StartTicks)
		case incident.TraceProcessExec:
			eventType, subject = EventProcessStarted, processSubject(e.PID, e.StartTicks)
		case incident.TraceProcessExit:
			eventType, subject = EventProcessExited, processSubject(e.PID, e.StartTicks)
		case incident.TraceProcessStopped:
			eventType, subject = EventProcessStopped, processSubject(e.PID, e.StartTicks)
		case incident.TraceProcessResumed:
			eventType, subject = EventProcessResumed, processSubject(e.PID, e.StartTicks)
		case incident.ConnectionOpened:
			eventType, subject = EventConnectionOpened, socketSubject(e.Connection)
		case incident.ConnectionClosed:
			eventType, subject = EventConnectionClosed, socketSubject(e.Connection)
		case incident.TraceSignalSent:
			// §3.4 "Y sent S": a single-target send is keyed by the
			// target's exact identity; a group send (PID 0) is keyed by
			// the addressed group, and the rule binds it to a member exit
			// through that member's PGID.
			eventType = EventSignalSent
			switch {
			case e.PID > 0:
				subject = processSubject(e.PID, e.StartTicks)
			case e.TargetPGID > 0:
				subject = groupSubject(e.TargetPGID)
			}
		case incident.TraceOomKill:
			// the tracer's oom:mark_victim record names the victim, which is
			// exactly the discriminator OOM_CAUSES_PROCESS_EXIT needs; the
			// sampled cgroup counter path stays CGROUP_OOM_KILLS_MEMBER.
			eventType, subject = EventOOM, processSubject(e.PID, e.StartTicks)
		default:
			// events with no causal consumer stay bundle-viewport only.
			continue
		}
		data := processEventData(i.Metadata.Processes, e)
		if e.Type == incident.TraceSignalSent {
			data = map[string]any{"signal": e.Signal, "signal_fact": e.SignalFact}
			if e.SenderPID > 0 {
				data["sender_pid"] = e.SenderPID
			}
			if e.TargetPGID > 0 {
				data["target_pgid"] = e.TargetPGID
			}
		}
		if e.Type == incident.TraceOomKill {
			// the marker the OOM discriminator reads: this is a kernel
			// record that names the victim, not a cgroup counter rise.
			data = map[string]any{"record": "oom_mark_victim"}
		}
		if e.Type == incident.ProcessExited || e.Type == incident.TraceProcessExit {
			// the exit's own signal fact and number: EXIT_MATCHES_SIGNAL
			// pairs them with the send that named the same signal.
			if e.Signal > 0 {
				data = ensureData(data)
				data["signal"] = e.Signal
			}
			if e.SignalFact != "" {
				data = ensureData(data)
				data["signal_fact"] = e.SignalFact
			}
			// the victim's cgroup identity in its own recorded data: the
			// sampled-counter OOM rule (§3.2) reads it from there.
			if cg := lastKnownCgroupPath(cgroupbypid, e.PID); cg != "" {
				data = ensureData(data)
				data["cgroup"] = cg
			}
		}
		events = append(events, Event{
			Type:       eventType,
			Timestamp:  e.Timestamp,
			Subject:    subject,
			Data:       data,
			PID:        e.PID,
			StartTicks: processEventStartTicks(e),
			// typed PGID (re-audit R8): failureAnchors folds member exits
			// into their group anchor by e.PGID; it was only in data, so
			// every member exit stayed a separate primary failure.
			PGID:       typedPGID(i.Metadata.Processes, e),
			Provenance: EventProvenance{Sources: []ProvenanceSource{provenance("event", strconv.Itoa(index))}},
		})
	}

	if !i.TriggeredAt.IsZero() {
		events = append(events, Event{
			Type:      EventIncidentTriggered,
			Timestamp: i.TriggeredAt,
			Subject:   SubjectRef{SubjectHost, "local"},
			Data:      map[string]any{"trigger": i.Trigger.Type},
			// the trigger's process identity, when it names one, makes that
			// process's exit a failure anchor (R13).
			PID:        i.Trigger.PID,
			StartTicks: i.Trigger.StartTicks,
			Provenance: EventProvenance{Sources: []ProvenanceSource{provenance("trigger", "incident")}},
		})
	}

	pgidof := map[int]int{}
	for _, m := range i.Metadata.Processes {
		pgidof[m.PID] = m.PGID
	}

	mem := memoryMachine{}
	disk := diskMachine{}
	diskio := ioPressureMachine{}
	network := networkMachine{}
	// oomKills remembers each cgroup's last observed cumulative oom_kill
	// counter and the wall time of that observation; an increase between
	// consecutive samples in capture order is a kernel OOM kill of one of
	// its members (§3.2's sampled evidence), and the remembered time is
	// the open of the interval in which that kill is certain to lie.
	oomKills := map[string]oomKillBaseline{}
	cpuepisodes := map[string]*cpuEpisode{}
	cgroupepisodes := map[string]*crossingEpisode{}
	// severeSamples counts, per episode, the samples observed at the severe
	// level (limit / exhaustion). A severe condition becomes a failure anchor
	// only when it persisted for more than one sample (4.27, re-audit R12).
	severesamples := map[string]int{}
	processstates := map[string]string{}
	processppid := map[string]int{}
	processfirstseen := map[string]time.Time{}
	// trusted is the last wall reading that is trustworthy for chronological
	// placement; lastWall is the previous processed reading (diagnostics).
	trusted := time.Time{}
	lastwall := time.Time{}
	previoussnapshot := -1

	for _, si := range snapshotorder {
		s := &i.Snapshots[si]
		wall := s.Timestamp
		if wall.IsZero() {
			continue
		}
		// at is the analysis timestamp derivations may use for this sample:
		// the wall clock when it is trustworthy, otherwise co-instant with
		// the last trusted sample (E1′: order inside the sampling instant is
		// not observed).
		at := wall
		displaced := false
		if !trusted.IsZero() {
			offset := wall.Sub(lastwall)
			switch {
			case wall.Before(trusted):
				// backward clock step: the recorded wall time moved
				// backwards. Type-sorted processing would first REPAIR the
				// sample and then claim the history it fabricated; capture
				// order detects the step instead (A7).
				displaced = true
				at = trusted
				events = append(events, Event{
					Type:      EventClockDiscontinuity,
					Timestamp: wall,
					Subject:   SubjectRef{SubjectHost, "local"},
					Data: map[string]any{
						"previous_wall": lastwall.Format(time.RFC3339Nano),
						"stepped_wall":  wall.Format(time.RFC3339Nano),
						"offset_ms":     offset.Milliseconds(),
						"backward":      true,
					},
					Provenance: EventProvenance{
						RuleID: RuleClockDiscontinuity,
						Sources: []ProvenanceSource{
							provenance("snapshot", strconv.Itoa(previoussnapshot)),
							provenance("snapshot", strconv.Itoa(si)),
						},
					},
				})
				// episodes cannot bridge the step: a recovery read after a
				// displaced sample cannot claim continuity (P4).
				mem.breakContinuity()
				disk.breakContinuity()
				diskio.breakContinuity()
				network.breakContinuity()
				for id := range cpuepisodes {
					cpuepisodes[id] = nil
				}
			case wall.Sub(trusted) > clockJumpThreshold:
				// forward hole: a sampling gap, not a clock error. it is
				// a different fact from a clock step and gets its own event.
				events = append(events, Event{
					Type:      EventTimelineGap,
					Timestamp: wall,
					Subject:   SubjectRef{SubjectHost, "local"},
					Data: map[string]any{
						"previous_wall": lastwall.Format(time.RFC3339Nano),
						"gap_ms":        wall.Sub(lastwall).Milliseconds(),
					},
					Provenance: EventProvenance{
						RuleID: RuleTimelineGap,
						Sources: []ProvenanceSource{
							provenance("snapshot", strconv.Itoa(previoussnapshot)),
							provenance("snapshot", strconv.Itoa(si)),
						},
					},
				})
				// A hole is unknown telemetry: no recovery may be claimed
				// across it (phase 3 philosophy, P4).
				mem.breakContinuity()
				disk.breakContinuity()
				diskio.breakContinuity()
				network.breakContinuity()
				for id := range cpuepisodes {
					cpuepisodes[id] = nil
				}
				trusted = wall
			case wall.After(trusted):
				trusted = wall
			}
		} else {
			trusted = wall
		}
		lastwall = wall
		previoussnapshot = si
		prov := EventProvenance{RuleID: RuleTimelineBuild, Sources: []ProvenanceSource{provenance("snapshot", strconv.Itoa(si))}}

		if systemSectionOK(s) && s.System != nil {
			memorypercent := 0.0
			memoryknown := s.System.MemoryStatsAvailable && s.System.MemoryTotal > 0
			if memoryknown {
				memorypercent = float64(s.System.MemoryUsed) / float64(s.System.MemoryTotal) * 100
				if memorypercent > 100 {
					// the phase 3 guard (4.1 review change 5): inconsistent
					// input cannot exceed capacity; clamp and mark it.
					memorypercent = 100
				}
			}
			memevents := mem.observe(at, memorypercent, memoryknown, prov, !displaced)
			if memoryknown && mem.active && mem.limitCrossed && memorypercent >= memoryLimitPercent {
				severesamples[mem.episode]++
			}
			for index := range memevents {
				memevents[index].Data = ensureData(memevents[index].Data)
				if memoryknown {
					memevents[index].Data["memory_percent"] = memorypercent
				}
			}
			events = append(events, memevents...)

			if known := s.System.DiskStatsAvailable && s.System.DiskTotal > 0; known {
				free := float64(s.System.DiskFree) / float64(s.System.DiskTotal) * 100
				subject := SubjectRef{SubjectFilesystem, s.System.DiskFilesystem}
				events = append(events, disk.observe(at, free, subject, prov, !displaced)...)
				if disk.active && disk.exhausted && free <= diskExhaustedPercent {
					severesamples[disk.episode]++
				}
			}
			iosome, ioknown := ioPressure(s)
			events = append(events, diskio.observe(at, iosome, ioknown, prov, !displaced)...)
		}

		if collectorSectionOK(s, "connections") {
			events = append(events, network.observe(at, s.Connections, EventProvenance{RuleID: RuleNetworkProgress, Sources: prov.Sources}, !displaced)...)
		}

		if cgroupSectionOK(s) {
			cgroupprov := EventProvenance{RuleID: RuleCgroupLimit, Sources: prov.Sources}
			// one observation per cgroup path per sample: several watched
			// processes share a cgroup, and observing it once per process
			// would inflate the persistence count (R12).
			seenpaths := map[string]bool{}
			for pi := range s.Processes {
				c := s.Processes[pi].Cgroup
				if c == nil || !c.MemoryCurrentAvailable || !c.MemoryMaxAvailable || c.MemoryMax == 0 || c.Path == "" {
					continue
				}
				if seenpaths[c.Path] {
					continue
				}
				seenpaths[c.Path] = true
				epi := cgroupepisodes[c.Path]
				if epi == nil {
					epi = &crossingEpisode{subject: SubjectRef{SubjectCgroup, c.Path}, limitFraction: cgroupLimitFraction, eventType: EventCgroupLimitReached}
					cgroupepisodes[c.Path] = epi
				}
				fraction := float64(c.MemoryCurrent) / float64(c.MemoryMax)
				cgroupevents := epi.observe(at, fraction, cgroupprov, !displaced)
				if epi.active && fraction >= cgroupLimitFraction {
					severesamples[epi.episode]++
				}
				for ei := range cgroupevents {
					cgroupevents[ei].Data = ensureData(cgroupevents[ei].Data)
					cgroupevents[ei].Data["memory_percent"] = fraction * 100
				}
				events = append(events, cgroupevents...)
			}

			// sampled OOM counters (§3.2): the kernel's cumulative
			// memory.events oom_kill per cgroup path. A rise between
			// consecutive capture-order samples is one kernel OOM kill of
			// one of the cgroup's members. A displaced sample emits
			// nothing (P4); the baseline still advances, so a later
			// comparison cannot resurrect the lost increment.
			seenoom := map[string]bool{}
			for pi := range s.Processes {
				c := s.Processes[pi].Cgroup
				if c == nil || !c.OOMEventsAvailable || c.Path == "" || seenoom[c.Path] {
					continue
				}
				seenoom[c.Path] = true
				before, known := oomKills[c.Path]
				// the baseline advances whether or not this sample was
				// displaced (P4): a displaced rise is unobservable and must
				// never resurrect in a later comparison.
				oomKills[c.Path] = oomKillBaseline{kills: c.OOMKills, wall: wall}
				if known && !displaced && c.OOMKills > before.kills {
					// stamped at the window open: the rise is certain only
					// inside the window, and an exit recorded inside it orders
					// after the event stamp so the engine can pair them. an
					// exit stamped before the open is not this window's victim;
					// the engine refuses such pairs, which is the conservative
					// direction.
					events = append(events, Event{
						Type:      EventOOM,
						Timestamp: before.wall,
						Subject:   SubjectRef{SubjectCgroup, c.Path},
						Data: map[string]any{
							"oom_kill_delta":       int64(c.OOMKills - before.kills),
							"oom_kill_total":       c.OOMKills,
							"oom_group_kill_total": c.OOMGroupKills,
							"interval_start":       before.wall.Format(time.RFC3339Nano),
							"interval_end":         wall.Format(time.RFC3339Nano),
						},
						Provenance: EventProvenance{RuleID: RuleOOMKillCounter, Sources: cgroupprov.Sources},
					})
				}
			}
		}

		if processSectionOK(s) {
			for pi := range s.Processes {
				p := &s.Processes[pi]
				subject := processSubject(p.PID, p.StartTicks)
				if _, seen := processfirstseen[subject.ID]; !seen {
					processfirstseen[subject.ID] = at
				}
				if prior, seen := processstates[subject.ID]; seen && prior != p.State {
					switch {
					case isStoppedState(prior) && !isStoppedState(p.State):
						events = append(events, Event{Type: EventProcessResumed, Timestamp: at, Subject: subject, PID: p.PID, StartTicks: p.StartTicks, Provenance: prov})
					case !isStoppedState(prior) && isStoppedState(p.State):
						events = append(events, Event{Type: EventProcessStopped, Timestamp: at, Subject: subject, PID: p.PID, StartTicks: p.StartTicks, Provenance: prov})
					}
				} else if _, seen := processstates[subject.ID]; !seen && isStoppedState(p.State) {
					// the process was already stopped at the first usable
					// observation. preserve the state fact but do not invent
					// when it entered the stopped state.
					events = append(events, Event{
						Type: EventProcessStopped, Timestamp: at, Subject: subject,
						PID: p.PID, StartTicks: p.StartTicks,
						OnsetUnknown: true, Data: map[string]any{"capture_start": processfirstseen[subject.ID]}, Provenance: prov,
					})
				}
				processstates[subject.ID] = p.State
				if prior, seen := processppid[subject.ID]; seen && prior != p.PPID {
					events = append(events, Event{
						Type:      EventProcessReparented,
						Timestamp: at,
						Subject:   subject,
						PID:       p.PID, StartTicks: p.StartTicks,
						PPID:           prior,
						PPIDStartTicks: parentStartTicksAt(i, prior, at),
						Data:           map[string]any{"from_ppid": prior, "to_ppid": p.PPID, "capture_start": processfirstseen[subject.ID]},
						Provenance:     prov,
					})
				}
				processppid[subject.ID] = p.PPID

				if p.CPUPercent < 0 {
					// sensor gap: the episode is UNKNOWN, never quietly over.
					cpuepisodes[subject.ID] = nil
					continue
				}
				epi := cpuepisodes[subject.ID]
				if epi == nil {
					epi = &cpuEpisode{subject: subject, identityPID: p.PID, identityTicks: p.StartTicks}
					cpuepisodes[subject.ID] = epi
				}
				events = append(events, epi.observe(at, p.CPUPercent, prov, !displaced)...)
			}
		} else {
			for id := range cpuepisodes {
				cpuepisodes[id] = nil
			}
		}
	}

	events = append(events, groupTerminationEvents(i, pgidof, eventorder)...)

	for index := range events {
		events[index].Class = classOf(events[index].Type)
		// A network stop is emitted only after ≥ networkStallThreshold of
		// non-progress across continuously available samples (§7.2), so it
		// is persistent by construction; the socket sample machine books no
		// per-sample severe counts and the stamp stays off it.
		if events[index].Type == EventNetworkProgressStopped {
			events[index].Data = ensureData(events[index].Data)
			continue
		}
		if severityAnchorTypes[events[index].Type] && events[index].Episode != "" {
			events[index].Data = ensureData(events[index].Data)
			events[index].Data["severe_samples"] = severesamples[events[index].Episode]
		}
	}
	sortEvents(events)
	assignIDs(events)
	for idx := range events {
		events[idx].Sequence = uint64(idx)
	}
	return &Timeline{Events: events, Origin: timelineOrigin(i, events)}
}

// captureOrder is the snapshot processing order. bundles that record a
// per-snapshot capture index (the phase 1 contract) use it; otherwise bundle
// order is capture order for recorder-written bundles (spec §10 item 1).
// recorded bundle events are unaffected: they carry their own timestamps.
func captureOrder(i *incident.Incident) []int {
	order := make([]int, len(i.Snapshots))
	allunset := true
	for index := range order {
		order[index] = index
		if i.Snapshots[index].CaptureIndex != 0 {
			allunset = false
		}
	}
	if allunset {
		return order
	}
	sort.SliceStable(order, func(a, b int) bool {
		return i.Snapshots[order[a]].CaptureIndex < i.Snapshots[order[b]].CaptureIndex
	})
	return order
}

func processEventStartTicks(event *incident.Event) int64 {
	if event.StartTicks != 0 {
		return event.StartTicks
	}
	if event.Connection != nil {
		return event.Connection.StartTicks
	}
	return 0
}

func typedPGID(processes []incident.ProcessMetadata, event *incident.Event) int {
	if event.Type != incident.ProcessExited && event.Type != incident.TraceProcessExit {
		return 0
	}
	return processGroupFor(processes, event.PID)
}

// processExitEventData is shared by the differ's PROCESS_EXIT and the
// merged TRACE_PROCESS_EXIT: the tracer stream carries the same recorded
// wait-status shape ("exit:N" / "signal:N", 6.10) in Event.ExitStatus.
func processExitEventData(processes []incident.ProcessMetadata, event *incident.Event) map[string]any {
	data := map[string]any{}
	if pgid := processGroupFor(processes, event.PID); pgid > 0 {
		data["pgid"] = pgid
	}
	// exit state is opportunistic capture (platform.ParseLinuxStat): present
	// only when a sampled zombie still exposed its wait status. "exit:0" is
	// the recorded "normal" state; every other non-empty value (a non-zero
	// exit code, a signal number) is a non-normal terminal state, and an
	// empty value stays UNKNOWN, the differ's ordinary reaped-exit case.
	if event.ExitStatus != "" {
		state := event.ExitStatus
		if state == "exit:0" {
			state = "normal"
		}
		data["exit_state"] = state
	}
	return data
}

func processEventData(processes []incident.ProcessMetadata, event *incident.Event) map[string]any {
	if event.Type != incident.ProcessExited && event.Type != incident.TraceProcessExit {
		return map[string]any{}
	}
	return processExitEventData(processes, event)
}

// oomKillBaseline is the last observed cumulative oom_kill value for one
// cgroup path and the wall time of that observation: together they name the
// window in which a counter rise is certain to have happened (P4). the time
// belongs to the sample the baseline was taken from, not to the current
// sample, so a section gap never shrinks a later window.
type oomKillBaseline struct {
	kills uint64
	wall  time.Time
}

// lastKnownCgroupPath returns the exited/victim process's last recorded
// unified cgroup path. the counter rule's "process in that cgroup" check
// reads it from the exit event's own recorded data, so it is evidence the
// bundle already carries rather than a graph-time inference.
func lastKnownCgroupPath(cgroupByPID map[int]string, pid int) string {
	if path, ok := cgroupByPID[pid]; ok {
		return path
	}
	return ""
}
func ensureData(data map[string]any) map[string]any {
	if data == nil {
		return make(map[string]any)
	}
	return data
}

func parentStartTicksAt(i *incident.Incident, pid int, at time.Time) int64 {
	var startTicks int64
	found := false
	for _, snapshot := range i.Snapshots {
		if !snapshot.Timestamp.Equal(at) {
			continue
		}
		for _, process := range snapshot.Processes {
			if process.PID != pid {
				continue
			}
			if found && startTicks != process.StartTicks {
				return 0
			}
			startTicks, found = process.StartTicks, true
		}
	}
	return startTicks
}

func processGroupFor(processes []incident.ProcessMetadata, pid int) int {
	for _, process := range processes {
		if process.PID == pid {
			return process.PGID
		}
	}
	return 0
}

func timelineOrigin(i *incident.Incident, events []Event) time.Time {
	if !i.CaptureStart.IsZero() {
		return i.CaptureStart
	}
	if len(events) == 0 {
		return time.Time{}
	}
	return events[0].Timestamp
}

// relative reports the event's offset from the timeline origin (4.19).
func (t *Timeline) Relative(e *Event) time.Duration {
	if e == nil || t.Origin.IsZero() {
		return 0
	}
	return e.Timestamp.Sub(t.Origin)
}

func systemSectionOK(s *collector.Snapshot) bool { return collectorSectionOK(s, "system") }
func processSectionOK(s *collector.Snapshot) bool {
	return collectorSectionOK(s, "processes") && (len(s.Processes) > 0 || (s.System != nil && s.System.ProcessCountAvailable))
}
func cgroupSectionOK(s *collector.Snapshot) bool { return collectorSectionOK(s, "cgroups") }

// collectorSectionOK applies the differ's conservative rule: an error report
// or an error-flagged metric marks the section unusable for the sample.
func collectorSectionOK(s *collector.Snapshot, name string) bool {
	for _, m := range s.Metrics {
		if m.Name == name && m.Error {
			return false
		}
	}
	for _, e := range s.Errors {
		if e.Collector == name {
			return false
		}
	}
	return true
}

func ioPressure(s *collector.Snapshot) (float64, bool) {
	psi, ok := s.Pressure[platform.PressureIO]
	if !ok || !psi.HasSome {
		return 0, false
	}
	return psi.Some.Avg10, true
}

func isStoppedState(state string) bool {
	return len(state) > 0 && (state[0] == 'T' || state[0] == 't')
}

func socketSubject(c *collector.ConnectionSnapshot) SubjectRef {
	if c == nil {
		return SubjectRef{SubjectSocket, "unknown"}
	}
	if c.Inode > 0 {
		return SubjectRef{SubjectSocket, "inode-" + strconv.FormatUint(c.Inode, 10)}
	}
	return SubjectRef{SubjectSocket, "port:" + c.LocalAddr + ":" + strconv.Itoa(int(c.LocalPort)) + ":" + c.RemoteAddr + ":" + strconv.Itoa(int(c.RemotePort))}
}

// episodeFinish carries the standard episode metadata for recovery/end
// events: observed span and the boundary that closed it.
func episodeFinish(duration time.Duration) map[string]any {
	return map[string]any{"duration_ms": duration.Milliseconds()}
}

// memoryMachine tracks host memory across samples (RuleMemoryCrossing@1):
//
//	below 90          quiet
//	>= 90             pressure episode (STARTED, or ACTIVE when already in
//	                  effect at the first available observation: onset is not
//	                  claimed - 4.28)
//	>= 98             additionally one quantity crossing a higher threshold:
//	                  MEMORY_LIMIT_REACHED, primary per episode (the two
//	                  events are one episode's escalation pair, linked with
//	                  ESCALATES_TO - spec §1.3)
//	back below 85     episode over: MEMORY_RECOVERED with observed span
//
// A trusted observation of the boundary carries its onset window: the
// condition was below the boundary at the last such sample and observed at
// this one. unavailable telemetry, a timeline gap, or a clock step is
// UNKNOWN: recovery is never claimed across it.
type memoryMachine struct {
	active, limitCrossed, everKnown bool
	startedAt                       time.Time
	episode                         string
	episodeN                        int
	lastBelowPressure               time.Time // last trusted observation below 90
	lastBelowLimit                  time.Time // last trusted observation below 98
	// unknownDuringEpisode records that telemetry went UNKNOWN while the
	// episode was active: the episode then cannot claim an observed recovery
	// and ends silently instead.
	unknownDuringEpisode bool
}

func (m *memoryMachine) breakContinuity() {
	if m.active {
		m.unknownDuringEpisode = true
	}
}

func (m *memoryMachine) observe(at time.Time, percent float64, known bool, prov EventProvenance, trusted bool) []Event {
	if !known {
		// UNKNOWN section: an active episode cannot be claimed recovered.
		if m.active {
			m.unknownDuringEpisode = true
		}
		return nil
	}
	var out []Event
	subject := SubjectRef{SubjectHost, "local"}
	onsetknown := m.everKnown
	switch {
	case percent >= memoryLimitPercent:
		if !m.active {
			m.episodeN++
			m.episode = fmt.Sprintf("memory:host:local#%d", m.episodeN)
			m.active, m.startedAt, m.limitCrossed = true, at, true
			out = append(out, m.conditionEvent(at, onsetknown, subject, prov, trusted))
			crossed := Event{Type: EventMemoryLimitReached, Timestamp: at, Subject: subject, Episode: m.episode, Provenance: prov}
			crossed.OnsetUnknown = !onsetknown || !trusted
			if trusted && !m.lastBelowLimit.IsZero() {
				crossed.OnsetWindow = &Window{NotBefore: m.lastBelowLimit, ObservedAt: at}
			}
			out = append(out, crossed)
		} else if !m.limitCrossed {
			m.limitCrossed = true
			crossed := Event{Type: EventMemoryLimitReached, Timestamp: at, Subject: subject, Episode: m.episode, Provenance: prov}
			crossed.OnsetUnknown = !trusted
			if trusted && !m.lastBelowLimit.IsZero() {
				crossed.OnsetWindow = &Window{NotBefore: m.lastBelowLimit, ObservedAt: at}
			}
			out = append(out, crossed)
		}
	case percent >= memoryPressurePercent:
		if trusted {
			m.lastBelowLimit = at
		}
		if !m.active {
			m.episodeN++
			m.episode = fmt.Sprintf("memory:host:local#%d", m.episodeN)
			m.active, m.startedAt = true, at
			out = append(out, m.conditionEvent(at, onsetknown, subject, prov, trusted))
		}
	case percent < memoryPressurePercent-memoryHysteresis && m.active:
		if m.unknownDuringEpisode {
			// the episode persisted across UNKNOWN telemetry: the observed
			// low reading cannot prove continuity, so no recovery is claimed.
			m.reset()
			m.everKnown = true
			m.lastBelowPressure, m.lastBelowLimit = at, at
			return nil
		}
		out = append(out, Event{
			Type: EventMemoryRecovered, Timestamp: at, Subject: subject,
			Episode:    m.episode,
			Data:       episodeFinish(at.Sub(m.startedAt)),
			Provenance: prov,
		})
		m.reset()
	}
	if trusted && percent < memoryPressurePercent {
		m.lastBelowPressure = at
	}
	if trusted && percent < memoryLimitPercent {
		m.lastBelowLimit = at
	}
	m.everKnown = true
	return out
}

// conditionEvent emits the episode-start event: STARTED when the onset was
// observed within the capture, ACTIVE with OnsetUnknown when the condition
// was already in effect at the first available observation (4.28). an
// onset observed only through displaced (clock-stepped) samples also keeps
// the onset unknown: its position is not resolvable in v1.
func (m *memoryMachine) conditionEvent(at time.Time, onsetKnown bool, subject SubjectRef, prov EventProvenance, trusted bool) Event {
	eventType := EventMemoryPressureStarted
	onsetUnknown := false
	if !onsetKnown || !trusted {
		eventType, onsetUnknown = EventMemoryPressureActive, true
	}
	event := Event{Type: eventType, Timestamp: at, Subject: subject, Episode: m.episode, OnsetUnknown: onsetUnknown, Provenance: prov}
	if trusted && onsetKnown && !m.lastBelowPressure.IsZero() {
		event.OnsetWindow = &Window{NotBefore: m.lastBelowPressure, ObservedAt: at}
	}
	return event
}

func (m *memoryMachine) reset() {
	// A3: the episode counter is monotonic across resets. A new episode opened
	// after a recovery must not reuse the closed episode's identity. two
	// distinct episodes sharing "memory:host:local#N" would let the
	// escalation rule bind the new episode's limit to the recovered onset,
	// forging a causal edge across an episode boundary.
	*m = memoryMachine{everKnown: true, episodeN: m.episodeN}
}

// diskMachine tracks one filesystem across samples (RuleDiskCrossing@1):
//
//	below 15% free   pressure episode (DISK_PRESSURE_STARTED, or DISK_LOW_ACTIVE
//	                 when already in effect at the first available observation)
//	below 5% free    additionally DISK_EXHAUSTED: the boundary fact is kept
//	                 even when one sample jumps straight to it (A10)
//	>= 30% free      episode over: DISK_RECOVERED when continuity held
//
// recovery is never claimed across a sensor gap, timeline gap, or clock step.
type diskMachine struct {
	subject                      SubjectRef
	active, exhausted, everKnown bool
	startedAt                    time.Time
	episode                      string
	episodeN                     int
	lastBelowPressure            time.Time
	lastBelowExhausted           time.Time
	unknownDuringEpisode         bool
}

func (d *diskMachine) breakContinuity() {
	if d.active {
		d.unknownDuringEpisode = true
	}
}

func (d *diskMachine) observe(at time.Time, freePercent float64, subject SubjectRef, prov EventProvenance, trusted bool) []Event {
	d.subject = subject
	var out []Event
	onsetknown := d.everKnown && !d.active
	switch {
	case freePercent <= diskExhaustedPercent:
		if !d.active {
			d.episodeN++
			d.episode = fmt.Sprintf("disk:%s#%d", subject.ID, d.episodeN)
			d.active, d.startedAt, d.exhausted = true, at, true
			out = append(out, d.conditionEvent(at, onsetknown, subject, prov, trusted))
			crossed := Event{Type: EventDiskExhausted, Timestamp: at, Subject: subject, Episode: d.episode, Provenance: prov}
			crossed.OnsetUnknown = !onsetknown || !trusted
			if trusted && !d.lastBelowExhausted.IsZero() {
				crossed.OnsetWindow = &Window{NotBefore: d.lastBelowExhausted, ObservedAt: at}
			}
			out = append(out, crossed)
		} else if !d.exhausted {
			d.exhausted = true
			crossed := Event{Type: EventDiskExhausted, Timestamp: at, Subject: subject, Episode: d.episode, Provenance: prov}
			crossed.OnsetUnknown = !trusted
			if trusted && !d.lastBelowExhausted.IsZero() {
				crossed.OnsetWindow = &Window{NotBefore: d.lastBelowExhausted, ObservedAt: at}
			}
			out = append(out, crossed)
		}
	case freePercent <= diskPressurePercent:
		if trusted {
			d.lastBelowExhausted = at
		}
		if !d.active {
			d.episodeN++
			d.episode = fmt.Sprintf("disk:%s#%d", subject.ID, d.episodeN)
			d.active, d.startedAt, d.exhausted = true, at, false
			out = append(out, d.conditionEvent(at, onsetknown, subject, prov, trusted))
		}
	case freePercent >= diskRecoverPercent && d.active:
		if d.unknownDuringEpisode {
			d.reset()
			d.everKnown = true
			d.lastBelowPressure, d.lastBelowExhausted = at, at
			return nil
		}
		out = append(out, Event{
			Type: EventDiskRecovered, Timestamp: at, Subject: subject, Episode: d.episode,
			Data: episodeFinish(at.Sub(d.startedAt)), Provenance: prov,
		})
		d.reset()
	}
	if trusted && freePercent > diskPressurePercent {
		d.lastBelowPressure = at
	}
	if trusted && freePercent > diskExhaustedPercent {
		d.lastBelowExhausted = at
	}
	d.everKnown = true
	return out
}

func (d *diskMachine) conditionEvent(at time.Time, onsetKnown bool, subject SubjectRef, prov EventProvenance, trusted bool) Event {
	eventType := EventDiskPressureStarted
	onsetUnknown := false
	if !onsetKnown || !trusted {
		eventType, onsetUnknown = EventDiskLowActive, true
	}
	event := Event{Type: eventType, Timestamp: at, Subject: subject, Episode: d.episode, OnsetUnknown: onsetUnknown, Provenance: prov}
	if trusted && onsetKnown && !d.lastBelowPressure.IsZero() {
		event.OnsetWindow = &Window{NotBefore: d.lastBelowPressure, ObservedAt: at}
	}
	return event
}

func (d *diskMachine) reset() {
	subject := d.subject
	// A3: episodeN is monotonic across resets. a newly opened episode after
	// a recovery must not reuse the closed episode's identity.
	*d = diskMachine{subject: subject, everKnown: true, episodeN: d.episodeN}
}

// ioPressureMachine derives IO_PRESSURE episodes from sustained severe IO PSI
// (avg10 some >= 20%) lasting at least diskIOSustain (§3.3: IO stall time is
// its own quantity, never DISK_PRESSURE). the onset is uncertain when the
// very first usable observation was already severe: PSI avg10 is itself a
// decaying mean, so a value above threshold at first sight says nothing
// about when the stall began (4.28 / A17).
type ioPressureMachine struct {
	active   bool
	since    time.Time
	sawBelow bool
	episode  string
	episodeN int
	broken   bool
}

func (r *ioPressureMachine) breakContinuity() {
	if r.active {
		r.broken = true
	}
}

func (r *ioPressureMachine) observe(at time.Time, somePercent float64, known bool, prov EventProvenance, trusted bool) []Event {
	subject := SubjectRef{SubjectHost, "local"}
	var out []Event
	if !known {
		if r.active {
			r.broken = true
		}
		return nil // sustained pressure across an UNKNOWN gap cannot be claimed
	}
	switch {
	case somePercent >= diskPressureIOPercent:
		if r.since.IsZero() {
			r.since = at
		}
		if !r.active && at.Sub(r.since) >= diskIOSustain {
			r.episodeN++
			r.episode = fmt.Sprintf("io:host:local#%d", r.episodeN)
			r.active = true
			event := Event{Type: EventIOPressureStarted, Timestamp: r.since, Subject: subject, Episode: r.episode, Provenance: prov}
			event.OnsetUnknown = !r.sawBelow || !trusted
			out = append(out, event)
		}
	case somePercent < diskPressureIOPercent:
		if r.active {
			if r.broken {
				r.active = false
				r.broken = false
				r.since = time.Time{}
				r.sawBelow = true
				return out
			}
			out = append(out, Event{
				Type: EventIOPressureEnded, Timestamp: at, Subject: subject,
				Episode: r.episode, Data: episodeFinish(at.Sub(r.since)), Provenance: prov,
			})
		}
		r.active = false
		r.since = time.Time{}
		r.sawBelow = true
	}
	return out
}

// crossingEpisode is the cgroup limit rule (RuleCgroupLimit@1): one event per
// episode when the path's memory.current/memory.max reaches the declared
// fraction. the episode ends only below the hysteresis boundary (A23): a
// cgroup wobbling at the boundary emits one event, not one per wobble. when
// the very first observation is already at the fraction, the crossing time
// was not observed and the event carries OnsetUnknown (A17). A jump from
// below straight to the boundary between two samples still emits (A10
// applies to every machine).
type crossingEpisode struct {
	subject       SubjectRef
	limitFraction float64
	eventType     EventType
	active        bool
	startedAt     time.Time
	// sawBelowKnown says a trusted observation below the boundary was made:
	// only then is the crossing's time observed (A17).
	sawBelowKnown bool
	episode       string
	episodeN      int
}

func (c *crossingEpisode) observe(at time.Time, fraction float64, prov EventProvenance, trusted bool) []Event {
	if fraction >= c.limitFraction {
		if !c.active {
			c.episodeN++
			c.episode = fmt.Sprintf("cgroup:%s#%d", c.subject.ID, c.episodeN)
			c.active = true
			c.startedAt = at
			onsetknown := c.sawBelowKnown
			event := Event{
				Type: c.eventType, Timestamp: at, Subject: c.subject,
				Episode:    c.episode,
				Data:       map[string]any{"fraction": fraction, "threshold": c.limitFraction},
				Provenance: prov,
			}
			event.OnsetUnknown = !onsetknown || !trusted
			return []Event{event}
		}
		return nil
	}
	if trusted && fraction < c.limitFraction-cgroupHysteresis && c.active {
		// below the hysteresis boundary: memory.current fell back, which is
		// observable, so the episode ends with an explicit clearing event
		// (re-audit R11). the next crossing is a new episode.
		c.active = false
		c.sawBelowKnown = true
		return []Event{{
			Type: EventCgroupLimitCleared, Timestamp: at, Subject: c.subject,
			Episode:    c.episode,
			Data:       map[string]any{"fraction": fraction, "duration_ms": at.Sub(c.startedAt).Milliseconds()},
			Provenance: prov,
		}}
	}
	if trusted {
		c.sawBelowKnown = true
	}
	return nil
}

// cpuEpisode tracks one process identity's CPU saturation (RuleCPUSaturation@1).
// saturation must be sustained for cpuSustainMinimum across continuously
// available, at-or-above-threshold samples before STARTED is emitted; a drop
// below the hysteresis boundary ends the episode with CPU_SATURATION_ENDED.
// if no sample below the threshold was ever observed for the identity, the
// activation carries OnsetUnknown (4.28).
type cpuEpisode struct {
	subject        SubjectRef
	identityPID    int
	identityTicks  int64
	active         bool
	startedAt      time.Time
	sustainedSince time.Time
	sawUnsaturated bool
	lastBelow      time.Time
	episode        string
	episodeN       int
}

func (c *cpuEpisode) observe(at time.Time, cpuPercent float64, prov EventProvenance, trusted bool) []Event {
	var out []Event
	switch {
	case cpuPercent >= cpuSaturatedPercent:
		if c.sustainedSince.IsZero() {
			c.sustainedSince = at
		}
		if !c.active && at.Sub(c.sustainedSince) >= cpuSustainMinimum {
			c.episodeN++
			c.episode = fmt.Sprintf("cpu:%s#%d", c.subject.ID, c.episodeN)
			c.active, c.startedAt = true, c.sustainedSince
			openedwellknown := c.sawUnsaturated
			out = append(out, Event{
				Type: EventCPUSaturationStarted, Timestamp: c.sustainedSince, Subject: c.subject,
				PID: c.identityPID, StartTicks: c.identityTicks,
				Episode:      c.episode,
				OnsetUnknown: !openedwellknown || !trusted, OnsetWindow: episodeWindow(c.lastBelow, c.sustainedSince, trusted && openedwellknown),
				Provenance: prov,
			})
		}
	case cpuPercent < cpuSaturatedBelow:
		c.sawUnsaturated = true
		if trusted {
			c.lastBelow = at
		}
		if c.active {
			c.active = false
			out = append(out, Event{
				Type: EventCPUSaturationEnded, Timestamp: at, Subject: c.subject,
				PID: c.identityPID, StartTicks: c.identityTicks,
				Episode:    c.episode,
				Data:       episodeFinish(at.Sub(c.startedAt)),
				Provenance: prov,
			})
		}
		c.sustainedSince = time.Time{}
	}
	// values between the shift boundaries keep the current state.
	return out
}

// episodeWindow builds the onset window when the crossing was actually
// observed between two trusted samples.
func episodeWindow(notBefore, observedAt time.Time, ok bool) *Window {
	if !ok {
		return nil
	}
	return &Window{NotBefore: notBefore, ObservedAt: observedAt}
}

type groupExit struct {
	eventIndex int
	at         time.Time
}

// groupTerminationEvents derives PROCESS_GROUP_TERMINATED (RuleGroupTerm-
// ination@1): a PGID losing at least two recorded member exits inside the
// coordinated window. the derived event is factual clustering; the causal
// interpretation stays with the rule layer.
func groupMemberPIDs(events []incident.Event, exits []groupExit) []int {
	pids := make([]int, 0, len(exits))
	for _, exit := range exits {
		if exit.eventIndex >= 0 && exit.eventIndex < len(events) {
			pids = append(pids, events[exit.eventIndex].PID)
		}
	}
	return pids
}

func groupMemberIdentities(events []incident.Event, exits []groupExit) []ProcessIdentity {
	identities := make([]ProcessIdentity, 0, len(exits))
	for _, exit := range exits {
		if exit.eventIndex >= 0 && exit.eventIndex < len(events) {
			event := events[exit.eventIndex]
			identities = append(identities, ProcessIdentity{PID: event.PID, StartTicks: event.StartTicks})
		}
	}
	return identities
}

func groupTerminationEvents(i *incident.Incident, pgidOf map[int]int, order []int) []Event {
	// Re-audit R9: the group event is emitted at the second member exit but
	// keeps absorbing members for the rest of its coordinated window (it
	// previously froze at two members), and a later, separate coordinated
	// termination of the same PGID derives its own event (it was previously
	// suppressed for the rest of the capture).
	sequences := map[int][]groupExit{}
	emitted := map[int]int{} // pgid -> index in out of the open cluster's event
	var out []Event
	for _, index := range order {
		e := &i.Events[index]
		if e.Type != incident.ProcessExited {
			continue
		}
		pgid, known := pgidOf[e.PID]
		if !known {
			continue
		}
		list := sequences[pgid]
		if len(list) > 0 && e.Timestamp.Sub(list[0].at) > groupCoordinatedWindow {
			list = nil
			delete(emitted, pgid)
		}
		list = append(list, groupExit{eventIndex: index, at: e.Timestamp})
		sequences[pgid] = list
		if len(list) < 2 {
			continue
		}
		sources := make([]ProvenanceSource, 0, len(list))
		for _, g := range list {
			sources = append(sources, provenance("event", strconv.Itoa(g.eventIndex)))
		}
		event := Event{
			Type:       EventProcessGroupTerminated,
			Timestamp:  list[0].at,
			Subject:    groupSubject(pgid),
			PGID:       pgid,
			ProcessIDs: groupMemberIdentities(i.Events, list),
			Data:       map[string]any{"pgid": pgid, "exits": len(list), "member_pids": groupMemberPIDs(i.Events, list)},
			Provenance: EventProvenance{RuleID: RuleGroupTermination, Sources: sources},
		}
		if at, open := emitted[pgid]; open {
			out[at] = event
			continue
		}
		emitted[pgid] = len(out)
		out = append(out, event)
	}
	return out
}
