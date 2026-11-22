package causal

// SignatureEventLink (4.16) maps phase 3 signature IDs to timeline events
// that can support them. the CLI/report layer scopes process diagnoses by
// exact process identity before filling SignatureMatch.RelatedEvents.
//
// conservative linkage rules:
//   - only event types the packages actually emit are listed;
//   - unobservable telemetry (OOM_EVENT, socket progress) is never claimed;
//   - a signature with no listed types links nothing (an empty slice).
var signatureEventTypes = map[string][]EventType{
	// Process-scoped signatures link exact process events, never host/resource
	// context. group termination also links its aggregate event.
	"FROZEN_PROCESS":            {EventProcessStopped, EventProcessResumed},
	"ORPHAN_PROCESS_TREE":       {EventProcessExited, EventProcessReparented},
	"PROCESS_GROUP_TERMINATION": {EventProcessGroupTerminated, EventProcessExited},
	"OOM_KILL":                  {EventProcessExited, EventOOM},
	"CPU_SPIN":                  {EventCPUSaturationStarted, EventCPUSaturationEnded},
	"BROKER_SOCKET_STALL":       {EventConnectionOpened, EventConnectionClosed},

	// these signatures describe host/resource/socket conditions, not a
	// particular process incarnation. OOM_KILL links OOM_EVENT only for an
	// exact identity (the tracer's victim-naming record); the cgroup-subject
	// counter event has no identity and is filtered out by the scope check.
	// Host/cgroup memory observations are never linked: they do not identify
	// the departed process.
	"DISK_EXHAUSTION":      {EventDiskPressureStarted, EventDiskLowActive, EventDiskExhausted, EventDiskRecovered, EventDiskPressureEnded},
	"RESOURCE_STARVATION":  {EventDiskPressureStarted, EventDiskPressureEnded, EventCPUSaturationStarted, EventCPUSaturationEnded},
	"NETWORK_PATH_FAILURE": {EventConnectionOpened, EventConnectionClosed},
}

// RelatedEventTypes returns the event types a signature's evidence overlaps,
// in a stable order, or nil for unknown signature IDs.
func RelatedEventTypes(signature string) []EventType {
	types := signatureEventTypes[signature]
	if len(types) == 0 {
		return nil
	}
	out := make([]EventType, len(types))
	copy(out, types)
	return out
}

// RelatedEventIDs filters timeline events to those supporting one signature.
// Process-scoped signatures require identities: an unscoped match links
// nothing rather than presenting unrelated process events as its evidence.
// resource and host events for process-scoped signatures are deliberately
// excluded: only exact process events can be linked without extra scoping data.
func RelatedEventIDs(tl *Timeline, signature string, scoped ...[]ProcessIdentity) []EventID {
	if tl == nil {
		return nil
	}
	types := RelatedEventTypes(signature)
	if len(types) == 0 {
		return nil
	}
	wanted := make(map[EventType]bool, len(types))
	for _, t := range types {
		wanted[t] = true
	}
	var processes []ProcessIdentity
	if len(scoped) > 0 {
		processes = scoped[0]
	}
	identities := make(map[ProcessIdentity]bool, len(processes))
	for _, identity := range processes {
		if identity.PID > 0 && identity.StartTicks > 0 {
			identities[identity] = true
		}
	}
	if isProcessLink(signature) && len(identities) == 0 {
		return nil
	}
	var out []EventID
	for _, event := range tl.Events {
		if !wanted[event.Type] {
			continue
		}
		if isProcessLink(signature) && !eventMatchesIdentities(&event, identities) {
			continue
		}
		out = append(out, event.ID)
	}
	return out
}

func eventMatchesIdentities(event *Event, identities map[ProcessIdentity]bool) bool {
	if event.Type == EventProcessGroupTerminated {
		return groupEventMatchesIdentities(event, identities)
	}
	if event.Type == EventProcessReparented {
		child := ProcessIdentity{PID: event.PID, StartTicks: event.StartTicks}
		parent := ProcessIdentity{PID: event.PPID, StartTicks: event.PPIDStartTicks}
		return eventIdentityKnown(child) && identities[child] || eventIdentityKnown(parent) && identities[parent]
	}
	identity := ProcessIdentity{PID: event.PID, StartTicks: event.StartTicks}
	return eventIdentityKnown(identity) && identities[identity]
}

func eventIdentityKnown(identity ProcessIdentity) bool {
	return identity.PID > 0 && identity.StartTicks > 0
}

func groupEventMatchesIdentities(group *Event, identities map[ProcessIdentity]bool) bool {
	for _, identity := range group.ProcessIDs {
		if eventIdentityKnown(identity) && identities[identity] {
			return true
		}
	}
	return false
}

func isProcessLink(signature string) bool {
	switch signature {
	case "OOM_KILL", "FROZEN_PROCESS", "ORPHAN_PROCESS_TREE", "PROCESS_GROUP_TERMINATION", "CPU_SPIN", "BROKER_SOCKET_STALL":
		return true
	default:
		return false
	}
}
