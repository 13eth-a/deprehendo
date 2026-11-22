package diagnosis

import (
	"fmt"
	"time"

	"runopsy/internal/platform"
)

// ---------------------------------------------------------------------------
// BROKER_SOCKET_STALL
// ---------------------------------------------------------------------------

const (
	stallEstablishedMinimum = 10 * time.Second
	wStallStable            = 0.15
	wStallOwnerAlive        = 0.15
	wStallNoChurn           = 0.05
	wStallHealthy           = 0.05
	stallCap                = 0.50
)

// BrokerSocketStallSignature diagnoses an application/broker stall (3.17):
// a runner-side process stays alive and a long-lived connection stays
// ESTABLISHED. those observations alone cannot establish lack of work. the v1 format has no socket byte
// counters, so RX progress is structurally UNKNOWN for every rule; the
// hypothesis is hard rejected because neither progress sensor exists.
type BrokerSocketStallSignature struct{}

func (BrokerSocketStallSignature) ID() SignatureID { return SignatureBrokerStall }
func (BrokerSocketStallSignature) Description() string {
	return "detects a runner alive with an established socket that stops making progress"
}

func (s BrokerSocketStallSignature) Analyze(ctx *AnalysisContext) SignatureMatch {
	cc := newConfidence()
	cc.unknown("SOCKET_RX_TX_BYTE_COUNTERS")
	cc.unknown("APPLICATION_LOG_PROGRESS")
	if !ctx.coverageOK(CoverConnections) {
		return notMatched(SignatureBrokerStall, "network telemetry was unavailable for most of the capture")
	}
	if !ctx.coverageOK(CoverProcesses) {
		return notMatched(SignatureBrokerStall, "process telemetry was unavailable for most of the capture")
	}

	socket, owner := stallCandidate(ctx)
	if socket == nil {
		return notMatched(SignatureBrokerStall, "no long-lived established connection with a surviving owner was observed")
	}
	cc.support(Evidence{Code: CodeStableConnection, Source: SourceNetwork, At: socket.EstablishedSince, Weight: wStallStable,
		Observed: map[string]any{
			"local":   fmt.Sprintf("%s:%d", socket.Key.LocalAddr, socket.Key.LocalPort),
			"remote":  fmt.Sprintf("%s:%d", socket.Key.RemoteAddr, socket.Key.RemotePort),
			"span_ms": socket.LastSeen.Sub(socket.EstablishedSince).Milliseconds(),
		}, Threshold: stallEstablishedMinimum})
	if owner != nil && owner.AliveAtEnd(ctx.End) {
		cc.support(Evidence{Code: CodeOwnerStaysAlive, Source: SourceProcess, At: ctx.End, Weight: wStallOwnerAlive,
			Observed: map[string]any{"pid": owner.Identity.PID, "start_ticks": owner.Identity.StartTicks}})
		cc.process(owner.Identity.PID, owner.Identity.StartTicks)
		cc.attr("pid", itoa(owner.Identity.PID))
	} else {
		cc.reject(Evidence{Code: CodeSocketBoundToDiedProcess, Source: SourceProcess, Weight: 0.30,
			Observed: "the socket's owner did not survive the capture"})
	}
	if !ctx.hadConnectionChurnAfter(socket.EstablishedSince) {
		cc.support(Evidence{Code: CodeNoReconnectChurn, Source: SourceNetwork, At: ctx.End, Weight: wStallNoChurn, Observed: true})
	} else {
		cc.reject(Evidence{Code: CodeNoReconnectChurn, Source: SourceNetwork, At: ctx.End, Weight: wStallNoChurn,
			Observed: "new sockets appeared while the owner lived: reconnect activity"})
	}
	supportHealthyResources(cc, ctx, wStallHealthy, ctx.End)
	if owner != nil && isWatchedIdentity(ctx, owner) {
		cc.attr("watched", "true")
	}

	// Anti-false-positive gate: with a healthy host, a manual trigger, and
	// no watched identity, a long-lived idle socket is indistinguishable
	// from a healthy idle workload; the honest answer is no diagnosis, and
	// the missing WORKER_LIFECYCLE expectation stays on the record.
	watched := owner != nil && isWatchedIdentity(ctx, owner)
	if !watched && ctx.Incident.Trigger.Type == "manual" && !ctx.resourcesStressed() {
		cc.unknown("WORKER_LIFECYCLE_EXPECTATION")
		_, _, _ = cc.score(0)
		return SignatureMatch{
			SignatureID:       SignatureBrokerStall,
			Confidence:        0,
			Rejected:          "long-lived established socket with no anomaly is indistinguishable from a healthy idle workload",
			MissingEvidence:   cc.missing,
			ProcessIdentities: append([]ProcessIdentity(nil), cc.processIdentities...),
		}
	}

	// the rival explanation must be absent for the stall reading to stand:
	// sockets that left ESTABLISHED mid-capture are path-failure evidence.
	if change, left := ownerLeftEstablished(ctx, owner); left {
		cc.reject(Evidence{Code: CodeDisconnectedSockets, Source: SourceNetwork, At: change.At, Weight: 0.40,
			Observed: map[string]any{"from": change.From, "to": change.To}})
	}

	score, sup, contra := cc.score(stallCap)
	match := SignatureMatch{
		SignatureID: SignatureBrokerStall,
		Confidence:  score,
		Summary:     "runner stayed alive with an established socket and no socket progress evidence",
		Rejected:    "socket byte counters and application progress are unavailable; an idle healthy connection and a broker stall are indistinguishable",
		Supporting:  sup, Contradicting: contra, MissingEvidence: cc.missing, Attributes: cc.attributes,
	}
	return cc.scope(match)
}

// stallCandidate picks the longest-lived established connection with a known
// owner that survived to capture end; ties break deterministically by key.
func stallCandidate(ctx *AnalysisContext) (*ConnectionLifetime, *ProcessLifetime) {
	var best *ConnectionLifetime
	var bestOwner *ProcessLifetime
	for _, life := range ctx.orderedConnections() {
		if life.OwnerKnown && life.Continuous && life.Established && life.LastSeen.Equal(ctx.End) {
			if span := life.LastSeen.Sub(life.EstablishedSince); !life.EstablishedSince.IsZero() && span >= stallEstablishedMinimum {
				if best == nil || span > best.LastSeen.Sub(best.EstablishedSince) {
					best = life
					bestOwner = ctx.Process[life.Owner]
				}
			}
		}
	}
	return best, bestOwner
}

// hadConnectionChurnAfter reports whether new sockets appeared after the
// anchor's first sight: reconnect activity is a network-failure tell, not a
// stall signature.
func (c *AnalysisContext) hadConnectionChurnAfter(anchor time.Time) bool {
	count := 0
	for _, life := range c.orderedConnections() {
		if life.FirstSeen.After(anchor.Add(time.Second)) {
			count++
			if count >= 3 {
				return true
			}
		}
	}
	return false
}

// ownerLeftEstablished reports whether any socket owned by the owner left
// ESTABLISHED mid-capture.
func ownerLeftEstablished(ctx *AnalysisContext, owner *ProcessLifetime) (stateChange, bool) {
	if owner == nil {
		return stateChange{}, false
	}
	for _, life := range ctx.orderedConnections() {
		if !life.OwnerKnown || life.Owner != owner.Identity {
			continue
		}
		if change, left := life.leftEstablishedMidCapture(); left {
			return change, true
		}
	}
	return stateChange{}, false
}

// ---------------------------------------------------------------------------
// NETWORK_PATH_FAILURE
// ---------------------------------------------------------------------------

const (
	pathSynChurnMinimum = 3
	wPathDisconnected   = 0.35
	wPathSynChurn       = 0.15
	wPathMultiHit       = 0.15
	wPathHealthy        = 0.10
	pathCap             = 0.85
)

// NetworkPathFailureSignature diagnoses connections failing at the path
// level (3.18): sockets leaving ESTABLISHED, SYN churn that never
// completes, or several endpoints affected at once. this is the rival
// explanation to BROKER_SOCKET_STALL; the exclusion pair in the engine
// decides which report survives when both would fire.
type NetworkPathFailureSignature struct{}

func (NetworkPathFailureSignature) ID() SignatureID { return SignatureNetworkFailure }
func (NetworkPathFailureSignature) Description() string {
	return "detects sockets leaving established state with connection-level churn"
}

func (s NetworkPathFailureSignature) Analyze(ctx *AnalysisContext) SignatureMatch {
	cc := newConfidence()
	cc.unknown("SYN_RETRANSMISSION_COUNTERS")
	cc.unknown("DNS_FAILURE_TELEMETRY")
	if !ctx.coverageOK(CoverConnections) {
		return notMatched(SignatureNetworkFailure, "network telemetry was unavailable for most of the capture; no path conclusion is possible")
	}

	disconnects, synchurn, affected, reconnects := pathEvidence(ctx)
	if len(disconnects) == 0 && synchurn == 0 {
		return notMatched(SignatureNetworkFailure, "no socket was observed leaving ESTABLISHED and no SYN churn was seen")
	}
	// reconnects are evidence of application retry/recovery, not a broken
	// path. only un-replaced failures count toward path failure.
	if reconnects > 0 && synchurn < pathSynChurnMinimum {
		match := SignatureMatch{
			SignatureID: SignatureNetworkFailure,
			Rejected:    "disconnects were followed by replacement connections to the same endpoints, which is consistent with application reconnect behavior",
			MissingEvidence: []string{
				"SYN_RETRANSMISSION_COUNTERS", "DNS_FAILURE_TELEMETRY",
			},
			Contradicting: []Evidence{{Code: CodeNoReconnectChurn, Source: SourceNetwork, At: ctx.End, Weight: 0.20, Observed: reconnects}},
		}
		return cc.scope(match)
	}
	if len(disconnects) == 0 && synchurn < pathSynChurnMinimum {
		return notMatched(SignatureNetworkFailure, "socket disconnects were repaired by reconnects and SYN churn stayed below the threshold")
	}
	if len(disconnects) > 0 {
		change := disconnects[0]
		cc.support(Evidence{Code: CodeDisconnectedSockets, Source: SourceNetwork, At: change.at, Weight: wPathDisconnected,
			Observed: map[string]any{"from": change.change.From, "to": change.change.To, "count": len(disconnects)}})
		cc.attr("disconnected", itoa(len(disconnects)))
	}
	if synchurn >= pathSynChurnMinimum {
		cc.support(Evidence{Code: CodeSynChurn, Source: SourceNetwork, At: ctx.End, Weight: wPathSynChurn,
			Observed: synchurn, Threshold: pathSynChurnMinimum})
	}
	if affected >= 2 {
		cc.support(Evidence{Code: CodeMultipleConnectionsHit, Source: SourceNetwork, At: ctx.End, Weight: wPathMultiHit,
			Observed: affected, Threshold: 2})
		cc.attr("connections_affected", itoa(affected))
	}
	supportHealthyResources(cc, ctx, wPathHealthy, ctx.End)

	score, sup, contra := cc.score(pathCap)
	rejected := ""
	if synchurn < pathSynChurnMinimum {
		rejected = "socket closures without repeated incomplete handshakes are compatible with normal peer shutdown"
	}
	match := SignatureMatch{
		SignatureID: SignatureNetworkFailure,
		Rejected:    rejected,
		Confidence:  score,
		Summary:     "connections failed at the socket level across the capture",
		Supporting:  sup, Contradicting: contra, MissingEvidence: cc.missing, Attributes: cc.attributes,
	}
	return cc.scope(match)
}

type pathDisconnect struct {
	at     time.Time
	change stateChange
	key    connKey
}

// pathEvidence counts mid-capture disconnects that were not replaced, short
// incomplete SYN attempts, and distinct affected connections. A socket that
// reconnects to the same peer after the disconnect is reported separately as
// reconnect behavior.
//
// peer identity is limited by the bundle privacy policy: conservative-v1
// replaces every local and remote address with "[REDACTED]", so the analyzer
// cannot count distinct peers. the retained remote port is used as the peer
// proxy (a reconnect normally reuses the same service port), and "multiple
// affected" counts distinct sockets, whose inode is preserved.
func pathEvidence(ctx *AnalysisContext) ([]pathDisconnect, int, int, int) {
	connections := ctx.orderedConnections()
	reconnected := 0
	// new sockets per retained peer proxy, for quick replacement lookups.
	latestestablishedbypeer := map[uint16]time.Time{}
	for _, life := range connections {
		if life.Established && life.FirstSeen.After(latestestablishedbypeer[life.Key.RemotePort]) {
			latestestablishedbypeer[life.Key.RemotePort] = life.FirstSeen
		}
	}
	var disconnects []pathDisconnect
	synchurn := 0
	affected := map[connKey]bool{}
	for _, life := range connections {
		change, left := life.leftEstablishedMidCapture()
		if left {
			replaced := latestestablishedbypeer[life.Key.RemotePort].After(life.LastSeen)
			if replaced {
				reconnected++
				continue
			}
			disconnects = append(disconnects, pathDisconnect{at: change.At, change: change, key: life.Key})
			affected[life.Key] = true
		}
		// outbound attempts must be observed absent in the immediately next
		// usable network sample. A pending connection at capture end is not
		// a failed attempt. SYN_RECV is ordinary passive handshake load and
		// provides no equivalent client failure evidence.
		if laststate := life.States[len(life.States)-1].To; laststate == "SYN_SENT" {
			next := life.lastSample + 1
			observedabsent := next < len(ctx.Samples) && ctx.Samples[next].Available[CoverConnections]
			if span := life.LastSeen.Sub(life.FirstSeen); observedabsent && span <= 5*time.Second {
				synchurn++
				affected[life.Key] = true
			}
		}
	}
	return disconnects, synchurn, len(affected), reconnected
}

// ---------------------------------------------------------------------------
// RESOURCE_STARVATION
// ---------------------------------------------------------------------------

const (
	// PSI avg10 percentages (0..100), not fractions. "severe" has to mean
	// severe: a single busy core on a multi-core host produces roughly 10-25%
	// CPU "some" pressure, and even an ordinary compile does, so the old 10%
	// boundary turned routine load into a RESOURCE_STARVATION diagnosis.
	starvationSomeSevere = 50.0
	starvationFullSevere = 20.0
	starvationMinimum    = 5 * time.Second
	wStarvSevere         = 0.45
	wStarvFull           = 0.15
	wStarvSustained      = 0.10
	starvationCap        = 0.80
)

// ResourceStarvationSignature is the fallback rule (3.19): it claims only
// that a resource sat under severe pressure, and names the subtype, without
// asserting a root cause. A missing pressure sensor is UNKNOWN, never a
// quiet system.
type ResourceStarvationSignature struct{}

func (ResourceStarvationSignature) ID() SignatureID { return SignatureStarvation }
func (ResourceStarvationSignature) Description() string {
	return "fallback: severe sustained system pressure without a more specific cause"
}

func (s ResourceStarvationSignature) Analyze(ctx *AnalysisContext) SignatureMatch {
	cc := newConfidence()
	if !ctx.coverageOK(CoverPressure) {
		return notMatched(SignatureStarvation, "pressure telemetry was unavailable for most of the capture")
	}
	if len(ctx.Pressure) == 0 {
		return notMatched(SignatureStarvation, "no pressure telemetry was recorded")
	}

	resource, some, full := starvationCandidate(ctx)
	if resource == "" {
		return notMatched(SignatureStarvation, "no resource pressure reached the severe boundary")
	}
	cc.support(Evidence{Code: CodePsiSomeExhausted, Source: SourcePressure, At: some.at, Weight: wStarvSevere,
		Observed: some.value, Threshold: starvationSomeSevere})
	cc.attr("resource", string(resource))
	if full.has {
		cc.support(Evidence{Code: CodePsiFullStalled, Source: SourcePressure, At: full.at, Weight: wStarvFull,
			Observed: full.value, Threshold: starvationFullSevere})
	}
	sustained := ctx.PressureSustained(resource, false, starvationSomeSevere)
	if sustained >= starvationMinimum {
		cc.support(Evidence{Code: CodePsiSustained, Source: SourcePressure, At: ctx.End, Weight: wStarvSustained,
			Observed: sustained.Milliseconds(), Threshold: starvationMinimum.Milliseconds()})
	}

	score, sup, contra := cc.score(starvationCap)
	rejected := ""
	if sustained < starvationMinimum {
		rejected = "severe pressure was observed but did not sustain the required span"
	}
	return SignatureMatch{
		SignatureID: SignatureStarvation,
		Rejected:    rejected,
		Confidence:  score,
		Summary:     "severe sustained system pressure observed",
		Supporting:  sup, Contradicting: contra, MissingEvidence: cc.missing, Attributes: cc.attributes,
	}
}

type starvationReading struct {
	has   bool
	value float64
	at    time.Time
}

func starvationReadingFor(series []pressureSample, threshold float64) starvationReading {
	var out starvationReading
	for _, s := range series {
		if s.SomeHas && s.Some >= threshold && (!out.has || s.Some > out.value) {
			out.has, out.value, out.at = true, s.Some, s.At
		}
	}
	return out
}

func fullReadingFor(series []pressureSample, threshold float64) starvationReading {
	var out starvationReading
	for _, s := range series {
		if s.FullHas && s.Full >= threshold && (!out.has || s.Full > out.value) {
			out.has, out.value, out.at = true, s.Full, s.At
		}
	}
	return out
}

// starvationCandidate picks the resource with the highest severe some
// pressure; resource ties break on the fixed CPU/memory/IO order.
func starvationCandidate(ctx *AnalysisContext) (platform.Resource, starvationReading, starvationReading) {
	var zero platform.Resource
	var some, full starvationReading
	candidates := []platform.Resource{platform.PressureCPU, platform.PressureMemory, platform.PressureIO}
	for _, resource := range candidates {
		if !ctx.coverageOK(CoverPressure) {
			continue
		}
		r := starvationReadingFor(ctx.Pressure[resource], starvationSomeSevere)
		if !r.has {
			continue
		}
		if !some.has || r.value > some.value {
			resource0, some0, full0 := resource, r, fullReadingFor(ctx.Pressure[resource], starvationFullSevere)
			zero, some, full = resource0, some0, full0
		}
	}
	return zero, some, full
}
