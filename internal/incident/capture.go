package incident

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"deprehendo/internal/collector"
	"deprehendo/internal/provider/evidence"
	"deprehendo/internal/trace"
)

type CaptureState string

const (
	Idle          CaptureState = "IDLE"
	CapturingPost CaptureState = "CAPTURING_POST"
	Finalizing    CaptureState = "FINALIZING"
	Complete      CaptureState = "COMPLETE"
	Failed        CaptureState = "FAILED"
)

type CaptureStatus struct {
	State           CaptureState
	ID, Path, Error string
}
type CaptureOptions struct {
	Window   CaptureWindow
	Metadata Metadata
	Writer   IncidentWriter
	MaxBytes int
	// ProviderSupervisors freeze CI-provider evidence into the capture at
	// finalize time (phase 5 §3.3). each is called at most once per incident;
	// the supervisor guarantees its own bound, and this capture imposes its
	// own deadline on top so a misbehaving provider never delays the write.
	ProviderSupervisors []ProviderSupervisor
	// ProviderFreezeTimeout bounds each provider freeze (default 6 s).
	ProviderFreezeTimeout time.Duration
	// ProviderPrivacy is the privacy level applied to provider sections when
	// the incident is encoded (default conservative).
	ProviderPrivacy evidence.PrivacyLevel
	// TracingSource is consulted once at finalize time to stamp the tracer
	// reliability self-report into the incident (6.48). optional; nil emits
	// a bundle with no tracing section, and a panicking source degrades to
	// the same "no tracer configured" incident rather than failing capture.
	TracingSource func() TraceReliability
	// DedupWindow is the correlation window merge uses to pair a tracer
	// event with the snapshot-differ event describing the same lifecycle
	// observation (6.31). zero takes the shared default; negative is invalid.
	DedupWindow time.Duration
}

// trace buffer bounds (6.27/6.47): a bounded capture must never grow without
// bound no matter how chatty the kernel is. events beyond the bound are
// dropped visibly (incident truncated bit + the reliability section), never
// silently: "the stream was incomplete", not "nothing happened".
const (
	MaxTraceEvents = MaxEvents / 2
	MaxTraceBytes  = MaxPayloadBytes / 8
)

// ProviderSupervisor is the capture's view of one running provider session.
// freeze returns a section that validates and never an error, mirroring
// provider.Supervisor.Freeze.
type ProviderSupervisor interface {
	Name() string
	Freeze(ctx context.Context, from, to time.Time) evidence.Section
}
type retainedSample struct {
	snapshot collector.Snapshot
	bytes    int
	records  int
}

// retainedTrace is one buffered tracer event (6.47): live tracer events are
// held pre-trigger exactly like snapshots, then replayed into the active
// incident at trigger time; post-window events append to activeTrace.
type retainedTrace struct {
	event Event
	ts    time.Time
	bytes int
}

// capture owns its own bounded history so trigger and sample observation have
// one linearization lock. observe must receive every completed recorder sample
// in timestamp order. storage IO never runs under the capture or recorder lock.
type Capture struct {
	mu               sync.Mutex
	options          CaptureOptions
	status           CaptureStatus
	history          []retainedSample
	historyRecords   int
	activeRecords    int
	historyBytes     int
	lastObserved     time.Time
	historyLoss      time.Time
	traceHistory     []retainedTrace
	traceBytes       int
	traceLoss        time.Time
	lastTrace        time.Time
	lastTraceMono    int64
	activeTrace      []Event
	activeTraceBytes int
	traceDropped     uint64
	completed        []CaptureStatus
	active           *Incident
	activeBytes      int
	timer            *time.Timer
	done             chan struct{}
	closed           bool
}

// defaultProviderFreezeTimeout bounds each provider freeze at finalize time.
const defaultProviderFreezeTimeout = 6 * time.Second

func NewCapture(o CaptureOptions) (*Capture, error) {
	if o.Window.PreTrigger < 0 || o.Window.PreTrigger > 24*time.Hour || o.Window.PostTrigger < 0 || o.Window.PostTrigger > time.Hour || o.Writer == nil {
		return nil, fmt.Errorf("incident: invalid capture options")
	}
	if o.MaxBytes == 0 {
		o.MaxBytes = MaxPayloadBytes / 2
	}
	if o.MaxBytes < 1024 || o.MaxBytes > MaxPayloadBytes/2 {
		return nil, fmt.Errorf("incident: invalid capture budget")
	}
	if o.DedupWindow < 0 {
		return nil, fmt.Errorf("incident: invalid dedup window")
	}
	if o.DedupWindow == 0 {
		o.DedupWindow = DefaultDedupWindow
	}
	if o.Metadata.AgentVersion == "" {
		o.Metadata.AgentVersion = AgentVersion
	}
	if o.Metadata.Host.OS == "" {
		o.Metadata.Host = LocalHost()
	}
	// metadata ownership must not alias caller slices.
	m, err := json.Marshal(o.Metadata)
	if err != nil {
		return nil, err
	}
	if len(m) > o.MaxBytes {
		return nil, fmt.Errorf("incident: metadata exceeds budget")
	}
	if err = json.Unmarshal(m, &o.Metadata); err != nil {
		return nil, err
	}
	return &Capture{options: o, status: CaptureStatus{State: Idle}}, nil
}
func (c *Capture) Status() CaptureStatus { c.mu.Lock(); defer c.mu.Unlock(); return c.status }

// StatusFor returns the active result or one of the 16 most recent terminal
// results. A subsequent trigger cannot hide a completed manual request.
func (c *Capture) StatusFor(id string) (CaptureStatus, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if id != "" && c.status.ID == id {
		return c.status, true
	}
	for n := len(c.completed) - 1; n >= 0; n-- {
		if c.completed[n].ID == id {
			return c.completed[n], true
		}
	}
	return CaptureStatus{}, false
}

// window reports the configured pre/post trigger window. it is immutable and
// lets trigger adapters describe capture progress without guessing defaults.
func (c *Capture) Window() CaptureWindow { return c.options.Window }
func (c *Capture) Observe(s collector.Snapshot) {
	records := snapshotRecords(s)
	var raw []byte
	var err error
	if records <= MaxEvidenceRecords/2 {
		raw, err = json.Marshal(s)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || s.Timestamp.IsZero() {
		return
	}
	if !c.lastObserved.IsZero() && !s.Timestamp.After(c.lastObserved) {
		return
	}
	c.lastObserved = s.Timestamp
	if err != nil || len(raw) > c.options.MaxBytes || records > MaxEvidenceRecords/2 {
		c.historyLoss = s.Timestamp
		if c.active != nil {
			c.active.Truncated = true
		}
		return
	}
	var detached collector.Snapshot
	if json.Unmarshal(raw, &detached) != nil {
		return
	}
	cutoff := s.Timestamp.Add(-c.options.Window.PreTrigger)
	for len(c.history) > 0 && (c.history[0].snapshot.Timestamp.Before(cutoff) || c.historyBytes+len(raw) > c.options.MaxBytes || len(c.history) >= MaxSnapshots || c.historyRecords+records > MaxEvidenceRecords/2) {
		if !c.history[0].snapshot.Timestamp.Before(cutoff) && c.history[0].snapshot.Timestamp.After(c.historyLoss) {
			c.historyLoss = c.history[0].snapshot.Timestamp
		}
		c.historyRecords -= c.history[0].records
		c.historyBytes -= c.history[0].bytes
		c.history[0] = retainedSample{}
		c.history = c.history[1:]
	}
	c.history = append(c.history, retainedSample{detached, len(raw), records})
	c.historyBytes += len(raw)
	c.historyRecords += records
	if c.status.State == CapturingPost && !s.Timestamp.Before(c.active.CaptureStart) && !s.Timestamp.After(c.active.CaptureEnd) {
		for len(c.active.Snapshots) > 0 && (c.activeBytes+len(raw) > c.options.MaxBytes || len(c.active.Snapshots) >= MaxSnapshots || c.activeRecords+records > MaxEvidenceRecords/2) {
			old, _ := json.Marshal(c.active.Snapshots[0])
			c.activeBytes -= len(old)
			c.activeRecords -= snapshotRecords(c.active.Snapshots[0])
			c.active.Snapshots[0] = collector.Snapshot{}
			c.active.Snapshots = c.active.Snapshots[1:]
			c.active.Truncated = true
		}
		// active and history are private and never mutated; exported copies belong
		// to the writer only after finalization has detached the active capture.
		c.active.Snapshots = append(c.active.Snapshots, detached)
		c.activeBytes += len(raw)
		c.activeRecords += records
	}
}
func (c *Capture) Trigger(t Trigger) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.status.State == CapturingPost || c.status.State == Finalizing {
		return "", fmt.Errorf("incident: capture unavailable or already active")
	}
	if !validTrigger(t.Type) || t.PID < 0 || t.StartTicks < 0 || len(t.Note) > 1024 || !utf8.ValidString(t.Note) {
		return "", fmt.Errorf("incident: invalid trigger")
	}
	t.Note = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\t' || r == 0x7f {
			return -1
		}
		return r
	}, t.Note)
	id, err := newID()
	if err != nil {
		return "", err
	}
	at := time.Now().UTC()
	start := at.Add(-c.options.Window.PreTrigger)
	i := &Incident{SchemaVersion: SchemaVersion, ID: id, TriggeredAt: at, CaptureStart: start, CaptureEnd: at.Add(c.options.Window.PostTrigger), Window: c.options.Window, Trigger: t, Metadata: c.options.Metadata}
	i.Truncated = !c.historyLoss.IsZero() && !c.historyLoss.Before(start) && !c.historyLoss.After(at)
	if !c.traceLoss.IsZero() && !c.traceLoss.Before(start) && !c.traceLoss.After(at) {
		// A tracer event inside the reported window was refused (bounded
		// buffer, out-of-order delivery): the bundle is truncated evidence
		// for the trace stream too (6.27).
		i.Truncated = true
	}
	c.activeBytes = 0
	c.activeRecords = 0
	for _, v := range c.history {
		if !v.snapshot.Timestamp.Before(start) && !v.snapshot.Timestamp.After(at) {
			i.Snapshots = append(i.Snapshots, v.snapshot)
			c.activeBytes += v.bytes
			c.activeRecords += v.records
		}
	}
	// replay the tracer's pre-trigger window into the active incident; the
	// definitive merge against differ evidence happens once, in finalize.
	for _, t := range c.traceHistory {
		if !t.ts.Before(start) && !t.ts.After(at) {
			c.activeTrace = append(c.activeTrace, t.event)
			c.activeTraceBytes += t.bytes
		}
	}
	c.active = i
	c.done = make(chan struct{})
	c.status = CaptureStatus{State: CapturingPost, ID: id}
	c.timer = time.AfterFunc(c.options.Window.PostTrigger, func() { c.finalize(false) })
	return id, nil
}

// ObserveTrace records one live tracer event (6.27/6.47). delivery must be in
// (wall-ms, monotonic) order (the tracer's own send order) so a regressing
// event is a tracer bug and is dropped with a visible counter, never used to
// re-sort the pre-trigger window. buffering mirrors observe: a bounded ring
// for the next incident's pre-trigger window plus direct appends while an
// incident is in its post-trigger window; everything over the bound is
// visible truncation, and the merge with polling evidence happens once, at
// freeze time, under the §9.1 rules.
func (c *Capture) ObserveTrace(te trace.TraceEvent) {
	ev := FromTrace(te, ProvenanceTrace)
	raw, err := json.Marshal(ev)
	if err != nil {
		ev = Event{} // invalid UTF-8 or similar: count, never panic
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		c.traceDropped++
		return
	}
	notedrop := func() {
		c.traceDropped++
		c.traceLoss = ev.Timestamp
		if c.active != nil {
			c.active.Truncated = true
		}
	}
	// ordering gate (§8): the tracer's monotonic stamp is CLOCK_MONOTONIC (
	// never regressing for the machine's whole uptime) so a strictly
	// smaller reading can only mean an out-of-order or broken sender, and
	// is refused with a visible counter rather than being used to re-sort
	// the pre-trigger window. equal stamps are accepted (coarse clocks can
	// return the same reading twice; freeze-time ordering tie-breaks inside
	// the same millisecond), and wall-clock regressions are tolerated for
	// real (clock steps): freeze-time ordering handles those.
	if ev.MonotonicNs > 0 && c.lastTraceMono > 0 && ev.MonotonicNs < c.lastTraceMono {
		notedrop()
		return
	}
	if ev.MonotonicNs > c.lastTraceMono {
		c.lastTraceMono = ev.MonotonicNs
	}
	if c.lastTrace.IsZero() || ev.Timestamp.After(c.lastTrace) {
		c.lastTrace = ev.Timestamp
	}
	if err != nil || len(raw) > MaxTraceBytes {
		notedrop()
		return
	}
	// evict everything older than the pre-trigger window, exactly like the
	// snapshot history does: the ring holds what the next trigger needs and
	// no more.
	cutoff := ev.Timestamp.Add(-c.options.Window.PreTrigger)
	for len(c.traceHistory) > 0 && c.traceHistory[0].ts.Before(cutoff) {
		c.traceBytes -= c.traceHistory[0].bytes
		c.traceHistory[0] = retainedTrace{}
		c.traceHistory = c.traceHistory[1:]
	}
	if c.traceBytes+len(raw) > MaxTraceBytes || len(c.traceHistory) >= MaxTraceEvents {
		notedrop()
		return
	}
	c.traceHistory = append(c.traceHistory, retainedTrace{event: ev, ts: ev.Timestamp, bytes: len(raw)})
	c.traceBytes += len(raw)
	if c.status.State == CapturingPost && !ev.Timestamp.Before(c.active.CaptureStart) && !ev.Timestamp.After(c.active.CaptureEnd) {
		if c.activeTraceBytes+len(raw) <= MaxTraceBytes && len(c.activeTrace) < MaxTraceEvents {
			c.activeTrace = append(c.activeTrace, ev)
			c.activeTraceBytes += len(raw)
		} else {
			c.active.Truncated = true
			c.traceDropped++
		}
	}
}

// TraceDropped reports how many live tracer events were refused by this
// capture (closed buffer, out-of-order delivery, bounds): the reliability
// section and status surfaces use it to keep “incomplete” from becoming
// “absent” (6.27).
func (c *Capture) TraceDropped() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.traceDropped
}

func (c *Capture) finalize(truncated bool) {
	c.mu.Lock()
	if c.status.State != CapturingPost {
		c.mu.Unlock()
		return
	}
	c.status.State = Finalizing
	i := c.active
	c.active = nil
	now := time.Now().UTC()
	if truncated {
		i.Truncated = true
		if now.Before(i.CaptureEnd) {
			i.CaptureEnd = now
		}
	}
	// the window end is a wall-clock instant, but the timer that closes it runs
	// on the monotonic clock. if the wall clock stepped back during the window,
	// stamping CreatedAt from it alone would put CreatedAt before CaptureEnd and
	// the bundle would fail its own validation. never stamp before the window end.
	if now.Before(i.CaptureEnd) {
		now = i.CaptureEnd
	}
	i.CreatedAt = now
	if c.options.TracingSource != nil {
		if t, perr := safeTraceReport(c.options.TracingSource); perr == nil {
			// the capture's own refusals are this recorder's share of the
			// honesty report (6.27): the tracer's wire losses and the
			// capture's window/bounds refusals are counted separately.
			t.CaptureLost = c.traceDropped
			i.Tracing = &t
		}
	}
	// cancellation can shorten the window after a completed sample carrying a
	// later source timestamp. keep the exported evidence within its boundary.
	for len(i.Snapshots) > 0 && i.Snapshots[len(i.Snapshots)-1].Timestamp.After(i.CaptureEnd) {
		i.Snapshots[len(i.Snapshots)-1] = collector.Snapshot{}
		i.Snapshots = i.Snapshots[:len(i.Snapshots)-1]
		i.Truncated = true
	}
	done := c.done
	c.mu.Unlock()
	// A stalled collector may complete later; capture closes on its deadline,
	// never waits for an unbounded collector or fabricates a final sample.
	err := attachProviders(i, c.options)
	if err == nil {
		err = deriveEvidence(i)
	}
	// 6.29–6.31: unify the polling-derived stream with the tracer stream
	// under the §9.1 rules. the trace copy owns duplicated lifecycle
	// entries, differ evidence survives as corroboration, weak evidence is
	// never deleted.
	if err == nil && len(c.activeTrace) > 0 {
		merged := Merge(i.Events, c.activeTrace, c.options.DedupWindow)
		if len(merged) > MaxEvents {
			merged = merged[:MaxEvents]
			i.Truncated = true
		}
		i.Events = merged
	}
	c.activeTrace = nil
	c.activeTraceBytes = 0
	// A new private incident copy prevents a writer from altering history.
	var detached *Incident
	if err == nil {
		detached, err = clone(i)
	}
	path := ""
	if err == nil {
		path, err = c.options.Writer.Write(context.Background(), detached)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status.Path = path
	if err != nil {
		c.status.State = Failed
		c.status.Error = err.Error()
		if len(c.status.Error) > 4096 {
			c.status.Error = c.status.Error[:4096]
		}
	} else {
		c.status.State = Complete
	}
	c.completed = append(c.completed, c.status)
	if len(c.completed) > 16 {
		copy(c.completed, c.completed[len(c.completed)-16:])
		c.completed = c.completed[:16]
	}
	close(done)
}

// close stops new samples/triggers and finalizes a marked partial post-window.
// its context bounds waiting, not the durable write; callers can wait again.
func (c *Capture) Close(ctx context.Context) error {
	c.mu.Lock()
	c.closed = true
	active := c.status.State == CapturingPost
	if c.timer != nil {
		c.timer.Stop()
	}
	done := c.done
	c.mu.Unlock()
	if active {
		go c.finalize(true)
	}
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	status := c.Status()
	if status.State == Failed {
		return fmt.Errorf("incident: %s", status.Error)
	}
	return nil
}

func snapshotRecords(s collector.Snapshot) int {
	return 1 + len(s.Processes) + len(s.Connections) + len(s.Metrics) + len(s.Errors)
}

// safeTraceReport isolates the reliability supplier from the capture: a bad
// source is a missing tracing section, never a failed write (6.48's mirror
// of the provider-freeze degradation rule).
func safeTraceReport(source func() TraceReliability) (t TraceReliability, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("recover: tracing report")
		}
	}()
	return source(), nil
}

// attachProviders freezes each running provider session for the capture
// window and stores the resulting sections (phase 5 §3.3). it runs before
// deriveEvidence because provider sections share the bundle's payload budget.
// A provider that cannot answer in time becomes an UNAVAILABLE section with
// the timeout reason; it never delays or fails the capture.
func attachProviders(i *Incident, o CaptureOptions) error {
	if len(o.ProviderSupervisors) == 0 {
		return nil
	}
	timeout := o.ProviderFreezeTimeout
	if timeout <= 0 {
		timeout = defaultProviderFreezeTimeout
	}
	privacy := o.ProviderPrivacy
	if privacy == "" {
		privacy = evidence.PrivacyConservative
	}
	sections := make([]evidence.Section, 0, len(o.ProviderSupervisors))
	for _, sup := range o.ProviderSupervisors {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		section := sup.Freeze(ctx, i.CaptureStart, i.CaptureEnd)
		cancel()
		if section.Provider == "" {
			section.Provider = sup.Name()
		}
		if section.Health.State == "" {
			section.Health.State = evidence.HealthUnavailable
		}
		// the capture redacts at the configured level too (§3.3). the provider
		// supervisor applied its own level at freeze time; this is belt-and-
		// braces, and it makes the recorded privacy level authoritative even
		// if a session forgets to redact.
		if section.Privacy == "" {
			section.Privacy = privacy
		}
		section.Redact(section.Privacy)
		sections = append(sections, section)
	}
	fitProviderSections(i, sections)
	return nil
}

// fitProviderSections trims frozen provider evidence into the bundle's
// payload budget: biggest sections first, replacing the ones that no longer
// fit with UNAVAILABLE markers, then restoring provider-name order so two
// captures from the same evidence compare equal.
func fitProviderSections(i *Incident, sections []evidence.Section) {
	sort.Slice(sections, func(a, b int) bool { return len(sectionJSON(sections[a])) > len(sectionJSON(sections[b])) })
	base, err := json.Marshal(i)
	if err != nil {
		i.Providers = []evidence.Section{evidence.Unavailable("unknown", evidence.ReasonInternalError)}
		return
	}
	budget := MaxPayloadBytes - len(base) - 2048
	if budget < 0 {
		budget = 0
	}
	out := make([]evidence.Section, 0, len(sections))
	for _, section := range sections {
		size := len(sectionJSON(section))
		if size <= budget {
			budget -= size
			out = append(out, section)
			continue
		}
		fallback := evidence.Unavailable(section.Provider, evidence.ReasonInternalError)
		out = append(out, fallback)
		if next := budget - len(sectionJSON(fallback)); next >= 0 {
			budget = next
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Provider < out[b].Provider })
	i.Providers = out
}

func sectionJSON(s evidence.Section) []byte {
	data, err := json.Marshal(s)
	if err != nil {
		return []byte("null")
	}
	return data
}

// derived records share the archive's payload and record limits with snapshots.
// reserve the trigger first, then keep a bounded factual timeline/identity list.
func deriveEvidence(i *Incident) error {
	i.Metadata.Processes = nil
	i.Events = []Event{{Timestamp: i.TriggeredAt, Type: IncidentTriggered, PID: i.Trigger.PID, StartTicks: i.Trigger.StartTicks}}
	base, err := json.Marshal(i)
	if err != nil {
		return err
	}
	remainingbytes := MaxPayloadBytes - len(base) - 1024
	remainingrecords := MaxEvidenceRecords - 1
	for _, s := range i.Snapshots {
		remainingrecords -= snapshotRecords(s)
	}
	var differ Differ
	for _, s := range i.Snapshots {
		for _, event := range differ.Observe(s) {
			raw, err := json.Marshal(event)
			if err != nil {
				return err
			}
			if len(i.Events) >= MaxEvents || remainingrecords <= 0 || len(raw)+1 > remainingbytes {
				i.Truncated = true
				continue
			}
			i.Events = append(i.Events, event)
			remainingbytes -= len(raw) + 1
			remainingrecords--
		}
	}
	sort.SliceStable(i.Events, func(a, b int) bool { return i.Events[a].Timestamp.Before(i.Events[b].Timestamp) })
	seen := map[identity]bool{}
	for _, s := range i.Snapshots {
		for _, p := range s.Processes {
			key := identity{p.PID, p.StartTicks}
			if seen[key] {
				continue
			}
			seen[key] = true
			metadata := ProcessMetadata{p.PID, p.PPID, p.PGID, p.SID, p.StartTicks, p.Name}
			raw, err := json.Marshal(metadata)
			if err != nil {
				return err
			}
			if len(i.Metadata.Processes) >= MaxEvents || remainingrecords <= 0 || len(raw)+1 > remainingbytes {
				i.Truncated = true
				continue
			}
			i.Metadata.Processes = append(i.Metadata.Processes, metadata)
			remainingbytes -= len(raw) + 1
			remainingrecords--
		}
	}
	return nil
}
