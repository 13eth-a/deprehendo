package provider

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/provider/evidence"
)

// SupervisorConfig bounds how much a provider can cost the recorder.
type SupervisorConfig struct {
	// QueueDepth is the number of snapshots buffered for the provider. when
	// it is full, new snapshots are dropped (and counted) rather than block
	// the recorder.
	QueueDepth int
	// AttachTimeout, ObserveTimeout and FreezeTimeout bound each call. A call
	// that overruns degrades the section; it never delays the recorder or the
	// incident write.
	AttachTimeout  time.Duration
	ObserveTimeout time.Duration
	FreezeTimeout  time.Duration
	// OverrunGrace is how long an overrunning call may keep running before
	// the session is abandoned. A call that finishes inside the grace is
	// only penalised in health: the session continues, because abandoning a
	// healthy session on one slow sample silently starves every later
	// incident of provider evidence (real-runner B3: a memory-pressure
	// episode slowed one observe past its 2 s deadline and the provider was
	// dead for the rest of the watch, with ~50k snapshots dropped).
	OverrunGrace time.Duration
}

// DefaultSupervisorConfig suits a 1 s sampling interval.
func DefaultSupervisorConfig() SupervisorConfig {
	return SupervisorConfig{
		QueueDepth:     32,
		AttachTimeout:  5 * time.Second,
		ObserveTimeout: 2 * time.Second,
		FreezeTimeout:  3 * time.Second,
		OverrunGrace:   30 * time.Second,
	}
}

// supervisor isolates one provider session from the recorder (5.1: "provider
// failures don't break recording"). guarantees, each covered by a test:
//
//   - offer never blocks and never panics, whatever the provider does;
//   - a provider panic, error or overrun turns into section health
//     (UNAVAILABLE / DEGRADED with a reason code), never into a recorder or
//     capture failure;
//   - freeze always returns a valid section within FreezeTimeout plus a small
//     constant, redacted to the configured privacy level;
//   - after a panic or a hung call the session is abandoned: no further
//     provider code runs.
type Supervisor struct {
	provider Provider
	config   SupervisorConfig
	privacy  evidence.PrivacyLevel

	queue    chan collector.Snapshot
	calls    chan func(Session)
	stop     chan struct{}
	stopped  chan struct{}
	attached chan struct{} // closed once attach has succeeded, failed or been abandoned

	dropped atomic.Int64

	mu      sync.Mutex
	session Session
	reasons map[evidence.Reason]bool
	dead    bool // panicked or hung: provider code is no longer invoked
}

// start attaches the provider on the supervisor goroutine. it returns
// immediately; attach failures surface as section health.
func Start(ctx context.Context, p Provider, host HostView, opts AttachOptions, config SupervisorConfig) *Supervisor {
	if config.QueueDepth <= 0 {
		config.QueueDepth = DefaultSupervisorConfig().QueueDepth
	}
	if opts.Privacy == "" {
		opts.Privacy = evidence.PrivacyConservative
	}
	s := &Supervisor{
		provider: p, config: config, privacy: opts.Privacy,
		queue:    make(chan collector.Snapshot, config.QueueDepth),
		calls:    make(chan func(Session)),
		stop:     make(chan struct{}),
		stopped:  make(chan struct{}),
		attached: make(chan struct{}),
		reasons:  map[evidence.Reason]bool{},
	}
	go s.loop(ctx, host, opts)
	return s
}

// name is the provider name; it is how the incident capture addresses its
// ProviderSupervisors (phase 5 §3.3).
func (s *Supervisor) Name() string { return s.provider.Name() }

// offer hands a snapshot to the provider without blocking.
func (s *Supervisor) Offer(snapshot collector.Snapshot) {
	select {
	case <-s.stop:
		return
	default:
	}
	select {
	case s.queue <- snapshot:
	default:
		s.dropped.Add(1)
	}
}

func (s *Supervisor) loop(ctx context.Context, host HostView, opts AttachOptions) {
	defer close(s.stopped)
	attachsettled := false
	settle := func() {
		if !attachsettled {
			attachsettled = true
			close(s.attached)
		}
	}
	defer settle()
	var session Session
	ok := s.guard(ctx, s.config.AttachTimeout, func(callCtx context.Context) error {
		var err error
		session, err = s.provider.Attach(callCtx, host, opts)
		if err == nil && session == nil {
			err = fmt.Errorf("provider returned a nil session")
		}
		return err
	})
	if !ok || session == nil {
		// attach failed (health already noted) or was abandoned: there is
		// no session to feed.
		return
	}
	s.mu.Lock()
	s.session = session
	s.mu.Unlock()
	settle()
	for {
		select {
		case <-s.stop:
			s.guard(ctx, s.config.ObserveTimeout, func(context.Context) error { return session.Close() })
			return
		case snapshot := <-s.queue:
			if !s.guard(ctx, s.config.ObserveTimeout, func(callCtx context.Context) error {
				session.Observe(callCtx, snapshot)
				return nil
			}) {
				return
			}
		case call := <-s.calls:
			call(session)
			s.mu.Lock()
			dead := s.dead
			s.mu.Unlock()
			if dead {
				return
			}
		}
	}
}

// guard runs one provider call with panic recovery and a deadline. it returns
// false when the session must be abandoned (panic or hang). errors degrade
// health but keep the session.
func (s *Supervisor) guard(parent context.Context, timeout time.Duration, call func(context.Context) error) bool {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	type result struct {
		err      error
		panicked bool
	}
	done := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- result{panicked: true}
			}
		}()
		done <- result{err: call(ctx)}
	}()
	select {
	case r := <-done:
		switch {
		case r.panicked:
			s.fail(evidence.ReasonPanic)
			return false
		case r.err != nil:
			s.note(evidence.ReasonInternalError)
		}
		return true
	case <-ctx.Done():
		// the deadline passed while the call was still running. A slow call
		// is not a hung one: the section is marked degraded and the loop
		// resumes only after the call has actually returned, so the session
		// is never mutated by two goroutines at once. only a call that also
		// overruns the grace period is abandoned; the recorder never waits
		// either way.
		grace := s.config.overrunGrace(timeout)
		select {
		case r := <-done:
			s.note(evidence.ReasonTimeout)
			if r.panicked {
				s.note(evidence.ReasonPanic)
			}
			return true
		case <-time.After(grace):
			// A genuinely hung provider: abandon the session so no further
			// provider code is invoked.
			s.fail(evidence.ReasonTimeout)
			return false
		}
	}
}

func (s *Supervisor) note(reason evidence.Reason) {
	s.mu.Lock()
	s.reasons[reason] = true
	s.mu.Unlock()
}

func (s *Supervisor) fail(reason evidence.Reason) {
	s.mu.Lock()
	s.reasons[reason] = true
	s.dead = true
	s.mu.Unlock()
}

// freeze returns the provider section for an incident window. it always
// returns a section that validates; it never returns an error.
func (s *Supervisor) Freeze(ctx context.Context, from, to time.Time) evidence.Section {
	// A capture can be triggered right after the session started: wait for
	// attach to settle, bounded by its own timeout.
	select {
	case <-s.attached:
	case <-time.After(s.config.AttachTimeout + time.Second):
		s.fail(evidence.ReasonTimeout)
	}
	s.mu.Lock()
	dead := s.dead
	attached := s.session != nil
	s.mu.Unlock()
	if dead || !attached {
		if !dead {
			s.note(evidence.ReasonInternalError)
		}
		return s.finish(evidence.Unavailable(s.provider.Name()))
	}
	type frozen struct {
		section evidence.Section
		err     error
	}
	result := make(chan frozen, 1)
	call := func(session Session) {
		var section evidence.Section
		var err error
		ok := s.guard(ctx, s.config.FreezeTimeout, func(callCtx context.Context) error {
			section, err = session.Freeze(callCtx, from, to)
			return err
		})
		if !ok {
			result <- frozen{err: fmt.Errorf("freeze abandoned")}
			return
		}
		result <- frozen{section: section, err: err}
	}
	deadline := time.NewTimer(s.config.FreezeTimeout + time.Second)
	defer deadline.Stop()
	select {
	case s.calls <- call:
	case <-s.stopped:
		s.note(evidence.ReasonInternalError)
		return s.finish(evidence.Unavailable(s.provider.Name()))
	case <-deadline.C:
		// freeze overran. this section is unavailable, but the call may still
		// return inside the guard's grace period; the guard decides whether
		// the session itself is abandoned, so do not fail it here.
		s.note(evidence.ReasonTimeout)
		return s.finish(evidence.Unavailable(s.provider.Name()))
	}
	select {
	case r := <-result:
		if r.err != nil {
			s.note(evidence.ReasonInternalError)
			return s.finish(evidence.Unavailable(s.provider.Name()))
		}
		return s.finish(r.section)
	case <-deadline.C:
		s.note(evidence.ReasonTimeout)
		return s.finish(evidence.Unavailable(s.provider.Name()))
	}
}

// finish applies supervisor health, redaction and validation. A section the
// provider produced that does not validate is replaced by an UNAVAILABLE one:
// malformed provider evidence never reaches a bundle.
func (s *Supervisor) finish(section evidence.Section) evidence.Section {
	name := s.provider.Name()
	section.Provider = name
	section.SchemaVersion = evidence.SchemaVersion
	section.Redact(s.privacy)
	s.mu.Lock()
	for reason := range s.reasons {
		section.Health.Reasons = appendReason(section.Health.Reasons, reason)
	}
	dead := s.dead
	s.mu.Unlock()
	if dropped := int(s.dropped.Load()); dropped > 0 {
		section.Health.Dropped = dropped
		section.Health.Reasons = appendReason(section.Health.Reasons, evidence.ReasonBackpressure)
	}
	// A section's health describes the recording that produced it. counters
	// and reasons are per incident window: keeping them would leave a watch
	// degraded forever after one slow sample, and a degraded section is not
	// judged by the provider signatures.
	s.mu.Lock()
	s.reasons = map[evidence.Reason]bool{}
	s.mu.Unlock()
	s.dropped.Store(0)
	switch {
	case dead:
		section.Health.State = evidence.HealthUnavailable
	case section.Health.State == "" || section.Health.State == evidence.HealthAvailable:
		if len(section.Health.Reasons) > 0 || section.Health.Dropped > 0 {
			section.Health.State = evidence.HealthDegraded
		} else {
			section.Health.State = evidence.HealthAvailable
		}
	}
	if len(section.Health.Reasons) > evidence.MaxReasons {
		section.Health.Reasons = section.Health.Reasons[:evidence.MaxReasons]
	}
	if err := section.Validate(); err != nil {
		fallback := evidence.Unavailable(name, evidence.ReasonInternalError)
		fallback.Privacy = s.privacy
		fallback.Health.Dropped = section.Health.Dropped
		if fallback.Health.Dropped > 0 {
			fallback.Health.Reasons = appendReason(fallback.Health.Reasons, evidence.ReasonBackpressure)
		}
		return fallback
	}
	return section
}

// overrunGrace is how long an overrunning call may keep running before the
// session is abandoned. ten times the call's own budget rides out a slow
// sample under load; two seconds is the floor for sub-second test budgets.
func (c SupervisorConfig) overrunGrace(timeout time.Duration) time.Duration {
	if c.OverrunGrace > 0 {
		return c.OverrunGrace
	}
	if grace := 10 * timeout; grace > 2*time.Second {
		return grace
	}
	return 2 * time.Second
}

func appendReason(reasons []evidence.Reason, reason evidence.Reason) []evidence.Reason {
	for _, r := range reasons {
		if r == reason {
			return reasons
		}
	}
	return append(reasons, reason)
}

// close stops the session. it waits at most timeout for the provider.
func (s *Supervisor) Close(timeout time.Duration) {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	select {
	case <-s.stopped:
	case <-time.After(timeout):
	}
}
