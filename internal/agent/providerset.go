package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"runopsy/internal/collector"
	"runopsy/internal/incident"
	"runopsy/internal/provider"
	"runopsy/internal/provider/evidence"
)

// ProviderOptions configure the provider wiring for `start` (phase 5 §4.1).
type ProviderOptions struct {
	// StateDir holds the provider salt (never exported).
	StateDir string
	// privacy is the privacy level provider sections are redacted to;
	// empty means conservative.
	Privacy evidence.PrivacyLevel
	// registered mirrors provider.Default.
	Registered *provider.Registry
	// SupervisorPIDs is the manual --github-runner-pid override (5.2).
	SupervisorPIDs []int
	// ReDiscover bounds re-discovery attempts after a supervisor exits.
	ReDiscover bool
}

// ProviderSet owns the supervisors of every registered provider detected on
// this host. it satisfies incident.ProviderSupervisor via each supervisor's
// Name/Freeze pair, feeds snapshots without blocking, and shuts down
// bounded. nothing here can fail recording: a panic, error, hang or backlog
// becomes section health inside provider.Supervisor.
type ProviderSet struct {
	privacy   evidence.PrivacyLevel
	host      provider.HostView
	supervers []*provider.Supervisor
	logger    *slog.Logger
}

// DetectAndStart detects providers (bounded per provider) and starts
// supervisors for the ones present. an empty registry is a no-op: the agent
// behaves identically with no provider compiled in (§4.1).
func DetectAndStart(ctx context.Context, options ProviderOptions, logger *slog.Logger) (*ProviderSet, error) {
	if options.Registered == nil {
		options.Registered = provider.Default
	}
	if logger == nil {
		logger = slog.Default()
	}
	if options.Privacy == "" {
		options.Privacy = evidence.PrivacyConservative
	}
	host := newHostView(options.StateDir)
	if salts := host.Salt(); len(salts) == 0 {
		logger.Warn("provider salt unavailable; provider identity derivation disabled", "error", host.SaltErr())
	}
	set := &ProviderSet{privacy: options.Privacy, host: host, logger: logger}
	for _, p := range options.Registered.All() {
		detectctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		detection, err := providerSafeDetect(detectctx, p, host)
		cancel()
		if err != nil {
			logger.Warn("provider detection failed", "provider", p.Name(), "error", err)
			continue
		}
		if !detection.Present && len(options.SupervisorPIDs) == 0 {
			continue
		}
		discoverctx, canceldiscover := context.WithTimeout(ctx, 5*time.Second)
		runners, err := providerSafeDiscover(discoverctx, p, host)
		canceldiscover()
		if err != nil {
			runners = nil
			logger.Warn("provider discovery failed", "provider", p.Name(), "error", err)
		}
		config := provider.DefaultSupervisorConfig()
		supervisor := provider.Start(ctx, p, host, provider.AttachOptions{
			Privacy:        options.Privacy,
			Runners:        runners,
			SupervisorPIDs: options.SupervisorPIDs,
			Budget:         provider.DefaultBudget(),
		}, config)
		set.supervers = append(set.supervers, supervisor)
		logger.Info("provider attached", "provider", p.Name(), "runners", len(runners))
	}
	return set, nil
}

// providerSafeDetect keeps a broken provider detect out of the agent.
func providerSafeDetect(ctx context.Context, p provider.Provider, host provider.HostView) (d provider.Detection, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("provider %s: detect panicked", p.Name())
		}
	}()
	return p.Detect(ctx, host)
}

// providerSafeDiscover keeps a broken or hung provider discover out of the
// agent's startup (audit R15: a discover panic used to crash `start`). A
// call that overruns is abandoned; the supervisor then discovers on its own
// inside its guarded Attach.
func providerSafeDiscover(ctx context.Context, p provider.Provider, host provider.HostView) ([]provider.RunnerInstance, error) {
	type result struct {
		runners []provider.RunnerInstance
		err     error
	}
	done := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- result{err: fmt.Errorf("provider %s: discover panicked", p.Name())}
			}
		}()
		runners, err := p.Discover(ctx, host)
		done <- result{runners: runners, err: err}
	}()
	select {
	case r := <-done:
		return r.runners, r.err
	case <-ctx.Done():
		return nil, fmt.Errorf("provider %s: discover timed out", p.Name())
	}
}

// supervisors returns the running supervisors for the capture's freeze hook
// (§3.3). called at capture construction, it is stable for the agent's
// lifetime: supervisors are started once.
func (s *ProviderSet) Supervisors() []incident.ProviderSupervisor {
	if s == nil || len(s.supervers) == 0 {
		return nil
	}
	out := make([]incident.ProviderSupervisor, len(s.supervers))
	for i, sup := range s.supervers {
		out[i] = sup
	}
	return out
}

// observe offers every completed recorder snapshot to every supervisor
// without blocking (§4.3). safe on a nil set.
func (s *ProviderSet) Observe(snapshot collector.Snapshot) {
	if s == nil {
		return
	}
	for _, sup := range s.supervers {
		sup.Offer(snapshot)
	}
}

// ProvidersPresent reports whether any provider supervisor runs.
func (s *ProviderSet) ProvidersPresent() bool {
	return s != nil && len(s.supervers) > 0
}

// close stops every supervisor with a bounded wait; provider code never
// delays the agent's own shutdown by more than the timeout.
func (s *ProviderSet) Close(timeout time.Duration) {
	if s == nil || len(s.supervers) == 0 {
		return
	}
	if timeout < time.Second {
		timeout = 6 * time.Second
	}
	var wg sync.WaitGroup
	for _, sup := range s.supervers {
		wg.Add(1)
		go func(sup *provider.Supervisor) {
			defer wg.Done()
			sup.Close(timeout)
		}(sup)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout + time.Second):
	}
}
