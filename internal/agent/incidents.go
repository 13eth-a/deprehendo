package agent

import (
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/incident"
)

// IncidentPipeline connects completed recorder samples to one capture and to
// factual trigger rules. observe must be called from the recorder's single
// sampling goroutine; persistence and event derivation stay asynchronous.
type IncidentPipeline struct {
	Capture *incident.Capture
	Rules   []incident.SnapshotRule
	Logger  *slog.Logger
	// OnSaved, when set, is called once per complete incident with its id and
	// bundle path, after the bundle is on disk. it is how phase 7's optional
	// auto-upload learns about a new incident (7.46); it must not block the
	// recording and must not be able to fail the save.
	OnSaved func(id, path string)

	stop      chan struct{}
	closeOnce sync.Once
}

// NewIncidentPipeline builds a pipeline. A nil logger discards trigger/persist
// messages, which is useful for tests and embedded use.
func NewIncidentPipeline(capture *incident.Capture, logger *slog.Logger, rules ...incident.SnapshotRule) *IncidentPipeline {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &IncidentPipeline{Capture: capture, Rules: rules, Logger: logger, stop: make(chan struct{})}
}

// observe records the sample for prehistory/post-window capture, then lets each
// rule evaluate it. triggers are requested synchronously (cheap, bounded) and
// saved in the background; a refused trigger is logged, never fatal to sampling.
func (p *IncidentPipeline) Observe(s collector.Snapshot) {
	if p == nil || p.Capture == nil {
		return
	}
	p.Capture.Observe(s)
	for _, rule := range p.Rules {
		if trigger := rule.Observe(s); trigger != nil {
			_, _ = p.Trigger(*trigger)
		}
	}
}

// trigger requests an incident capture. it returns the incident ID when the
// request was accepted; the save continues asynchronously.
func (p *IncidentPipeline) Trigger(t incident.Trigger) (string, error) {
	if p == nil || p.Capture == nil {
		return "", fmt.Errorf("agent: no incident capture configured")
	}
	id, err := p.Capture.Trigger(t)
	if err != nil {
		p.Logger.Warn("incident trigger refused", "trigger", t.Type, "pid", t.PID, "error", err)
		return "", err
	}
	post := p.Capture.Window().PostTrigger
	p.Logger.Info("incident triggered", "id", id, "trigger", t.Type, "pid", t.PID, "post_window", post)
	go p.reportSaved(id)
	return id, nil
}

// reportSaved logs the terminal outcome once. it polls the capture's small
// status view rather than adding a callback to the storage layer.
func (p *IncidentPipeline) reportSaved(id string) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
		}
		status, ok := p.Capture.StatusFor(id)
		if !ok {
			return
		}
		switch status.State {
		case incident.Complete:
			p.Logger.Info("incident saved", "id", id, "path", status.Path)
			if p.OnSaved != nil && status.Path != "" {
				// local persistence has already happened: a queue or network
				// problem here cannot affect the bundle.
				p.OnSaved(id, status.Path)
			}
			return
		case incident.Failed:
			p.Logger.Error("incident save failed", "id", id, "error", status.Error, "path", status.Path)
			return
		}
	}
}

// close stops background outcome reporting. it does not finalize the capture;
// the caller closes the capture after the recorder has stopped.
func (p *IncidentPipeline) Close() {
	if p == nil {
		return
	}
	p.closeOnce.Do(func() { close(p.stop) })
}
