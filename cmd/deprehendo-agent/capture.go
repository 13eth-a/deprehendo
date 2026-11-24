package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"deprehendo/internal/agent"
	"deprehendo/internal/incident"
	"deprehendo/internal/provider/evidence"
)

// defaultIncidentDir resolves ~/.deprehendo/incidents, returning empty when the
// user's home directory is unavailable so flag validation can report it.
func defaultIncidentDir() string {
	dir, err := incident.DefaultDir()
	if err != nil {
		return ""
	}
	return dir
}

// captureSettings is the validated incident-capture configuration for start.
type captureSettings struct {
	Directory           string
	Pre                 time.Duration
	Post                time.Duration
	Retention           incident.RetentionPolicy
	OnStop              bool
	OnExit              bool
	Memory              float64
	DiskFree            float64
	Threshold           time.Duration
	ProviderSupervisors []incident.ProviderSupervisor
	ProviderPrivacy     evidence.PrivacyLevel
	// TracingSource, when set, is consulted at finalize time for the tracer's
	// reliability report (6.48). nil means "no tracer in this process", which
	// readers treat as an older bundle with no tracing section.
	TracingSource func() incident.TraceReliability
}

func describeRetention(maxIncidents int, maxAge time.Duration) string {
	parts := []string{"count limit off"}
	if maxIncidents > 0 {
		parts[0] = fmt.Sprintf("max %d bundles", maxIncidents)
	}
	if maxAge > 0 {
		parts = append(parts, fmt.Sprintf("max age %s", maxAge))
	} else {
		parts = append(parts, "age limit off")
	}
	return strings.Join(parts, ", ")
}

func describeTriggers(onStop, onExit bool, memory, diskFree float64, duration time.Duration) string {
	var parts []string
	if memory > 0 {
		parts = append(parts, fmt.Sprintf("memory >= %g%% for %s", memory, duration))
	}
	if diskFree > 0 {
		parts = append(parts, fmt.Sprintf("disk free <= %g%% for %s", diskFree, duration))
	}
	if onStop {
		parts = append(parts, "watched process stopped")
	}
	if onExit {
		parts = append(parts, "watched process exited")
	}
	if len(parts) == 0 {
		return "none (manual only)"
	}
	return strings.Join(parts, ", ")
}

// pruningWriter persists a bundle and then applies retention. retention is
// best-effort: a prune failure never turns a successful save into an incident
// failure, and an existing artifact is never overwritten.
type pruningWriter struct {
	inner  incident.FileWriter
	dir    string
	policy incident.RetentionPolicy
	logger *slog.Logger
}

func (w pruningWriter) Write(ctx context.Context, i *incident.Incident) (string, error) {
	path, err := w.inner.Write(ctx, i)
	if err != nil {
		return path, err
	}
	result, perr := incident.Prune(w.dir, w.policy, time.Now())
	if perr != nil {
		w.logger.Warn("incident retention incomplete", "error", perr, "removed", len(result.Removed))
	} else if len(result.Removed) > 0 {
		w.logger.Info("incident retention pruned bundles", "removed", len(result.Removed))
	}
	return path, nil
}

// setupIncidentCapture creates the private directory, clears only abandoned
// temp files, applies retention once before writing starts, and builds the
// capture plus its factual trigger rules.
func setupIncidentCapture(settings captureSettings, logger *slog.Logger) (*incident.Capture, *agent.IncidentPipeline, error) {
	if err := incident.EnsureDir(settings.Directory); err != nil {
		return nil, nil, err
	}
	if removed, err := incident.CleanupStaleTemps(settings.Directory, time.Now().Add(-time.Hour)); err != nil {
		logger.Warn("incident temp cleanup incomplete", "error", err, "removed", removed)
	} else if removed > 0 {
		logger.Info("incident temp cleanup", "removed", removed)
	}
	if result, err := incident.Prune(settings.Directory, settings.Retention, time.Now()); err != nil {
		logger.Warn("incident retention incomplete", "error", err, "removed", len(result.Removed))
	} else if len(result.Removed) > 0 {
		logger.Info("incident retention pruned bundles", "removed", len(result.Removed))
	}

	capture, err := incident.NewCapture(incident.CaptureOptions{
		Window: incident.CaptureWindow{PreTrigger: settings.Pre, PostTrigger: settings.Post},
		Writer: pruningWriter{
			inner:  incident.FileWriter{Directory: settings.Directory},
			dir:    settings.Directory,
			policy: settings.Retention,
			logger: logger,
		},
		ProviderSupervisors: settings.ProviderSupervisors,
		ProviderPrivacy:     settings.ProviderPrivacy,
		TracingSource:       settings.TracingSource,
	})
	if err != nil {
		return nil, nil, err
	}
	var rules []incident.SnapshotRule
	if settings.Memory > 0 || settings.DiskFree > 0 {
		rule := &incident.ResourceRules{}
		if settings.Memory > 0 {
			rule.Memory = &incident.ThresholdRule{Value: settings.Memory, Duration: settings.Threshold}
		}
		if settings.DiskFree > 0 {
			rule.DiskFree = &incident.ThresholdRule{Value: settings.DiskFree, Duration: settings.Threshold}
		}
		rules = append(rules, rule)
	}
	if settings.OnStop {
		rules = append(rules, &incident.StoppedProcessRule{Enabled: true})
	}
	if settings.OnExit {
		rules = append(rules, &incident.WatchedProcessExitRule{Enabled: true})
	}
	return capture, agent.NewIncidentPipeline(capture, logger, rules...), nil
}

// only one agent may apply cleanup/retention in an incident directory.
// keep the lock inode in place after unlocking; removing it allows two
// processes to hold locks on different inodes with the same path.
func lockIncidentDirectory(directory string) (func(), error) {
	if err := incident.EnsureDir(directory); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(directory, ".deprehendo.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("incident directory is already in use: %w", err)
	}
	return func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN); _ = file.Close() }, nil
}
