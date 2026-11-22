// command runopsy-agent provides the foreground phase 1 flight recorder.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"runopsy/internal/agent"
	"runopsy/internal/collector"
	"runopsy/internal/diagnosis"
	"runopsy/internal/incident"
	"runopsy/internal/provider/evidence"
	"runopsy/internal/provider/github"
	"runopsy/internal/trace"
)

const version = incident.AgentVersion

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage())
		return 2
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprintln(stdout, usage())
		return 0
	case "version":
		return runVersion(args[1:], stdout, stderr)
	case "status", "dump":
		return inspect(args[0], args[1:], stdout, stderr)
	case "start":
		return runStart(args[1:], stdout, stderr)
	case "trigger":
		return runTrigger(args[1:], stdout, stderr)
	case "inspect":
		return runInspect(args[1:], stdout, stderr)
	case "incidents":
		return runIncidents(args[1:], stdout, stderr)
	case "validate":
		return runValidate(args[1:], stdout, stderr)
	case "extract":
		return runExtract(args[1:], stdout, stderr)
	case "analyze":
		return runAnalyze(args[1:], stdout, stderr)
	case "timeline":
		return runTimeline(args[1:], stdout, stderr)
	case "evaluate":
		return runEvaluate(args[1:], stdout, stderr)
	case "github":
		return runGitHub(args[1:], stdout, stderr)
	case "trace":
		return runTrace(args[1:], stdout, stderr)
	case "login":
		return runLogin(args[1:], stdout, stderr)
	case "upload":
		return runUpload(args[1:], stdout, stderr)
	case "queue":
		return runQueue(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "runopsy-agent: unknown command %q\n\n%s", args[0], usage())
		return 2
	}
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("runopsy-agent version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "runopsy-agent version: unexpected arguments")
		return 2
	}
	fmt.Fprintf(stdout, "Runopsy Agent %s\nAnalyzer %s\nSignature set %d\n", version, diagnosis.AnalyzerVersion, diagnosis.SignatureSetVersion)
	return 0
}

func dumpSnapshot(stdout, stderr io.Writer) int {
	r, err := agent.New(agent.Options{Interval: time.Second, Capacity: 32})
	if err != nil {
		fmt.Fprintf(stderr, "runopsy-agent: initialize snapshot: %v\n", err)
		return 1
	}
	r.SampleOnce()
	if err := r.Dump(stdout); err != nil {
		fmt.Fprintf(stderr, "runopsy-agent: dump snapshot: %v\n", err)
		return 1
	}
	return 0
}

func runStart(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("runopsy-agent start", flag.ContinueOnError)
	fs.SetOutput(stderr)
	interval := fs.Duration("interval", time.Second, "sampling interval")
	window := fs.Duration("window", 120*time.Second, "rolling buffer duration")
	loglevel := fs.String("log-level", "info", "log level: debug, info, warn, error")
	socket := fs.String("socket", agent.DefaultSocket(), "private control socket path")
	maxbuffer := fs.Int64("max-buffer-mb", 64, "estimated retained snapshot budget in MiB")
	collectprocesses := fs.Bool("collect-processes", true, "collect process metadata")
	collectnetwork := fs.Bool("collect-network", true, "collect TCP sockets and ownership")
	collectpressure := fs.Bool("collect-pressure", true, "collect Linux PSI")
	collectcgroups := fs.Bool("collect-cgroups", true, "collect agent and watched-process cgroups")
	watchFS := fs.String("watch-fs", "/", "filesystem whose capacity is sampled")
	watchpid := fs.Int("watch-pid", 0, "only retain this process and its tree")
	watchname := fs.String("watch-name", "", "only retain processes with this name")
	watchtree := fs.Bool("watch-tree", false, "include descendants of watched processes")
	githubwatch := fs.Bool("github-watch", false, "discover GitHub runners and watch all listener trees")
	githubrunnerpids := fs.String("github-runner-pids", "", "comma-separated Runner.Listener PIDs to attach (default: discover)")
	provideridentifiers := fs.Bool("provider-identifiers", false, "include runner/job identifiers in saved provider evidence")
	incidentdir := fs.String("incident-dir", defaultIncidentDir(), "incident bundle directory (default ~/.runopsy/incidents)")
	cloudconfigpath := fs.String("cloud-config", defaultCloudConfigPath(), "credential file for optional auto-upload")
	capturepre := fs.Duration("capture-pre", 90*time.Second, "pre-trigger evidence window")
	capturepost := fs.Duration("capture-post", 30*time.Second, "post-trigger evidence window")
	maxIncidents := fs.Int("max-incidents", 50, "retained incident bundles (0 disables the count limit)")
	maxincidentage := fs.Duration("max-incident-age", 0, "maximum incident bundle age (0 disables the age limit)")
	triggeronstop := fs.Bool("trigger-on-stop", false, "trigger when a watched process enters a stopped state")
	triggeronexit := fs.Bool("trigger-on-process-exit", false, "trigger when a watched process disappears")
	triggermemory := fs.Float64("trigger-memory-percent", 0, "trigger when host memory use stays at or above this percent (0 disables)")
	triggerdiskfree := fs.Float64("trigger-disk-free-percent", 0, "trigger when disk free stays at or below this percent (0 disables)")
	triggerduration := fs.Duration("trigger-duration", 5*time.Second, "continuous duration required by threshold triggers")
	tracingmode := fs.String("tracing", "", "tracing mode: auto, ebpf, proc or disabled (default $RUNOPSY_TRACING or auto)")
	tracedebugoutput := fs.String("trace-debug-output", "", "record the raw decoded trace stream to this file for replay (debug only, 6.46)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "runopsy-agent: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if *interval <= 0 || *window <= 0 {
		fmt.Fprintln(stderr, "runopsy-agent: --interval and --window must be positive")
		return 2
	}
	if *socket == "" || *maxbuffer < 1 || *maxbuffer > 1024 {
		fmt.Fprintln(stderr, "runopsy-agent: --socket must be nonempty and --max-buffer-mb must be 1..1024")
		return 2
	}
	if *watchpid < 0 {
		fmt.Fprintln(stderr, "runopsy-agent: --watch-pid must be positive")
		return 2
	}
	if *watchFS == "" {
		fmt.Fprintln(stderr, "runopsy-agent: --watch-fs must not be empty")
		return 2
	}
	filter := collector.Filter{Name: *watchname, Descendants: *watchtree}
	var explicitRunnerPIDs []int
	if *githubwatch && (*watchpid != 0 || *watchname != "" || *watchtree) {
		fmt.Fprintln(stderr, "runopsy-agent: --github-watch cannot be combined with --watch-pid, --watch-name, or --watch-tree")
		return 2
	}
	if *watchpid > 0 {
		filter.PIDs = []int{*watchpid}
	}
	if *githubwatch {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		runners, discovererr := (github.GitHubProvider{}).Discover(ctx, agent.NewHostView(agent.DefaultStateDir()))
		cancel()
		if discovererr != nil {
			fmt.Fprintf(stderr, "runopsy-agent: GitHub runner discovery: %v\n", discovererr)
			return 1
		}
		if len(runners) == 0 {
			fmt.Fprintln(stderr, "runopsy-agent: no GitHub Actions runners discovered")
			return 1
		}
		for _, runner := range runners {
			if runner.Supervisor.PID > 0 {
				filter.PIDs = append(filter.PIDs, runner.Supervisor.PID)
			}
		}
		filter.Descendants = true
		explicitRunnerPIDs = make([]int, 0, len(runners))
		for _, runner := range runners {
			if runner.Supervisor.PID > 0 {
				explicitRunnerPIDs = append(explicitRunnerPIDs, runner.Supervisor.PID)
			}
		}
	}
	if *githubrunnerpids != "" {
		pids, parseerr := parsePIDList(*githubrunnerpids)
		if parseerr != nil {
			fmt.Fprintf(stderr, "runopsy-agent: --github-runner-pids: %v\n", parseerr)
			return 2
		}
		for _, pid := range pids {
			if pid < 1 {
				fmt.Fprintln(stderr, "runopsy-agent: GitHub runner PIDs must be positive")
				return 2
			}
			explicitRunnerPIDs = append(explicitRunnerPIDs, pid)
			filter.PIDs = append(filter.PIDs, pid)
		}
		// A runner is only useful to the provider together with the worker
		// and job processes it spawns (5.10), so an explicit listener implies
		// its descendants just like --github-watch does.
		if len(pids) > 0 {
			filter.Descendants = true
		}
	}
	filter.PIDs = uniquePIDs(filter.PIDs)
	if *watchtree && !filter.Active() {
		fmt.Fprintln(stderr, "runopsy-agent: --watch-tree requires --watch-pid or --watch-name")
		return 2
	}
	if *incidentdir == "" {
		fmt.Fprintln(stderr, "runopsy-agent: cannot determine the default incident directory; pass --incident-dir")
		return 2
	}
	if *capturepre < 0 || *capturepre > 24*time.Hour || *capturepost < 0 || *capturepost > time.Hour {
		fmt.Fprintln(stderr, "runopsy-agent: --capture-pre must be 0..24h and --capture-post 0..1h")
		return 2
	}
	if *maxIncidents < 0 || *maxincidentage < 0 {
		fmt.Fprintln(stderr, "runopsy-agent: --max-incidents and --max-incident-age must not be negative")
		return 2
	}
	if math.IsNaN(*triggermemory) || math.IsNaN(*triggerdiskfree) || *triggermemory < 0 || *triggermemory > 100 || *triggerdiskfree < 0 || *triggerdiskfree > 100 {
		fmt.Fprintln(stderr, "runopsy-agent: trigger percentages must be in 0..100 (0 disables)")
		return 2
	}
	if *triggerduration < 0 {
		fmt.Fprintln(stderr, "runopsy-agent: --trigger-duration must not be negative")
		return 2
	}
	// tracing configuration is resolved before anything is started so an
	// invalid mode is a usage error, not a degraded run (6.21).
	tracingcfg, traceerr := traceConfig(*tracingmode, "")
	if traceerr != nil {
		fmt.Fprintf(stderr, "runopsy-agent: %v\n", traceerr)
		return 2
	}
	tracingcfg.DebugOutput = *tracedebugoutput
	if (*triggeronstop || *triggeronexit) && !filter.Active() {
		fmt.Fprintln(stderr, "runopsy-agent: process-exit and stopped-state triggers require --watch-pid or --watch-name")
		return 2
	}
	if (*triggeronstop || *triggeronexit) && !*collectprocesses {
		fmt.Fprintln(stderr, "runopsy-agent: process-exit and stopped-state triggers require process collection")
		return 2
	}
	level, err := parseLogLevel(*loglevel)
	if err != nil {
		fmt.Fprintf(stderr, "runopsy-agent: %v\n", err)
		return 2
	}
	capacity64 := *window / *interval
	if *window%*interval != 0 {
		capacity64++
	}
	maxint := uint64(^uint(0) >> 1)
	if capacity64 < 1 || uint64(capacity64) > maxint {
		fmt.Fprintln(stderr, "runopsy-agent: requested window/interval capacity is not representable")
		return 2
	}
	capacity := int(capacity64)
	const maxSnapshots = 1 << 20 // bounded recorder: reject absurd allocations
	if capacity > maxSnapshots {
		fmt.Fprintf(stderr, "runopsy-agent: --window/--interval would retain %d snapshots; the recorder supports at most %d\n", capacity, maxSnapshots)
		return 2
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	privacy := evidence.PrivacyConservative
	if *provideridentifiers {
		privacy = evidence.PrivacyIdentifiers
	}
	providers, err := agent.DetectAndStart(context.Background(), agent.ProviderOptions{
		StateDir: agent.DefaultStateDir(), Privacy: privacy, SupervisorPIDs: explicitRunnerPIDs,
	}, logger)
	if err != nil {
		logger.Warn("provider setup failed; recording continues without provider enrichment", "error", err)
		providers = nil
	}
	if providers != nil {
		defer providers.Close(6 * time.Second)
	}
	release, err := lockIncidentDirectory(*incidentdir)
	if err != nil {
		logger.Error("incident directory", "error", err)
		return 1
	}
	defer release()
	// the tracer supervisor owns spawning, restart and health (6.38/6.39).
	// creating it does not start anything: an unstartable tracer is a valid,
	// permanently-degraded manager, never an error that costs the recording.
	// it is created after the capture so its event sink can feed the capture
	// directly (6.29/6.47); the reliability section reads it at finalize.
	var tracer *trace.Manager
	var tracedEvents atomic.Uint64
	capture, pipeline, err := setupIncidentCapture(captureSettings{
		Directory:           *incidentdir,
		Pre:                 *capturepre,
		Post:                *capturepost,
		Retention:           incident.RetentionPolicy{MaxIncidents: *maxIncidents, MaxAge: *maxincidentage},
		OnStop:              *triggeronstop,
		OnExit:              *triggeronexit,
		Memory:              *triggermemory,
		DiskFree:            *triggerdiskfree,
		Threshold:           *triggerduration,
		ProviderSupervisors: providerSupervisors(providers),
		ProviderPrivacy:     privacy,
		TracingSource: func() incident.TraceReliability {
			if tracer == nil {
				return incident.TraceReliability{State: "unavailable", Reason: "tracer supervisor never started"}
			}
			return incident.TraceReliabilityFromHealth(tracer.Health())
		},
	}, logger)
	if err != nil {
		logger.Error("initialize incident capture", "error", err)
		return 1
	}
	tracercfg := trace.ManagerConfig{Mode: tracingcfg.Mode, DebugOutput: tracingcfg.DebugOutput}
	// events are decoded in the tracer and handed straight to the capture:
	// ObserveTrace owns the provenance/merge path (6.29–6.31), so the sink
	// must not reenter the manager. the counter is for the shutdown log.
	tracercfg.Events = func(te trace.TraceEvent) {
		tracedEvents.Add(1)
		capture.ObserveTrace(te)
	}
	tracer = trace.NewManager(tracercfg)
	// 6.22/6.23: the desired watch set is exactly what the filter selects:
	// the same processes the bundle records. the rust tracer inherits
	// children of watched PIDs at fork (contract §6) and forgets exits, so
	// short-lived children of the watched tree need no agent round trip.
	watcher := tracer.Watches()
	// each PID is pushed with the start time the snapshot saw, so a PID
	// reused while the tracer restarts is refused instead of adopted
	// (contract §6.3 f, §11.1).
	pushedwatch := make([]trace.Watched, 0, 64)
	syncwatch := func(snap collector.Snapshot) {
		if !filter.Active() {
			return
		}
		ws := make([]trace.Watched, 0, len(snap.Processes))
		for _, p := range snap.Processes {
			if p.PID > 0 {
				ws = append(ws, trace.Watched{PID: uint32(p.PID), StartTicks: p.StartTicks})
			}
		}
		if sameWatchSet(pushedwatch, ws) {
			return
		}
		watcher.SetWatched(ws)
		pushedwatch = append(pushedwatch[:0], ws...)
	}
	runtimeagent, err := agent.New(agent.Options{
		Interval:         *interval,
		Window:           *window,
		MaxHistoryBytes:  *maxbuffer << 20,
		Capacity:         capacity,
		Filter:           filter,
		WatchFS:          *watchFS,
		DisableProcesses: !*collectprocesses,
		DisableNetwork:   !*collectnetwork,
		DisablePressure:  !*collectpressure,
		DisableCgroups:   !*collectcgroups,
		Capture:          capture,
		OnSnapshot: func(snapshot collector.Snapshot) {
			pipeline.Observe(snapshot)
			syncwatch(snapshot)
			if providers != nil {
				providers.Observe(snapshot)
			}
		},
	})
	if err != nil {
		logger.Error("initialize agent", "error", err)
		return 1
	}
	fmt.Fprintf(stdout, "Runopsy Agent %s\nSampling interval: %s\nBuffer window: %s (%d snapshots)\nPlatform: %s/%s\nDisk watch: %s\nLog level: %s\n", version, *interval, *window, capacity, runtime.GOOS, runtime.GOARCH, *watchFS, strings.ToLower(*loglevel))

	fmt.Fprintf(stdout, "Collectors: processes=%t network=%t pressure=%t cgroups=%t\nHistory budget: %d MiB\n", *collectprocesses, *collectnetwork, *collectpressure, *collectcgroups, *maxbuffer)
	if filter.Active() {
		fmt.Fprintf(stdout, "Watching: %s\n", describeFilter(filter))
	}
	fmt.Fprintf(stdout, "Tracing: %s\n", tracingcfg.Mode.Describe())
	if tracingcfg.DebugOutput != "" {
		fmt.Fprintf(stdout, "Trace recording: %s\n", tracingcfg.DebugOutput)
	}
	if tracingcfg.Mode.Enabled() && !filter.Active() {
		logger.Warn("the tracer watch set is empty: without --watch-pid/--watch-name/--watch-tree or --github-watch, no process is watched and the tracer reports nothing (6.22)")
	}
	fmt.Fprintf(stdout, "Incident capture: %s (%s before, %s after)\n", *incidentdir, *capturepre, *capturepost)
	fmt.Fprintf(stdout, "Incident retention: %s\n", describeRetention(*maxIncidents, *maxincidentage))
	fmt.Fprintf(stdout, "Automatic triggers: %s\n", describeTriggers(*triggeronstop, *triggeronexit, *triggermemory, *triggerdiskfree, *triggerduration))
	server, err := runtimeagent.ServeControl(*socket)
	if err != nil {
		logger.Error("control socket", "error", err)
		return 1
	}
	defer server.Close()
	fmt.Fprintf(stdout, "Control socket: %s\n\nRecording...\n", *socket)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 7.46–7.49: automatic upload is opt-in through the credential file's
	// auto_upload field. it only enqueues bundles the capture has already
	// written, so the local incident is never at risk. A configuration
	// problem warns and recording continues without it.
	if hook, hookerr := newAutoUpload(*cloudconfigpath, logger); hookerr != nil {
		logger.Warn("auto-upload unavailable; incidents stay local", "error", hookerr)
	} else if hook != nil {
		pipeline.OnSaved = hook.OnSaved
		logger.Info("auto-upload on", "queue", hook.queue.Path(), "retry_interval", autoUploadInterval)
		go hook.DrainLoop(ctx)
	}

	handlerdone := make(chan struct{})
	go func() { defer close(handlerdone); <-ctx.Done(); stop() }()
	defer func() { stop(); <-handlerdone }()
	// supervise the tracer next to the recorder. the manager degrades to
	// polling-only on its own; nothing about it can abort the recording.
	tracectx, stoptrace := context.WithCancel(ctx)
	tracedone := make(chan struct{})
	go func() { defer close(tracedone); _ = tracer.Run(tracectx) }()
	stoptracing := func() {
		stoptrace()
		tracer.Stop()
		<-tracedone
	}
	defer stoptracing()

	runerr := runtimeagent.Run(ctx)
	// stop the tracer before the capture finalizes, so the bundle's
	// reliability section describes a finished session (6.48).
	stoptracing()
	pipeline.Close()
	closectx, closecancel := context.WithTimeout(context.Background(), 30*time.Second)
	closeerr := capture.Close(closectx)
	closecancel()
	if closeerr != nil {
		logger.Error("incident capture shutdown", "error", closeerr)
	} else if saved := capture.Status(); saved.State == incident.Complete && saved.Path != "" {
		logger.Info("incident saved", "id", saved.ID, "path", saved.Path)
	}
	if runerr != nil && !errors.Is(runerr, context.Canceled) {
		logger.Error("agent stopped", "error", runerr)
		return 1
	}
	status := runtimeagent.Status()
	tracerhealth := tracer.Health()
	logger.Info("tracer",
		"state", tracerhealth.State,
		"reason", tracerhealth.Reason,
		"backend", tracerhealth.Caps.Backend,
		"events", tracedEvents.Load(),
		"events_lost", tracerhealth.Lost,
		"restarts", tracerhealth.Restarts,
		"recorded_events", tracerhealth.RecordedEvents,
		"record_truncated", tracerhealth.RecordTruncated,
	)
	logger.Info("recording stopped",
		"uptime", runtimeagent.Uptime(),
		"samples", status.Samples,
		"collector_errors", status.CollectorErrors,
		"missed_samples", status.MissedSamples,
		"buffer_used", status.BufferUsed,
		"buffer_capacity", status.BufferCapacity,
		"last_sample", status.LastSample,
		"last_duration", status.LastDuration,
		"processes", status.ProcessCount,
		"connections", status.ConnectionCount,
	)
	for name, metric := range status.CollectorMetrics {
		logger.Debug("collector timing", "collector", name, "last", metric.Last, "average", metric.Average, "cycles", metric.Cycles, "errors", metric.Errors)
	}
	fmt.Fprintln(stdout, "Shutdown complete.")
	if closeerr != nil {
		return 1
	}
	return 0
}

func parseLogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid --log-level %q (want debug, info, warn, or error)", s)
	}
}

func usage() string {
	return `Usage:
  runopsy-agent <command> [flags]

Commands:
  start     record snapshots and preserve incidents in the foreground
  status    inspect the running recorder
  trigger   freeze an incident in the running recorder
  inspect   read a saved .runopsy bundle (--timeline, --snapshot, --at, --privacy)
  incidents list saved bundles
  validate  validate a saved .runopsy bundle
  extract   extract verified bundle components
  analyze   diagnose a saved bundle (deterministic signature engine)
  timeline  render normalized events and rule-backed causal reconstruction
  evaluate  evaluate test bundles against out-of-band ground-truth labels
  github    discover, doctor, watch, API-enrich, or interpret GitHub Actions runners
  trace     tracer debug surface: capabilities, status, replay
  login     store the Runopsy Cloud endpoint and personal token (0600 config)
  upload    validate a .runopsy bundle and upload it to Runopsy Cloud
  queue     show, retry or drain the local upload queue
  version   print agent and embedded analysis versions
  dump      print the latest retained snapshot (--history for the timeline)

Start flags:
  --interval DUR   sampling interval (default 1s)
  --window DUR     requested retention window (default 2m)
  --log-level      debug, info, warn, or error (default info)
  --watch-fs PATH  filesystem whose capacity is sampled (default /)
  --watch-pid N    only retain this process
  --watch-name S   only retain processes named S
  --watch-tree     include descendants of watched processes
  --github-watch   discover GitHub runners and watch all listener trees
  --github-runner-pids PID,...  attach to explicit Runner.Listener processes
  --provider-identifiers       opt in to runner/repository/job identifiers in bundles
  --socket PATH    private Unix control socket (also for status/dump)
  --max-buffer-mb  estimated retained snapshot budget in MiB (default 64)
  --collect-processes BOOL  enable process metadata (default true)
  --collect-network BOOL    enable TCP sockets/ownership (default true)
  --collect-pressure BOOL   enable PSI (default true)
  --collect-cgroups BOOL    enable cgroups (default true)
  Use --collect-NAME=false to disable a collector.
  --cloud-config PATH       credential file for auto-upload (default ~/.config/runopsy/config.json)
  --incident-dir PATH       incident bundle directory (default ~/.runopsy/incidents)
  --capture-pre DUR         pre-trigger evidence window (default 90s)
  --capture-post DUR        post-trigger evidence window (default 30s)
  --max-incidents N         retained bundles; 0 disables the count limit (default 50)
  --max-incident-age DUR    maximum bundle age; 0 disables the age limit (default 0)
  --trigger-on-stop         trigger when a watched process enters a stopped state
  --trigger-on-process-exit trigger when a watched process disappears
  --trigger-memory-percent  trigger when memory stays at/above this percent (0 off)
  --trigger-disk-free-percent trigger when disk free stays at/below this percent (0 off)
  --trigger-duration DUR    continuous duration for threshold triggers (default 5s)

Inspection:
  status [--json] [--socket PATH]
  dump [--history | --once] [--socket PATH]
  trigger [--socket PATH] [--note TEXT]
  inspect FILE [--timeline] [--snapshot N | --at DUR] [--privacy]
  incidents list [--incident-dir DIR]
  validate FILE
  extract FILE [--output DIR]
  analyze FILE [--json] [--explain] [--report] [--min-confidence F] [--disable SIG1,SIG2]
              [--document FILE]
  timeline FILE [--causal] [--json] [--report] [--explain-edge EDGE]
  evaluate DIR [--json] [--min-confidence F] [--disable SIG1,SIG2]  (test fixtures only)
  github discover [--state-dir DIR]  list locally detected runner instances
  github doctor [--state-dir DIR]    report discovery; live health is UNKNOWN until sampled
  github watch [start flags]         discover and record runner trees
  github api-enrich BUNDLE --output FILE [--token-file FILE] [--repo OWNER/NAME]
  --once collects a new standalone sample; otherwise dump reads the running agent.

This slice records host load/CPU/memory/disk, process, TCP-socket, PSI, and
cgroup state in a bounded rolling buffer with partial-failure snapshots, then
freezes a pre/post incident window into a checksummed .runopsy bundle on a
manual trigger or a factual threshold/stopped-process rule. Bundles can be
inspected and diagnosed offline. No service installation is included.
`
}

// describeFilter renders the active watch selection for the startup banner.
// sameWatchSet reports whether two candidate watch lists name the same
// processes, identities included, regardless of order, so the desired set is pushed only when it
// actually changed: a RESET+ADD with identical contents every cycle would
// spam the tracer with controls for a stable tree.
func sameWatchSet(a, b []trace.Watched) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[uint32]int64, len(a))
	for _, w := range a {
		set[w.PID] = w.StartTicks
	}
	for _, w := range b {
		if ticks, ok := set[w.PID]; !ok || ticks != w.StartTicks {
			return false
		}
	}
	return true
}

func describeFilter(filter collector.Filter) string {
	var parts []string
	if len(filter.PIDs) > 0 {
		parts = append(parts, "pid "+itoaList(filter.PIDs))
	}
	if filter.Name != "" {
		parts = append(parts, "name "+filter.Name)
	}
	selection := strings.Join(parts, " or ")
	if filter.Descendants {
		selection += " (+ descendants)"
	}
	return selection
}

func itoaList(values []int) string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = strconv.Itoa(value)
	}
	return strings.Join(out, ",")
}

func inspect(command string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", agent.DefaultSocket(), "running agent control socket")
	jsonoutput := fs.Bool("json", false, "JSON output")
	history := fs.Bool("history", false, "dump retained timeline")
	once := fs.Bool("once", false, "collect a standalone snapshot")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || (*history && *once) || (command == "status" && (*history || *once)) {
		fmt.Fprintln(stderr, "runopsy-agent: invalid inspection arguments")
		return 2
	}
	if *once {
		return dumpSnapshot(stdout, stderr)
	}
	view := "status"
	if command == "dump" {
		view = "snapshot"
		if *history {
			view = "history"
		}
	}
	var data strings.Builder
	if err := agent.ReadControl(context.Background(), *socket, view, &data); err != nil {
		fmt.Fprintln(stderr, "runopsy-agent:", err)
		return 1
	}
	if command == "dump" || *jsonoutput {
		if _, err := io.WriteString(stdout, data.String()); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	var status agent.Status
	if err := json.Unmarshal([]byte(data.String()), &status); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "Status: recording\nUptime: %s\nSnapshots: %d / %d\nLast sample: %s\nWatched processes: %d\nTCP connections: %d\nCollector failures: %d\nMissed samples: %d\n", status.Uptime.Round(time.Millisecond), status.BufferUsed, status.BufferCapacity, status.LastSample.Format(time.RFC3339Nano), status.ProcessCount, status.ConnectionCount, status.CollectorErrors, status.MissedSamples)
	return 0
}
