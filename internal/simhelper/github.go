// package simhelper: the fake GitHub runner helpers (phase 5 item 5.41).
//
// A real runner is a supervisor process (Runner.Listener) that spawns a worker
// (Runner.Worker) per job, and the worker spawns the job's process tree. the
// harness reproduces exactly that shape with real OS processes so the recorder
// and the provider correlate real observations instead of mocked ones:
//
//	bin/Runner.Listener  _ghrunner   ← writes _diag/Runner_*.log, spawns the worker
//	bin/Runner.Worker    _ghworker   ← writes _diag/Worker_*.log, spawns the job tree
//	_work/job            _ghjob      ← a job process (and its child)
//
// every process is spawned into its own process group so one group kill models
// a real process-group termination and never reaches the recorder itself.
package simhelper

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"deprehendo/internal/platform"
)

// GitHub scenario names accepted by `deprehendo-sim github`.
const (
	GitHubHealthyIdle        = "healthy-idle"
	GitHubHealthyJob         = "healthy-job"
	GitHubAssignmentStall    = "assignment-stall"
	GitHubCommunicationStall = "communication-stall"
	GitHubFinalizationStall  = "finalization-stall"
	GitHubWorkerOOM          = "worker-oom"
	GitHubRunnerSelfKill     = "runner-self-kill"
	GitHubOrphanJob          = "orphan-job"
	GitHubNormalEphemeral    = "normal-ephemeral-exit"
)

// GitHubScenarios lists the fake-runner scenarios in plan order.
func GitHubScenarios() []string {
	return []string{
		GitHubHealthyIdle, GitHubHealthyJob, GitHubAssignmentStall,
		GitHubCommunicationStall, GitHubFinalizationStall, GitHubWorkerOOM,
		GitHubRunnerSelfKill, GitHubOrphanJob, GitHubNormalEphemeral,
	}
}

// GitHubStateFile is written by the listener into the installation root so a
// caller can attach to the exact PIDs without guessing.
const GitHubStateFile = "sim-state.json"

// GitHubState is the harness's published process state.
type GitHubState struct {
	Scenario   string `json:"scenario"`
	Listener   int    `json:"listener_pid"`
	Worker     int    `json:"worker_pid,omitempty"`
	JobRoot    int    `json:"job_root_pid,omitempty"`
	Phase      string `json:"phase"`
	UpdatedUTC string `json:"updated_utc"`
}

// GitHubPlan is the per-scenario choreography. zero durations mean "not
// scheduled". it is exported so tests can pin what each scenario claims to
// do without running nine live harnesses.
type GitHubPlan struct {
	Worker     bool
	JobTree    bool
	Broker     bool
	AssignOnly bool // log the assignment, never spawn a worker
	JobAfter   time.Duration
	DropBroker time.Duration
	KillJob    time.Duration
	KillWorker time.Duration
	KillTree   bool // the worker kill also takes the job tree (OOM)
	SelfKill   time.Duration
	WorkerExit time.Duration
	// ListenerStop ends the listener early (ephemeral lifecycle); zero means
	// the listener runs for the whole --hold.
	ListenerStop time.Duration
}

// jobAssignmentDelay is how long a runner idles before the job arrives. it
// gives a caller time to attach recording while the runner is idle (so the
// assignment happens on camera) and keeps the assignment record within the
// C6 ±2 s binding window of the worker's first observation.
const jobAssignmentDelay = 2 * time.Second

// PlanFor returns the choreography for a scenario name.
func PlanFor(name string) (GitHubPlan, error) {
	switch name {
	case GitHubHealthyIdle:
		return GitHubPlan{Broker: true}, nil
	case GitHubHealthyJob:
		return GitHubPlan{Worker: true, JobTree: true, Broker: true, JobAfter: jobAssignmentDelay}, nil
	case GitHubAssignmentStall:
		// assignment logged, no worker ever: the 5.20 shape.
		return GitHubPlan{Broker: true, AssignOnly: true, JobAfter: jobAssignmentDelay}, nil
	case GitHubCommunicationStall:
		return GitHubPlan{Worker: true, JobTree: true, Broker: true, JobAfter: jobAssignmentDelay, DropBroker: 2 * time.Second}, nil
	case GitHubFinalizationStall:
		return GitHubPlan{Worker: true, JobTree: true, JobAfter: jobAssignmentDelay, KillJob: 2 * time.Second}, nil
	case GitHubWorkerOOM:
		// the worker and the job it owns disappear together; the listener
		// survives, which distinguishes this from a self-kill.
		return GitHubPlan{Worker: true, JobTree: true, JobAfter: jobAssignmentDelay, KillWorker: 3 * time.Second, KillTree: true}, nil
	case GitHubRunnerSelfKill:
		return GitHubPlan{Worker: true, JobTree: true, JobAfter: jobAssignmentDelay, SelfKill: 3 * time.Second}, nil
	case GitHubOrphanJob:
		// only the worker dies, so the job tree survives reparented.
		return GitHubPlan{Worker: true, JobTree: true, JobAfter: jobAssignmentDelay, KillWorker: 2 * time.Second}, nil
	case GitHubNormalEphemeral:
		return GitHubPlan{Worker: true, JobTree: true, JobAfter: jobAssignmentDelay, WorkerExit: 3 * time.Second, ListenerStop: 5 * time.Second}, nil
	default:
		return GitHubPlan{}, fmt.Errorf("unknown fake-runner scenario %q", name)
	}
}

// GitHubDescription is the CLI help line for one scenario.
func GitHubDescription(name string) string {
	switch name {
	case GitHubHealthyIdle:
		return "idle listener with a long-lived broker connection"
	case GitHubHealthyJob:
		return "assignment, worker and job process tree running normally"
	case GitHubAssignmentStall:
		return "assignment logged, listener alive, no worker ever spawns"
	case GitHubCommunicationStall:
		return "broker connection closes while the job keeps running"
	case GitHubFinalizationStall:
		return "job tree exits while the worker stays alive"
	case GitHubWorkerOOM:
		return "worker and job disappear, listener survives"
	case GitHubRunnerSelfKill:
		return "listener, worker and job disappear together"
	case GitHubOrphanJob:
		return "worker dies, job tree survives reparented"
	case GitHubNormalEphemeral:
		return "one job completes, then the ephemeral listener exits"
	default:
		return ""
	}
}

// RunGitHub dispatches the hidden fake-runner helpers.
func RunGitHub(args []string, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "simhelper: missing fake-runner helper")
		return 2
	}
	switch args[0] {
	case "_ghrunner":
		return runGitHubRunner(args[1:], stderr)
	case "_ghworker":
		return runGitHubWorker(args[1:], stderr)
	case "_ghjob":
		return runGitHubJob(args[1:], stderr)
	default:
		fmt.Fprintf(stderr, "simhelper: unknown fake-runner helper %q\n", args[0])
		return 2
	}
}

// logStamp formats a diagnostic timestamp the way the runner does: local
// clock plus an explicit zone, millisecond precision.
func logStamp(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05Z")
}

// realRecords maps the harness's messages onto the record shape and wording
// a real runner writes to `_diag` ("[<time>Z INFO <component>] <message>"),
// so the end-to-end run exercises the parser a real runner feeds (principal
// phase 5 audit R1). messages not listed keep the terminal component.
var realRecords = map[string][2]string{
	"Received job message": {"JobDispatcher", "Job request 1 for plan 6f1c job 0d2e received."},
	"Job message received": {"Worker", "Job message received"},
}

// appendLine appends one diagnostic record, creating the file if needed.
// message may carry the legacy "[RUNNER 1] " / "[WORKER 1] " tag, which is
// dropped.
func appendLine(path, message string) error {
	if strings.HasPrefix(message, "[") {
		if end := strings.IndexByte(message, ']'); end > 0 {
			message = strings.TrimSpace(message[end+1:])
		}
	}
	component := "Terminal"
	if mapped, ok := realRecords[message]; ok {
		component, message = mapped[0], mapped[1]
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = fmt.Fprintf(file, "[%s INFO %s] %s\n", logStamp(time.Now()), component, message)
	return err
}

// spawnGroup starts cmd as its own process-group leader.
func spawnGroup(bin string, args ...string) (*exec.Cmd, error) {
	cmd := exec.Command(bin, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func writeState(root string, state GitHubState) {
	state.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	data, err := json.Marshal(state)
	if err != nil {
		return
	}
	temp := filepath.Join(root, GitHubStateFile+".tmp")
	if err := os.WriteFile(temp, data, 0o644); err != nil {
		return
	}
	_ = os.Rename(temp, filepath.Join(root, GitHubStateFile))
}

// ReadGitHubState reads the published harness state.
func ReadGitHubState(root string) (GitHubState, error) {
	data, err := os.ReadFile(filepath.Join(root, GitHubStateFile))
	if err != nil {
		return GitHubState{}, err
	}
	var state GitHubState
	if err := json.Unmarshal(data, &state); err != nil {
		return GitHubState{}, err
	}
	return state, nil
}

// killGroupQuiet signals a process group, tolerating a group that is already
// gone (the common case during cleanup).
func killGroupQuiet(pid int) {
	if pid <= 0 {
		return
	}
	_ = platform.KillGroup(pid, syscall.SIGKILL)
}

// runGitHubRunner is the listener process.
func runGitHubRunner(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("_ghrunner", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		root     string
		scenario string
		hold     time.Duration
	)
	fs.StringVar(&root, "root", "", "runner installation root")
	fs.StringVar(&scenario, "scenario", GitHubHealthyJob, "scenario name")
	fs.DurationVar(&hold, "hold", 12*time.Second, "overall lifetime")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if root == "" || hold <= 0 || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "_ghrunner: --root and a positive --hold are required")
		return 2
	}
	choreo, err := PlanFor(scenario)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	listener, _ := os.FindProcess(os.Getpid())
	runnerlog := filepath.Join(root, "_diag", "Runner_"+time.Now().UTC().Format("20060102-150405")+".log")
	workerlog := filepath.Join(root, "_diag", "Worker_"+time.Now().UTC().Format("20060102-150405")+".log")
	state := GitHubState{Scenario: scenario, Listener: os.Getpid(), Phase: "starting"}

	// everything the listener owns is torn down on the way out; the harness
	// must never leave a stray worker or job process behind.
	var (
		mu       sync.Mutex
		children []int
		brokerLn net.Listener
		broker   net.Conn
	)
	track := func(cmd *exec.Cmd) int {
		if cmd == nil || cmd.Process == nil {
			return 0
		}
		mu.Lock()
		children = append(children, cmd.Process.Pid)
		mu.Unlock()
		return cmd.Process.Pid
	}
	cleanup := func() {
		mu.Lock()
		pids := append([]int(nil), children...)
		mu.Unlock()
		for _, pid := range pids {
			killGroupQuiet(pid)
		}
		if broker != nil {
			_ = broker.Close()
		}
		if brokerLn != nil {
			_ = brokerLn.Close()
		}
	}
	defer cleanup()

	if err := appendLine(runnerlog, "[RUNNER 1] Listening for Jobs"); err != nil {
		fmt.Fprintf(stderr, "_ghrunner: %v\n", err)
		return 1
	}
	state.Phase = "idle"
	writeState(root, state)

	// A real listener keeps a long-lived connection to the broker. the
	// harness uses a loopback endpoint: it is a real ESTABLISHED socket owned
	// by this process, though on a local port (control-channel
	// classification requires remote 443 and is covered by fixtures).
	if choreo.Broker {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			brokerLn = ln
			go func() {
				for {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					_ = conn.Close()
				}
			}()
			if conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
				broker = conn
			}
		}
	}

	deadline := time.Now().Add(hold)
	if choreo.ListenerStop > 0 && choreo.ListenerStop < hold {
		deadline = time.Now().Add(choreo.ListenerStop)
	}

	// worker (and job tree) startup mirrors the runner: the assignment record
	// is written immediately before Runner.Worker appears. the idle delay is
	// what lets a recorder attach while the runner is still idle, so the
	// assignment itself is observed rather than inferred after the fact.
	if choreo.Worker || choreo.AssignOnly {
		if choreo.JobAfter > 0 {
			wait := choreo.JobAfter
			if remaining := time.Until(deadline); remaining > 0 && wait > remaining {
				wait = remaining // a short --hold still ends on time
			}
			time.Sleep(wait)
		}
		_ = appendLine(runnerlog, "[RUNNER 1] Received job message")
		state.Phase = "assigned"
		writeState(root, state)
	}
	if choreo.Worker {
		// bool flags do not consume a separate value argument, so the equals
		// form is required here ("--job-tree true" would become a positional
		// argument and the worker would refuse to start).
		jobargs := []string{"_ghworker", "--root", root, "--log", workerlog, "--hold", hold.String(), "--job-tree=" + strconv.FormatBool(choreo.JobTree)}
		worker, err := spawnGroup(filepath.Join(root, "bin", "Runner.Worker"), jobargs...)
		if err != nil {
			fmt.Fprintf(stderr, "_ghrunner: spawn worker: %v\n", err)
			return 1
		}
		state.Worker = track(worker)
		_ = appendLine(runnerlog, "[RUNNER 1] Running job: linux-tests")
		writeState(root, state)
		go func() { _ = worker.Wait() }()

		if choreo.JobTree {
			// give the worker a moment to publish its job root. A missing job
			// tree means the harness itself is broken, so it fails loudly
			// instead of recording a scenario that never happened.
			for i := 0; i < 50; i++ {
				if st, err := ReadGitHubState(root); err == nil && st.JobRoot > 0 {
					state.JobRoot = st.JobRoot
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if state.JobRoot == 0 {
				fmt.Fprintln(stderr, "_ghrunner: worker did not publish a job tree")
				return 1
			}
		}
		state.Phase = "running"
		writeState(root, state)
	}

	schedule := func(after time.Duration, action func()) {
		if after <= 0 {
			return
		}
		time.AfterFunc(after, action)
	}
	jobpid := func() int {
		if st, err := ReadGitHubState(root); err == nil {
			return st.JobRoot
		}
		return 0
	}

	// Scenario-specific choreography.
	if choreo.DropBroker > 0 {
		schedule(choreo.DropBroker, func() {
			if broker != nil {
				_ = broker.Close()
			}
			state.Phase = "disconnected"
			writeState(root, state)
		})
	}
	if choreo.KillJob > 0 {
		schedule(choreo.KillJob, func() {
			killGroupQuiet(jobpid())
			state.Phase = "job-exited"
			writeState(root, state)
		})
	}
	if choreo.KillWorker > 0 {
		schedule(choreo.KillWorker, func() {
			state.Phase = "worker-killed"
			writeState(root, state)
			if choreo.KillTree {
				killGroupQuiet(jobpid())
			}
			killGroupQuiet(state.Worker)
		})
	}
	if choreo.WorkerExit > 0 {
		schedule(choreo.WorkerExit, func() {
			_ = appendLine(workerlog, "[WORKER 1] Job completed with result: Succeeded")
			state.Phase = "job-completed"
			writeState(root, state)
		})
	}
	if choreo.SelfKill > 0 {
		schedule(choreo.SelfKill, func() {
			state.Phase = "self-kill"
			writeState(root, state)
			// the runner terminating its own process group: worker and job
			// disappear with it, nearly simultaneously.
			killGroupQuiet(state.Worker)
			killGroupQuiet(jobpid())
			_ = listener.Signal(syscall.SIGKILL)
		})
	}

	remaining := time.Until(deadline)
	if remaining > 0 {
		time.Sleep(remaining)
	}
	state.Phase = "stopped"
	writeState(root, state)
	if scenario == GitHubNormalEphemeral {
		_ = appendLine(runnerlog, "[RUNNER 1] Runner service stopped")
	}
	return 0
}

// runGitHubWorker is the per-job worker process.
func runGitHubWorker(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("_ghworker", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		root    string
		logPath string
		hold    time.Duration
		jobTree bool
	)
	fs.StringVar(&root, "root", "", "runner installation root")
	fs.StringVar(&logPath, "log", "", "worker diagnostic log path")
	fs.DurationVar(&hold, "hold", 12*time.Second, "overall lifetime")
	fs.BoolVar(&jobTree, "job-tree", true, "spawn the job process tree")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if root == "" || hold <= 0 || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "_ghworker: --root and a positive --hold are required")
		return 2
	}

	var job *exec.Cmd
	cleanup := func() {
		if job != nil && job.Process != nil {
			killGroupQuiet(job.Process.Pid)
		}
	}
	defer cleanup()

	if logPath != "" {
		_ = appendLine(logPath, "[WORKER 1] Job message received")
	}
	if jobTree {
		jobbin := filepath.Join(root, "_work", "job")
		cmd, err := spawnGroup(jobbin, "_ghjob", "--hold", hold.String(), "--children", "1")
		if err != nil {
			fmt.Fprintf(stderr, "_ghworker: spawn job: %v\n", err)
			return 1
		}
		job = cmd
		go func() { _ = cmd.Wait() }()
		// publish the root so the listener can target the tree.
		if st, err := ReadGitHubState(root); err == nil {
			st.JobRoot = cmd.Process.Pid
			st.Phase = "job-started"
			writeState(root, st)
		}
	}
	time.Sleep(hold)
	return 0
}

// runGitHubJob is a job process; it optionally spawns one child so the tree
// has a root and a descendant.
func runGitHubJob(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("_ghjob", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		hold     time.Duration
		children int
	)
	fs.DurationVar(&hold, "hold", 12*time.Second, "lifetime")
	fs.IntVar(&children, "children", 0, "child job processes to spawn")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if hold <= 0 || children < 0 || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "_ghjob: a positive --hold is required")
		return 2
	}
	self, err := os.Executable()
	if err != nil {
		return 1
	}
	var kids []*exec.Cmd
	defer func() {
		for _, kid := range kids {
			if kid.Process != nil {
				killGroupQuiet(kid.Process.Pid)
			}
		}
	}()
	for i := 0; i < children; i++ {
		// A job descendant stays in its root's process group: the runner kills
		// a job by group, so the whole tree must be reachable that way.
		cmd := exec.Command(self, "_ghjob", "--hold", hold.String())
		if err := cmd.Start(); err != nil {
			fmt.Fprintf(stderr, "_ghjob: spawn child: %v\n", err)
			return 1
		}
		kids = append(kids, cmd)
	}
	time.Sleep(hold)
	return 0
}

// InstallationFiles are the paths a fake installation must contain; the
// simulator package materializes them.
func InstallationFiles(root string) []string {
	return []string{
		filepath.Join(root, "bin", "Runner.Listener"),
		filepath.Join(root, "bin", "Runner.Worker"),
		filepath.Join(root, "_work", "job"),
		filepath.Join(root, "config.sh"),
		filepath.Join(root, ".runner"),
	}
}

// IsGitHubHelper reports whether args name a hidden fake-runner helper.
func IsGitHubHelper(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "_ghrunner", "_ghworker", "_ghjob":
		return true
	}
	return false
}
