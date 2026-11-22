package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"runopsy/internal/platform"
	"runopsy/internal/provider"
	"runopsy/internal/provider/evidence"
)

// Well-known GitHub actions runner facts (§9.1). only the allowlisted
// `.runner` keys below are decoded; every other key in a real file is
// discarded at decode time, so an added field can never carry a secret.
const (
	listenerName = "Runner.Listener"
	workerName   = "Runner.Worker"

	runnerConfigFile = ".runner"
	runnerSetupFile  = "config.sh"
	runnerBinDir     = "bin"
	runnerDiagDir    = "_diag"
)

// runnerConfig is the allowlisted `.runner` schema (§9.1). only these keys
// are decoded; every other key a real file carries (pool, server and GitHub
// URLs, ...) is discarded at decode time and never held in memory, so an
// added field can never carry a secret into evidence. key names still need
// confirming on a real runner (5.42).
//
// audit R4: the decoder used to *reject* any file with a key outside the
// allowlist, and real `.runner` files always have such keys (and are written
// with a UTF-8 byte-order mark), so on a real host the runner name, the
// ephemeral flag and therefore EPHEMERAL_COMPLETE were all unreachable.
type runnerConfig struct {
	AgentID    int64  `json:"agentId"`
	AgentName  string `json:"agentName"`
	Ephemeral  bool   `json:"ephemeral"`
	WorkFolder string `json:"workFolder"`
}

func (c *runnerConfig) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	var out runnerConfig
	for key, raw := range fields {
		var err error
		switch key {
		case "agentId":
			err = json.Unmarshal(raw, &out.AgentID)
		case "agentName":
			err = json.Unmarshal(raw, &out.AgentName)
		case "ephemeral":
			err = json.Unmarshal(raw, &out.Ephemeral)
		case "workFolder":
			err = json.Unmarshal(raw, &out.WorkFolder)
		default:
			continue // not allowlisted: dropped unread
		}
		if err != nil {
			return fmt.Errorf("allowlisted .runner key %q has an unexpected type", key)
		}
	}
	*c = out
	return nil
}

// installLayout verifies a candidate install root contains the configuration
// and listener layout (C2 (b)).
func installLayout(root string) (exeFound, layoutOK bool) {
	if root == "" {
		return false, false
	}
	if info, err := os.Stat(filepath.Join(root, runnerBinDir, listenerName)); err == nil && info.Mode().IsRegular() {
		exeFound = true
	}
	_, configerr := os.Stat(filepath.Join(root, runnerConfigFile))
	_, setuperr := os.Stat(filepath.Join(root, runnerSetupFile))
	return exeFound, configerr == nil && setuperr == nil
}

// readRunnerConfig loads the allowlisted fields of a root's `.runner`.
// it never returns raw content.
func readRunnerConfig(root string) (runnerConfig, error) {
	data, err := readBoundedFile(filepath.Join(root, runnerConfigFile), 64<<10)
	if err != nil {
		return runnerConfig{}, err
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")) // .NET writes a UTF-8 BOM
	var cfg runnerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return runnerConfig{}, fmt.Errorf(".runner: %w", err)
	}
	return cfg, nil
}

// procNameIs matches a recorded process name against a runner binary name.
// linux reports the bare comm; macOS reports the executable path (and ps
// appends " (deleted)" for an unlinked binary), so a path-style name is
// matched by its basename. the name is a cheap filter only: tagging still
// requires the executable and install-layout checks below.
func procNameIs(name, want string) bool {
	name = strings.TrimSuffix(name, " (deleted)")
	if strings.EqualFold(name, want) {
		return true
	}
	return strings.EqualFold(path.Base(name), want)
}

var (
	// version patterns tried in order; closed set, no network.
	versionDirPattern   = regexp.MustCompile(`^v?(\d+\.\d{2,3}\.\d+)$`)
	runnerLogVersionRE  = regexp.MustCompile(`(?i)runner[^\n]{0,40}version[^\n]{0,10}v?(\d+\.\d{2,3}\.\d+)`)
	semverInLinePattern = regexp.MustCompile(`\b(\d+\.\d{2,3}\.\d+)\b`)
)

// runnerVersion resolves the runner software version for a root (§9.1:
// version string only, ClassVersion). the resolved path is used for ref
// hashing and dropped; it never reaches the bundle.
func runnerVersion(root string) (string, evidence.Source, error) {
	entries, err := os.ReadDir(root)
	if err == nil {
		var versions []string
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			if m := versionDirPattern.FindStringSubmatch(entry.Name()); m != nil {
				versions = append(versions, m[1])
			}
		}
		// highest numeric version wins if more than one staging dir lingers.
		sort.Slice(versions, func(i, j int) bool { return runnerVersionLess(versions[i], versions[j]) })
		if len(versions) > 0 {
			return versions[len(versions)-1], evidence.SourceRunnerConfig, nil
		}
	}
	// fall back to the first listener diagnostic log header.
	logs, _ := filepath.Glob(filepath.Join(root, runnerDiagDir, "Runner_*.log"))
	sort.Strings(logs)
	for _, path := range logs {
		data, err := readBoundedFile(path, 64<<10)
		if err != nil {
			continue
		}
		if m := runnerLogVersionRE.FindSubmatch(data); m != nil {
			return string(m[1]), evidence.SourceRunnerLog, nil
		}
		if m := semverInLinePattern.FindSubmatch(data); m != nil {
			return string(m[1]), evidence.SourceRunnerLog, nil
		}
	}
	return "", "", os.ErrNotExist
}

func runnerVersionLess(left, right string) bool {
	leftparts, rightparts := strings.Split(left, "."), strings.Split(right, ".")
	for index := 0; index < len(leftparts) && index < len(rightparts); index++ {
		leftnumber, lefterr := strconv.Atoi(leftparts[index])
		rightnumber, righterr := strconv.Atoi(rightparts[index])
		if lefterr != nil || righterr != nil {
			return left < right
		}
		if leftnumber != rightnumber {
			return leftnumber < rightnumber
		}
	}
	if len(leftparts) != len(rightparts) {
		return len(leftparts) < len(rightparts)
	}
	return left < right
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	handle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	buf := make([]byte, limit)
	n, err := handle.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}

type hostView = provider.HostView

// detect answers "is a GitHub runner plausibly on this host?" cheaply and
// locally: comm-name candidates from one process-table pass. present stays
// false when the table or salt is unavailable: identities cannot be derived
// without the salt (§3.2).
func Detect(ctx context.Context, host hostView) (provider.Detection, error) {
	processes, err := host.Processes(ctx)
	if err != nil {
		return provider.Detection{}, err
	}
	detection := provider.Detection{}
	if len(host.Salt()) == 0 {
		detection.Reasons = append(detection.Reasons, evidence.ReasonNotDetected)
		return detection, nil
	}
	for _, p := range processes {
		if procNameIs(p.Name, listenerName) {
			detection.Present = true
			detection.Candidates++
		}
	}
	if !detection.Present {
		detection.Reasons = []evidence.Reason{evidence.ReasonNotDetected}
	}
	return detection, nil
}

// discover enumerates runners (5.2–5.4). identity is ref (C1: never the
// PID). A process is tagged RUNNER_SUPERVISOR against C2 only after its
// executable *and* install layout verify; a name-only match is a candidate
// that `discover` reports but never tags.
func Discover(ctx context.Context, host hostView) ([]provider.RunnerInstance, error) {
	processes, err := host.Processes(ctx)
	if err != nil {
		return nil, err
	}
	salt := host.Salt()
	if len(salt) == 0 {
		return nil, errors.New("github: runner identity needs the agent salt")
	}
	var candidates []platform.Process
	for _, p := range processes {
		// comm is truncated at 15 characters; "Runner.Listener" is exactly
		// 15, so the comm match is exact. the full executable check happens
		// below through Inspect.
		if !procNameIs(p.Name, listenerName) {
			continue
		}
		candidates = append(candidates, p)
	}
	seenroots := map[string]*githubInstall{}
	var out []provider.RunnerInstance
	for _, candidate := range candidates {
		detail, err := host.Inspect(ctx, evidence.ProcessRef{PID: candidate.PID, StartTicks: candidate.StartTicks})
		if err != nil {
			// incarnation changed mid-discovery: not reportable this pass.
			continue
		}
		root := installRootFromExe(detail.Executable)
		exeok := strings.EqualFold(exeBasename(detail.Executable), listenerName)
		exefound, layoutok := installLayout(root)
		if !exeok || !exefound || !layoutok {
			// C2 on every platform: verified installations only; a name-only
			// lookalike is a candidate, never a runner (audit R14: the
			// checks used to be skipped off linux).
			continue
		}
		cfg, cfgerr := readRunnerConfig(root)
		if cfgerr != nil {
			cfg = runnerConfig{}
		}
		install := seenroots[root]
		if install == nil {
			install = &githubInstall{root: root, cfg: cfg}
			if cfgerr == nil {
				install.ConfigGood = true
			}
			if version, source, err := runnerVersion(root); err == nil {
				install.version, install.versionSource = version, source
			}
			seenroots[root] = install
		}
		runnerref := install.ref(salt)
		namestate := evidence.UnknownText(evidence.ClassRunnerName)
		if cfgerr == nil && cfg.AgentName != "" {
			namestate = evidence.KnownText(evidence.ClassRunnerName, cfg.AgentName, evidence.SourceRunnerConfig)
		}
		versionstate := evidence.UnknownText(evidence.ClassVersion)
		if install.version != "" {
			versionstate = evidence.KnownText(evidence.ClassVersion, install.version, install.versionSource)
		}
		lifecycle := evidence.LifecycleUnknown
		if cfgerr == nil && cfg.Ephemeral {
			lifecycle = evidence.LifecycleEphemeral
		} else if cfgerr == nil {
			lifecycle = evidence.LifecyclePersistent
		}
		instance := provider.RunnerInstance{
			Provider:   Name,
			Ref:        runnerref,
			Supervisor: evidence.ProcessRef{PID: candidate.PID, StartTicks: candidate.StartTicks},
			Name:       namestate,
			Version:    versionstate,
			Lifecycle:  lifecycle,
			Private:    install,
		}
		out = append(out, instance)
	}
	sortRunners(out)
	return out, nil
}

func sortRunners(in []provider.RunnerInstance) {
	sort.Slice(in, func(i, j int) bool { return in[i].Ref < in[j].Ref })
}

func runtimeIsLinux() bool { return runtime.GOOS == "linux" }

// installRootFromExe returns the runner root for a resolved listener path:
// `bin/Runner.Listener` sits directly under the root. runner releases also
// ship the binaries in a versioned directory (`bin.<version>`, with `bin` as a
// link to it); both layouts map to the same root.
func installRootFromExe(exe string) string {
	if exe == "" {
		return ""
	}
	dir := filepath.Dir(exe)
	base := filepath.Base(dir)
	if base == runnerBinDir || strings.HasPrefix(base, runnerBinDir+".") {
		return filepath.Dir(dir)
	}
	return ""
}

func exeBasename(exe string) string {
	if exe == "" {
		return ""
	}
	return filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
}

// githubInstall is the provider-private state for one runner installation.
// it is never serialized and never leaves the provider (RunnerInstance.Private).
type githubInstall struct {
	root          string
	cfg           runnerConfig
	ConfigGood    bool
	version       string
	versionSource evidence.Source
}

// ref derives the stable runner identity (§3.2): canonical install root,
// plus the configured runner name when readable; otherwise the root alone.
// the salt is the agent's per-installation salt, so refs are stable on the
// host and unlinkable in a bundle copied elsewhere.
func (g *githubInstall) ref(salt []byte) evidence.Ref {
	if len(salt) == 0 || g.root == "" {
		return ""
	}
	ref, err := evidence.NewRef("rnr", salt, filepath.Clean(g.root), g.cfg.AgentName)
	if err != nil {
		return ""
	}
	return ref
}
