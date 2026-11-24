package trace

// A re-exec'd helper that speaks just enough of the tracer protocol to attack
// the supervisor from the outside. testing failure isolation with a real
// child process (not an in-process fake) is the point (6.40): the guarantees
// are about process boundaries: crashes, signals, hangs and mid-frame
// truncation must all be observed the way the production agent observes them.

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const (
	fakeTracerModeEnv     = "DEPREHENDO_FAKE_TRACER_MODE"
	fakeTracerSocketEnv   = "DEPREHENDO_FAKE_TRACER_SOCKET"
	fakeTracerEventsEnv   = "DEPREHENDO_FAKE_TRACER_EVENTS"
	fakeTracerBootEnv     = "DEPREHENDO_FAKE_TRACER_BOOT_ID"
	fakeTracerNSEnv       = "DEPREHENDO_FAKE_TRACER_NS_INODE"
	fakeTracerClockEnv    = "DEPREHENDO_FAKE_TRACER_CLOCK"
	fakeTracerCapStateEnv = "DEPREHENDO_FAKE_TRACER_CAP_CONFLICT"

	// fake tracer behaviours. each one is a distinct production failure mode.
	fakeModeStream          = "stream"      // handshake, stream events, then serve controls
	fakeModeGarbage         = "garbage"     // handshake, then bytes that are not a frame
	fakeModeCrashMidFrame   = "mid-frame"   // handshake, half a frame header+payload, exit 3
	fakeModePanic           = "panic"       // handshake, then abort with a panic
	fakeModeKill9           = "kill9"       // handshake, then idle until the test kills it
	fakeModeCloseEarly      = "close-early" // handshake, then hang up but keep listening
	fakeModeHangHandshake   = "hang"        // accept and never answer the handshake
	fakeModeNoSocket        = "no-socket"   // never create the socket at all
	fakeModeVersionMismatch = "version"     // handshake claiming an incompatible schema
	fakeModeSilent          = "silent"      // handshake answered, then no frames at all
	fakeModeLossHealth      = "loss-health" // §6.3 d/e frames, then an idle session
	fakeModeUnsupported     = "unsupported" // handshake refusing the mechanism (6.53)
	fakeModeStale           = "stale"       // refuses ADD PIDs claiming fakeStaleTicks (§6.3 f)
	fakeModeFloodCrash      = "flood-crash" // writes its events, then dies mid-frame (§11.1)
)

// TestFakeTracerChild is only meaningful when re-exec'd by the tests below;
// in a normal run it skips immediately.
func TestFakeTracerChild(t *testing.T) {
	mode := os.Getenv(fakeTracerModeEnv)
	if mode == "" {
		t.Skip("helper process for the tracer isolation/benchmark tests")
	}
	events, _ := strconv.Atoi(os.Getenv(fakeTracerEventsEnv))
	os.Exit(fakeTracerMain(mode, os.Getenv(fakeTracerSocketEnv), events))
}

// fakeTracerCommand builds the re-exec command for one fake tracer.
func fakeTracerCommand(mode, socket string, events int) *exec.Cmd {
	return fakeTracerCommandEnv(mode, socket, events, nil)
}

// fakeTracerCommandEnv builds the re-exec command with extra environment
// overrides for the handshake identity fields (§6.3 b): the fake serves the
// stream exactly, but claims another boot, namespace, clock or an incoherent
// capability state in its handshake.
func fakeTracerCommandEnv(mode, socket string, events int, extra map[string]string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestFakeTracerChild$")
	cmd.Env = append(os.Environ(),
		fakeTracerModeEnv+"="+mode,
		fakeTracerSocketEnv+"="+socket,
		fakeTracerEventsEnv+"="+strconv.Itoa(events),
	)
	for k, v := range extra {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	// the helper never has useful output and a panicking one would flood the
	// test log; failure is reported through its exit status instead.
	cmd.Stdout, cmd.Stderr = nil, nil
	return cmd
}

func fakeTracerMain(mode, socket string, events int) int {
	if mode == fakeModeNoSocket {
		time.Sleep(30 * time.Second)
		return 0
	}
	_ = os.Remove(socket)
	if dir := filepath.Dir(socket); dir != "" {
		_ = os.MkdirAll(dir, 0o700)
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return 1
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return 0
		}
		code := fakeTracerServe(conn, mode, events)
		_ = conn.Close()
		if code != 0 {
			return code
		}
	}
}

// fakeTracerServe runs one session. A non-zero return ends the child with
// that exit code (a crash); zero returns to the accept loop.
func fakeTracerServe(conn net.Conn, mode string, events int) int {
	f := newFramer(conn, conn)
	if mode == fakeModeHangHandshake {
		// accept, read nothing, never reply: the agent's handshake deadline
		// must expire instead of the recorder blocking on a wedged peer.
		time.Sleep(30 * time.Second)
		return 0
	}
	frame, err := f.readFrame()
	if err != nil {
		return 0
	}
	if frame.Kind != KindHandshake {
		return 0
	}
	if mode == fakeModeVersionMismatch {
		bad, err := encodeHandshake(Handshake{
			ProtocolVersion: ProtocolVersion + 99,
			MinVersion:      ProtocolVersion + 99,
			TracerVersion:   "incompatible",
			SchemaVersion:   SchemaVersion + 1,
		})
		if err != nil {
			return 1
		}
		_ = f.writeFrame(KindHandshake, SchemaVersion+1, bad)
		return 0
	}
	hs := Handshake{
		ProtocolVersion: ProtocolVersion,
		MinVersion:      ProtocolVersionMin,
		TracerVersion:   "fake-tracer",
		Capabilities:    Capabilities{ProcessExec: true, ProcessExit: true, Backend: "proc_connector"},
		MonotonicNs:     time.Now().UnixNano(),
		WallUnixMs:      time.Now().UnixMilli(),
		SchemaVersion:   SchemaVersion,
		// §6.3 b defaults: a coherent foreign-basic handshake. identity is
		// deliberately unset here (unknown): every identity refusal case in
		// the tests threads its own mismatch through the env overrides.
		EventClock: EventClockMonotonic,
	}
	// §6.3 b handshake overrides for the identity tests.
	if v := os.Getenv(fakeTracerBootEnv); v != "" {
		hs.BootID = v
	}
	if v := os.Getenv(fakeTracerNSEnv); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 1
		}
		hs.PIDNamespaceInode = n
	}
	if v := os.Getenv(fakeTracerClockEnv); v != "" {
		hs.EventClock = v
	}
	if v := os.Getenv(fakeTracerCapStateEnv); v != "" {
		// mirrors a tracer that lies in one capability pair: a state saying
		// the mechanism did not attach while the boolean claims it can be
		// observed (§6.3 b coherence).
		hs.Capabilities.ProcessExec = true
		hs.Capabilities.ExecState = v
	}
	if mode == fakeModeUnsupported {
		// mirrors the rust tracer after a real refusal: the capability is
		// marked unsupported and the reason names the kernel (6.53).
		hs.Capabilities = Capabilities{Backend: "proc_connector", Unsupported: true}
		hs.SelectionReason = "kernel does not offer the connector: fake refusal (os error 111)"
	}
	reply, err := encodeHandshake(hs)
	if err != nil {
		return 1
	}
	if err := f.writeFrame(KindHandshake, SchemaVersion, reply); err != nil {
		return 0
	}

	switch mode {
	case fakeModeGarbage:
		// A well-formed connection carrying a non-frame: the session must end,
		// the agent must live.
		_, _ = conn.Write([]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02})
		return 0
	case fakeModeCrashMidFrame:
		// declare a large frame, deliver a few bytes, die. neither side may
		// treat the truncated payload as a short event.
		header := make([]byte, 12)
		binary.LittleEndian.PutUint32(header[0:], uint32(KindEvent))
		binary.LittleEndian.PutUint32(header[4:], 4096)
		binary.LittleEndian.PutUint16(header[8:], SchemaVersion)
		_, _ = conn.Write(header)
		_, _ = conn.Write(make([]byte, 24))
		return 3
	case fakeModePanic:
		panic("deprehendo-trace test: deliberate tracer panic")
	case fakeModeKill9:
		time.Sleep(60 * time.Second)
		return 0
	case fakeModeCloseEarly:
		return 0
	case fakeModeSilent:
		// handshake answered, then nothing at all, the paused sensor of
		// §6.3 e. nothing ever ends this session but the agent's silence
		// watchdog; the process must stay alive for it to be torn down vs.
		// merely crashed.
		time.Sleep(60 * time.Second)
		return 0
	case fakeModeLossHealth:
		// LOSS and HEALTH exactly as the production tracer sends them
		// (framing.rs encode_loss/encode_health shapes), then the standard
		// control-serving tail. the manager's health must reflect both.
		lossraw, err := json.Marshal(Loss{Stage: StageQueue, CountAtLeast: 7, FirstNs: 100, LastNs: 200})
		if err != nil {
			return 1
		}
		if err := f.writeFrame(KindLoss, SchemaVersion, lossraw); err != nil {
			return 1
		}
		healthraw, err := json.Marshal(TracerHealth{UptimeMs: 1200, EventsSent: 3, EventsLost: 7, QueueDepth: 0, Watches: 0, MonotonicNs: time.Now().UnixNano()})
		if err != nil {
			return 1
		}
		if err := f.writeFrame(KindHealth, SchemaVersion, healthraw); err != nil {
			return 1
		}
	}

	for i := 0; i < events; i++ {
		ev := TraceEvent{
			SchemaVersion: SchemaVersion,
			Sequence:      uint64(i + 1),
			MonotonicNs:   time.Now().UnixNano(),
			WallUnixMs:    time.Now().UnixMilli(),
			Type:          EventEXEC,
			PID:           uint32(1000 + i),
			Source:        SourceSynthetic,
		}
		raw, err := encodeEvent(ev)
		if err != nil {
			return 1
		}
		if err := f.writeFrame(KindEvent, SchemaVersion, raw); err != nil {
			return 0
		}
	}
	if mode == fakeModeFloodCrash {
		// everything above is queued in the socket when the tracer dies:
		// half a frame header, then exit, the way a SIGKILL mid-write ends.
		header := make([]byte, 6)
		binary.LittleEndian.PutUint32(header[0:], uint32(KindEvent))
		_, _ = conn.Write(header)
		return 3
	}
	for {
		frame, err := f.readFrame()
		if err != nil {
			return 0
		}
		control, err := decodeControl(frame.Raw)
		if err != nil {
			return 0
		}
		reply := ControlAck{Op: control.Op, Watches: uint32(len(control.PIDs))}
		if mode == fakeModeStale && control.Op == OpAdd && len(control.StartTicks) == len(control.PIDs) {
			// the production tracer refuses a PID whose live identity no
			// longer matches the claim; here the claim fakeStaleTicks
			// stands for "this PID now belongs to another process".
			for i, pid := range control.PIDs {
				if control.StartTicks[i] == fakeStaleTicks {
					reply.Stale = append(reply.Stale, pid)
				}
			}
			reply.Watches -= uint32(len(reply.Stale))
		}
		ack, err := encodeAck(reply)
		if err != nil {
			return 1
		}
		if err := f.writeFrame(KindAck, SchemaVersion, ack); err != nil {
			return 0
		}
		if control.Op == OpShutdown {
			return 0
		}
	}
}

// waitForSocket polls until the unix socket exists.
func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if !time.Now().Before(deadline) {
			return os.ErrDeadlineExceeded
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// fakeStaleTicks is the identity claim the stale-mode fake tracer refuses.
const fakeStaleTicks = 13
