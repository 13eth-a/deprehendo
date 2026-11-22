package github

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"runopsy/internal/collector"
)

// Real-runner scenario S10: an outbound block on 443 while the runner is up.

func appendDiag(t *testing.T, root, line string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(root, "_diag", "Runner_20261028-1200.log"), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
}

func logLine(at time.Time, level, component, msg string) string {
	return "[" + at.UTC().Format("2006-01-02 15:04:05") + "Z " + level + " " + component + "] " + msg
}

// idlePooled is an idle supervisor HTTPS connection: ESTABLISHED, nothing
// queued, keepalive timer armed, counters frozen. under an outbound DROP it
// looks exactly like this for the whole outage.
func idlePooled(inode uint64) collector.ConnectionSnapshot {
	conn := channelConn(inode)
	conn.QueuesAvailable, conn.ProgressAvailable = true, true
	conn.Timer = 2
	conn.BytesAcked, conn.BytesReceived = 900, 1200
	return conn
}

func observeConns(ctx context.Context, s interface {
	Observe(context.Context, collector.Snapshot)
}, host *fakeHost, at time.Time, conns ...collector.ConnectionSnapshot) {
	snap := snapshotAt(host, at, 10)
	snap.Connections = conns
	s.Observe(ctx, snap)
}

// the listener also holds an idle pooled socket, so the socket rule alone
// keeps seeing a live channel; the runner's own connect-error statement,
// unanswered for 30 s, opens the episode. one event, then the reconnect
// statement and a live channel close it.
func TestS10StatedDisconnectIsAStallDespiteIdlePooledSocket(t *testing.T) {
	ctx := context.Background()
	host, root, base := fakeRunner(t, logLine(time.Date(2026, 10, 28, 12, 0, 1, 0, time.UTC), "INFO", "Terminal", "Listening for Jobs"))
	s := attachSession(t, host)
	for i := 0; i < 5; i++ {
		observeConns(ctx, s, host, base.Add(time.Duration(i)*time.Second), idlePooled(1))
	}
	appendDiag(t, root, logLine(base.Add(5*time.Second), "ERR", "Terminal", "Runner connect error: The HTTP request timed out after 00:01:00. Retrying until reconnected."))
	for i := 5; i <= 120; i += 5 {
		observeConns(ctx, s, host, base.Add(time.Duration(i)*time.Second), idlePooled(1))
	}
	appendDiag(t, root, logLine(base.Add(121*time.Second), "INFO", "Terminal", "Runner reconnected."))
	for i := 122; i <= 140; i += 2 {
		c := idlePooled(1)
		c.BytesReceived = uint64(1200 + i) // traffic again
		observeConns(ctx, s, host, base.Add(time.Duration(i)*time.Second), c)
	}
	events := eventsOf(freezeAll(t, s, base), EventCommunicationStalled)
	if len(events) != 1 {
		t.Fatalf("stall events = %d, want exactly 1", len(events))
	}
	if onset := events[0].Timestamp.Sub(base); onset < 35*time.Second || onset > 45*time.Second {
		t.Fatalf("stall onset at +%v, want about 30 s after the stated disconnect (+5 s)", onset)
	}
}

// A connect error answered by a reconnect inside the grace is a blip.
func TestS10TransientConnectErrorIsNotAStall(t *testing.T) {
	ctx := context.Background()
	host, root, base := fakeRunner(t, logLine(time.Date(2026, 10, 28, 12, 0, 1, 0, time.UTC), "INFO", "Terminal", "Listening for Jobs"))
	s := attachSession(t, host)
	for i := 0; i < 5; i++ {
		observeConns(ctx, s, host, base.Add(time.Duration(i)*time.Second), idlePooled(1))
	}
	appendDiag(t, root, logLine(base.Add(5*time.Second), "ERR", "Terminal", "Runner connect error: connection reset. Retrying until reconnected."))
	for i := 5; i < 15; i++ {
		observeConns(ctx, s, host, base.Add(time.Duration(i)*time.Second), idlePooled(1))
	}
	appendDiag(t, root, logLine(base.Add(15*time.Second), "INFO", "Terminal", "Runner reconnected."))
	for i := 15; i < 90; i += 5 {
		observeConns(ctx, s, host, base.Add(time.Duration(i)*time.Second), idlePooled(1))
	}
	if got := eventsOf(freezeAll(t, s, base), EventCommunicationStalled); len(got) != 0 {
		t.Fatalf("a 10 s reconnect produced %d stall events", len(got))
	}
}

// A healthy idle long-poll arms the keepalive timer and carries no data for
// most of its cycle. that is not a wedged transport.
func TestS10KeepaliveTimerIsNotWedged(t *testing.T) {
	ctx := context.Background()
	host, _, base := fakeRunner(t, logLine(time.Date(2026, 10, 28, 12, 0, 1, 0, time.UTC), "INFO", "Terminal", "Listening for Jobs"))
	s := attachSession(t, host)
	for i := 0; i < 60; i++ {
		observeConns(ctx, s, host, base.Add(time.Duration(i)*time.Second), idlePooled(1))
	}
	if got := eventsOf(freezeAll(t, s, base), EventCommunicationStalled); len(got) != 0 {
		t.Fatalf("a keepalive-armed idle long-poll produced %d stall events", len(got))
	}
}

// A capture taken after a long outage starts after the onset. the episode
// overlaps the window, so its onset event must be in the bundle.
func TestS10StallOnsetBeforeTheWindowIsKept(t *testing.T) {
	ctx := context.Background()
	host, root, base := fakeRunner(t, logLine(time.Date(2026, 10, 28, 12, 0, 1, 0, time.UTC), "INFO", "Terminal", "Listening for Jobs"))
	s := attachSession(t, host)
	for i := 0; i < 5; i++ {
		observeConns(ctx, s, host, base.Add(time.Duration(i)*time.Second), idlePooled(1))
	}
	appendDiag(t, root, logLine(base.Add(5*time.Second), "ERR", "Terminal", "Runner connect error: timed out. Retrying until reconnected."))
	for i := 5; i <= 180; i += 5 {
		observeConns(ctx, s, host, base.Add(time.Duration(i)*time.Second), idlePooled(1))
	}
	// freeze with a 90 s pre-window ending at +180 s: the window opens at
	// +90 s, long after the onset (about +40 s).
	section, err := s.Freeze(ctx, base.Add(90*time.Second), base.Add(180*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if got := eventsOf(section, EventCommunicationStalled); len(got) != 1 {
		t.Fatalf("stall episode open across the window: %d onset events in the bundle, want 1", len(got))
	}
	if err := section.Validate(); err != nil {
		t.Fatalf("section invalid: %v", err)
	}
}

// an episode that ended before the window opened stays out of the bundle.
func TestS10EndedEpisodeBeforeTheWindowIsDropped(t *testing.T) {
	ctx := context.Background()
	host, root, base := fakeRunner(t, logLine(time.Date(2026, 10, 28, 12, 0, 1, 0, time.UTC), "INFO", "Terminal", "Listening for Jobs"))
	s := attachSession(t, host)
	for i := 0; i < 5; i++ {
		observeConns(ctx, s, host, base.Add(time.Duration(i)*time.Second), idlePooled(1))
	}
	appendDiag(t, root, logLine(base.Add(5*time.Second), "ERR", "Terminal", "Runner connect error: timed out. Retrying until reconnected."))
	for i := 5; i <= 60; i += 5 {
		observeConns(ctx, s, host, base.Add(time.Duration(i)*time.Second), idlePooled(1))
	}
	appendDiag(t, root, logLine(base.Add(61*time.Second), "INFO", "Terminal", "Runner reconnected."))
	for i := 62; i <= 200; i += 2 {
		c := idlePooled(1)
		c.BytesReceived = uint64(1200 + i)
		observeConns(ctx, s, host, base.Add(time.Duration(i)*time.Second), c)
	}
	section, err := s.Freeze(ctx, base.Add(120*time.Second), base.Add(200*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if got := eventsOf(section, EventCommunicationStalled); len(got) != 0 {
		t.Fatalf("an episode that ended at +62 s leaked into a window opening at +120 s")
	}
}

// A runner that died is a lifecycle fact, not a communication stall (R7).
func TestS10StatedDisconnectOfDeadRunnerIsNotAStall(t *testing.T) {
	ctx := context.Background()
	host, root, base := fakeRunner(t, logLine(time.Date(2026, 10, 28, 12, 0, 1, 0, time.UTC), "INFO", "Terminal", "Listening for Jobs"))
	s := attachSession(t, host)
	for i := 0; i < 5; i++ {
		observeConns(ctx, s, host, base.Add(time.Duration(i)*time.Second), idlePooled(1))
	}
	appendDiag(t, root, logLine(base.Add(5*time.Second), "ERR", "Terminal", "Runner connect error: timed out. Retrying until reconnected."))
	for i := 6; i <= 90; i += 5 {
		snap := snapshotAt(host, base.Add(time.Duration(i)*time.Second), 0, procListener, procWorker, procJobRoot)
		s.Observe(ctx, snap)
	}
	if got := eventsOf(freezeAll(t, s, base), EventCommunicationStalled); len(got) != 0 {
		t.Fatalf("dead runner produced %d stall events", len(got))
	}
}
