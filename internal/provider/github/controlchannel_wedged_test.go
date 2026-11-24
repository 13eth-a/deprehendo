package github

import (
	"context"
	"testing"
	"time"

	"deprehendo/internal/collector"
	"deprehendo/internal/provider"
)

// wedgedConn is the S10 socket: ESTABLISHED to 443 with its byte counters
// frozen and send data queued under an armed timer. the kernel never closes
// it, so the stall comes from the frozen transport, not a closed socket.
func wedgedConn(inode uint64, queued bool) collector.ConnectionSnapshot {
	conn := channelConn(inode)
	conn.ProgressAvailable = true
	conn.QueuesAvailable = true
	conn.BytesAcked = 4915
	conn.BytesReceived = 5725
	if queued {
		conn.TxQueue = 3202
		conn.Timer = 4
	}
	return conn
}

func observeConn(ctx context.Context, s provider.Session, host *fakeHost, at time.Time, conn collector.ConnectionSnapshot) {
	snap := snapshotAt(host, at, 10)
	snap.Connections = []collector.ConnectionSnapshot{conn}
	s.Observe(ctx, snap)
}

func TestS10WedgedControlSocketIsCommunicationStall(t *testing.T) {
	ctx := context.Background()
	host, _, base := fakeRunner(t, "[2026-10-28 12:00:00Z INFO Terminal] Listening for Jobs")
	s := attachSession(t, host)
	// the channel qualifies with healthy, advancing counters.
	for i := 0; i < 3; i++ {
		c := channelConn(1)
		c.ProgressAvailable, c.QueuesAvailable = true, true
		c.BytesAcked = uint64(1000 + i*100)
		c.BytesReceived = uint64(2000 + i*100)
		observeConn(ctx, s, host, base.Add(time.Duration(i)*time.Second), c)
	}
	// then the transport freezes: still ESTABLISHED, queued data, timer armed.
	for i := 3; i < 30; i++ {
		observeConn(ctx, s, host, base.Add(time.Duration(i)*time.Second), wedgedConn(1, true))
	}
	if got := eventsOf(freezeAll(t, s, base), EventCommunicationStalled); len(got) != 1 {
		t.Fatalf("wedged socket: communication stall events = %d, want 1", len(got))
	}
}

func TestS10IdleLongPollIsNotCommunicationStall(t *testing.T) {
	ctx := context.Background()
	host, _, base := fakeRunner(t, "[2026-10-28 12:00:00Z INFO Terminal] Listening for Jobs")
	s := attachSession(t, host)
	for i := 0; i < 30; i++ {
		c := wedgedConn(1, false)
		observeConn(ctx, s, host, base.Add(time.Duration(i)*time.Second), c)
	}
	if got := eventsOf(freezeAll(t, s, base), EventCommunicationStalled); len(got) != 0 {
		t.Fatalf("idle long-poll reported as a communication stall: %+v", got)
	}
}
