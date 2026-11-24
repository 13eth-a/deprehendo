package simulator

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultPingInterval      = 200 * time.Millisecond
	defaultStallThreshold    = time.Second
	defaultStallDuration     = 6 * time.Second
	defaultStallAfter        = 3
	defaultPostRecoveryPongs = 2
)

// SocketStall simulates the nastiest network failure deprehendo will have to name:
// a TCP connection that stays open while application-level progress stops. the
// peer keeps reading (so the socket never fills and never closes), it just never
// answers.
//
// the client proves the connection is alive the same way a real one would: it
// never sees EOF, only read timeouts. it announces a stall only after
// --stall-threshold of silence, and it announces recovery only after the same
// connection produces another response.
type SocketStall struct {
	pingInterval   time.Duration
	stallThreshold time.Duration
	stallDuration  time.Duration
	stallAfter     int
}

func (s *SocketStall) Name() string { return "socket-stall" }

func (s *SocketStall) Description() string {
	return "open TCP connection that stops making application-level progress"
}

func (s *SocketStall) RegisterFlags(fs *flag.FlagSet) {
	fs.DurationVar(&s.pingInterval, "ping-interval", defaultPingInterval, "client ping interval")
	fs.DurationVar(&s.stallThreshold, "stall-threshold", defaultStallThreshold,
		"silence before the client declares the socket stalled; must exceed --ping-interval")
	fs.DurationVar(&s.stallDuration, "stall-duration", defaultStallDuration,
		"how long the server withholds responses while leaving the socket open")
	fs.IntVar(&s.stallAfter, "stall-after", defaultStallAfter, "responses served before the server stalls")
}

func (s *SocketStall) Run(ctx context.Context, cfg Config) error {
	ping := s.pingInterval
	if ping <= 0 {
		ping = defaultPingInterval
	}
	threshold := s.stallThreshold
	if threshold <= 0 {
		threshold = defaultStallThreshold
	}
	stallfor := s.stallDuration
	if stallfor <= 0 {
		stallfor = defaultStallDuration
	}
	stallafter := s.stallAfter
	if stallafter <= 0 {
		stallafter = defaultStallAfter
	}
	if threshold <= ping {
		return fmt.Errorf("stall-threshold (%s) must exceed ping-interval (%s)", threshold, ping)
	}

	if stallfor <= threshold {
		return fmt.Errorf("stall-duration (%s) must exceed stall-threshold (%s)", stallfor, threshold)
	}

	// the scenario must always terminate on its own: one full
	// connect -> stall -> recover -> close cycle plus slack. --duration caps it.
	budget := time.Duration(stallafter)*ping + stallfor + 5*threshold + 5*time.Second
	usercapped := cfg.Duration > 0
	if usercapped {
		budget = cfg.Duration
	}
	runctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	start := time.Now()
	tr := newTransitioner(stateConnecting)
	setstate := func(to connState) error {
		from, err := tr.Transition(to)
		if err != nil {
			return err
		}
		cfg.Emit("conn_state", map[string]any{"from": string(from), "to": string(to)})
		return nil
	}

	srv, err := newStallServer(cfg, stallafter, stallfor)
	if err != nil {
		return fmt.Errorf("listen on 127.0.0.1: %w", err)
	}
	srv.Start(runctx)

	cfg.Say(fmt.Sprintf("Listening: %s", srv.Addr()))
	cfg.Emit("started", map[string]any{
		"pid":                os.Getpid(),
		"transport":          "tcp",
		"ping_interval_ms":   ping.Milliseconds(),
		"stall_threshold_ms": threshold.Milliseconds(),
		"stall_duration_ms":  stallfor.Milliseconds(),
	})
	cfg.Emit("listening", map[string]any{"addr": srv.Addr()})

	conn, err := net.DialTimeout("tcp", srv.Addr(), 5*time.Second)
	if err != nil {
		cancel()
		srv.Close()
		return fmt.Errorf("connect to %s: %w", srv.Addr(), err)
	}

	// cancellation must interrupt reads even with a very long stall threshold.
	stopclose := context.AfterFunc(runctx, func() { _ = conn.Close() })
	defer stopclose()

	var (
		clientWG  sync.WaitGroup
		closeOnce sync.Once
		pingsSent atomic.Int64
	)
	// closing is idempotent and ordered: stop the pinger, break the socket so
	// the reader and the server handler unwind, then join the server.
	closeall := func() {
		closeOnce.Do(func() {
			cancel()
			_ = conn.Close()
			clientWG.Wait()
			srv.Close()
		})
	}
	defer closeall()

	cfg.Say(fmt.Sprintf("Connected: %s", conn.RemoteAddr()))
	if err := setstate(stateHealthy); err != nil {
		return err
	}
	cfg.Emit("connected", map[string]any{
		"local":  conn.LocalAddr().String(),
		"remote": conn.RemoteAddr().String(),
	})

	pingctx, stoppings := context.WithCancel(runctx)
	defer stoppings()
	clientWG.Add(1)
	go func() {
		defer clientWG.Done()
		t := time.NewTicker(ping)
		defer t.Stop()
		for {
			select {
			case <-pingctx.Done():
				return
			case <-t.C:
				if _, err := conn.Write([]byte("ping\n")); err != nil {
					// losing the socket is reported by the reader, which owns the
					// state machine; the pinger just stops.
					return
				}
				n := pingsSent.Add(1)
				cfg.Emit("ping_sent", map[string]any{"ping": n})
			}
		}
	}()

	reason := "cycle_complete"
	var runErr error
	rxcount := 0
	postrecovery := 0
	lastprogress := time.Now()
	stalledat := time.Time{}
	reader := bufio.NewReader(conn)

loop:
	for {
		if runctx.Err() != nil {
			reason = stopReason(ctx, usercapped)
			break
		}
		if err := conn.SetReadDeadline(time.Now().Add(threshold)); err != nil {
			runErr = fmt.Errorf("set read deadline: %w", err)
			reason = "read_deadline_error"
			break
		}

		line, err := reader.ReadString('\n')
		if runctx.Err() != nil {
			reason = stopReason(ctx, usercapped)
			break
		}
		if err == nil {
			rxcount++
			now := time.Now()
			silent := now.Sub(lastprogress)
			lastprogress = now
			cfg.Emit("pong_received", map[string]any{
				"bytes":     len(line),
				"rx_count":  rxcount,
				"silent_ms": silent.Milliseconds(),
			})

			switch tr.State() {
			case stateStalled:
				// progress resumed on the same connection: the stall is over.
				stalledfor := now.Sub(stalledat)
				if terr := setstate(stateRecovered); terr != nil {
					runErr = terr
					reason = "state_error"
					break loop
				}
				cfg.Emit("recovered", map[string]any{
					"stall_ms": stalledfor.Milliseconds(),
					"rx_count": rxcount,
				})
				cfg.Say(fmt.Sprintf("RX progress resumed after %s", stalledfor.Round(time.Millisecond)))
			case stateRecovered:
				postrecovery++
				if postrecovery >= defaultPostRecoveryPongs {
					reason = "cycle_complete"
					break loop
				}
			}
			continue
		}

		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			// A read timeout is the only signal that separates "peer went quiet
			// but the connection lives" from "peer closed": no EOF, no reset.
			switch tr.State() {
			case stateHealthy:
				silent := time.Since(lastprogress)
				if terr := setstate(stateStalled); terr != nil {
					runErr = terr
					reason = "state_error"
					break loop
				}
				stalledat = lastprogress
				cfg.Emit("stall_detected", map[string]any{
					"rx_count":   rxcount,
					"silent_ms":  silent.Milliseconds(),
					"pings_sent": pingsSent.Load(),
					"socket":     "open",
					"progress":   "none",
				})
				cfg.Say("Connection: open (read timeout, no EOF); RX progress: none")
			case stateStalled:
				cfg.Emit("stall_waiting", map[string]any{
					"elapsed_ms": time.Since(stalledat).Milliseconds(),
					"rx_count":   rxcount,
				})
			default:
				cfg.Emit("stall_waiting", map[string]any{
					"elapsed_ms": time.Since(lastprogress).Milliseconds(),
					"rx_count":   rxcount,
					"state":      string(tr.State()),
				})
			}
			continue
		}

		// EOF or a hard error: the connection is genuinely gone.
		if runctx.Err() != nil {
			reason = stopReason(ctx, usercapped)
			break
		}
		runErr = fmt.Errorf("read from server: %w", err)
		reason = "connection_closed"
		break
	}

	closeall()
	if reason == "cycle_incomplete" && runErr == nil {
		runErr = fmt.Errorf("socket-stall safety budget elapsed before stall and recovery completed")
	}
	if tr.State() != stateClosed {
		if cerr := setstate(stateClosed); cerr != nil && runErr == nil {
			runErr = cerr
		}
	}
	cfg.Emit("closed", map[string]any{
		"rx_count":   rxcount,
		"pings_sent": pingsSent.Load(),
		"reason":     reason,
	})
	code := 0
	if runErr != nil {
		code = 1
	}
	cfg.Emit("exited", map[string]any{
		"code":      code,
		"reason":    reason,
		"uptime_ms": time.Since(start).Milliseconds(),
	})
	return runErr
}

// stopReason distinguishes a caller-requested cap from the internal safety
// budget expiring without the cycle finishing.
func stopReason(parent context.Context, userCapped bool) string {
	if parent.Err() != nil {
		return "interrupted"
	}
	if userCapped {
		return "duration_elapsed"
	}
	return "cycle_incomplete"
}

// stallServer is a single-peer TCP server that answers pings until it is told to
// stall, then keeps reading and dropping them. reading is what keeps the socket
// ESTABLISHED instead of applying backpressure.
type stallServer struct {
	ln net.Listener

	cfg        Config
	stallAfter int
	stallFor   time.Duration

	mu          sync.Mutex
	conn        net.Conn
	pings       int
	stalled     bool
	stalledOnce bool
	closed      bool

	wg        sync.WaitGroup
	closeOnce sync.Once
	done      chan struct{}
}

func newStallServer(cfg Config, stallAfter int, stallFor time.Duration) (*stallServer, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return &stallServer{ln: ln, cfg: cfg, stallAfter: stallAfter, stallFor: stallFor, done: make(chan struct{})}, nil
}

func (s *stallServer) Addr() string { return s.ln.Addr().String() }

func (s *stallServer) Start(ctx context.Context) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := s.ln.Accept()
			if err != nil {
				return
			}
			if !s.adopt(c) {
				_ = c.Close()
				continue
			}
			s.wg.Add(1)
			go s.handle(ctx, c)
		}
	}()
}

// adopt takes ownership of the first connection only; the scenario models one
// peer, so extra clients are turned away.
func (s *stallServer) adopt(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.conn != nil {
		return false
	}
	s.conn = c
	return true
}

func (s *stallServer) handle(ctx context.Context, c net.Conn) {
	defer s.wg.Done()
	defer c.Close()

	r := bufio.NewReader(c)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		if strings.TrimSpace(line) != "ping" {
			continue
		}

		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		s.pings++
		n := s.pings
		// stall once per connection. A second stall would need its own state
		// transition, which the state machine deliberately rejects.
		startstall := !s.stalled && !s.stalledOnce && n > s.stallAfter
		if startstall {
			s.stalled = true
			s.stalledOnce = true
		}
		stalled := s.stalled
		s.mu.Unlock()

		if startstall {
			s.cfg.Emit("server_stalled", map[string]any{
				"after_pings":       n,
				"stall_duration_ms": s.stallFor.Milliseconds(),
			})
			s.cfg.Say("Entering simulated stall...")
			s.wg.Add(1)
			go s.resumeAfter(ctx)
		}
		if stalled {
			s.cfg.Emit("ping_dropped", map[string]any{"ping": n})
			continue
		}
		if _, err := c.Write([]byte("pong\n")); err != nil {
			return
		}
		s.cfg.Emit("pong_sent", map[string]any{"ping": n})
	}
}

func (s *stallServer) resumeAfter(ctx context.Context) {
	defer s.wg.Done()
	t := time.NewTimer(s.stallFor)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return
	case <-s.done:
		return
	case <-t.C:
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.stalled = false
	s.mu.Unlock()
	s.cfg.Emit("server_resumed", nil)
}

func (s *stallServer) Close() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.mu.Lock()
		s.closed = true
		c := s.conn
		s.mu.Unlock()
		_ = s.ln.Close()
		if c != nil {
			_ = c.Close()
		}
	})
	s.wg.Wait()
}
